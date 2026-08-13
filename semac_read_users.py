#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
semac_read_users.py — 讀取 SEMAC / CHIYU 門禁卡機內的使用者資料

協定逆向自 lib/SemacV14.dll：
  SemacV14.Request.ParentRequest   … 封包表頭 / checksum
  SemacV14.Request.CommonRequest   … 0x06 / 0x04 無酬載命令
  SemacV14.Request.GetUserDataRequest (0x08)
  SemacV14.GetEntity.GetRetrievingUserIDListEntity / GetUserDataEntity / GetQueryTheNumberOfAlreadyRegisteredUsersEntity
  SemacV14.Func.Get*FromBytes      … 欄位解碼（皆為 big-endian）

封包格式 (PC→卡機 STX=0x07；卡機→PC STX=0x09)：
  [0]=STX  [1]=0x03(SOH)  [2:6]=總長度(BE32)  [6:8]=TerminalID(BE16)
  [8]=命令碼  [9:-2]=酬載  [-2]=checksum(sum(frame[:-2])&0xFF)  [-1]=0x04(ETX)

連線模型（重要）：
  Somac 主程式本身是 TCP「伺服器」，卡機開機後主動連進來（見 ServiceModel.OpenListen）。
  因此本工具預設 --mode listen：由腳本監聽一個埠，等卡機連進來再下命令。
  作法：把某台卡機的 "Software IP:Port" 指到本機執行腳本的位址（用 SeMacSearch，
  或先關掉 Somac 服務、讓腳本佔用同一個埠）。
  若你的卡機被設定成「伺服器模式」(自己 listen，PC 當 client 連進去)，
  改用 --mode connect --ip <卡機IP> --port <埠> --tid <機號>。

限制：假設卡機未啟用傳輸加密(AES)、TLS、或連線密碼(Terminal Passcode)。
     若有啟用，需要金鑰，本工具無法解讀（會逾時或拿到亂碼）。
"""

import argparse
import csv
import datetime
import json
import socket
import sys
import time

# ---- 命令碼（對應 SemacV14 CommandType enum）----
CMD_QUERY_USER_COUNT = 0x04   # QueryTheNumberOfAlreadyRegisteredUsers
CMD_USER_ID_LIST     = 0x06   # RetrievingUserIDList
CMD_GET_USER_DATA    = 0x08   # GetUserData
CMD_KEEPALIVE        = 0x50   # KeepAliveCheck（卡機主動送，伺服器回同碼含時間）

STX_PC     = 0x07             # PC → 卡機
STX_READER = 0x09            # 卡機 → PC
SOH        = 0x03
ETX        = 0x04

# ---- 卡機清單：由 config/device.py 載入 ----
def _load_device_config():
    import importlib.util
    import os
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config", "device.py")
    spec = importlib.util.spec_from_file_location("device_config", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return list(mod.READERS), int(getattr(mod, "DEFAULT_PORT", 1621))


try:
    READERS, DEFAULT_PORT = _load_device_config()
except Exception as _e:
    # 載不到設定就不要偷偷用內建值，直接報錯，避免連錯卡機
    sys.stderr.write("錯誤：無法載入 config/device.py（%s）\n" % _e)
    READERS = []
    DEFAULT_PORT = 1621           # 僅作為 --port 的預設值；卡機埠請寫在 config/device.py


# ============================ 封包組裝 / 拆解 ============================

def build_frame(cmd, tid, payload=b""):
    """組一個 PC→卡機 封包。"""
    n = 9 + len(payload) + 2                       # 表頭9 + 酬載 + checksum + ETX
    f = bytearray(n)
    f[0] = STX_PC
    f[1] = SOH
    f[2:6] = n.to_bytes(4, "big")                  # 總長度 BE32
    f[6:8] = (tid & 0xFFFF).to_bytes(2, "big")     # TerminalID BE16
    f[8] = cmd & 0xFF
    f[9:9 + len(payload)] = payload
    f[-2] = sum(f[:-2]) & 0xFF                      # checksum
    f[-1] = ETX
    return bytes(f)


def build_keepalive_reply(tid):
    """回覆卡機 keepalive：0x50 + 目前時間（同步卡機時鐘），共 64 bytes。
    對應 KeepAliveCheckRequest.GetByteData 的欄位順序。"""
    now = datetime.datetime.now()
    payload = bytearray(64 - 11)                    # 酬載 = 總長64 - (表頭9+checksum+etx=11) = 53
    # payload[k] 對應封包 byte (9+k)
    payload[0] = now.second                         # byte 9
    payload[1] = now.minute                         # byte 10
    payload[2] = now.hour                            # byte 11
    payload[3] = (now.weekday() + 1) % 7            # byte 12  .NET DayOfWeek: 週日=0
    payload[4] = now.month                           # byte 13
    payload[5] = now.day                             # byte 14
    payload[6] = now.year % 100                      # byte 15  年-2000
    payload[10] = 0x64                               # byte 19（原程式固定值）
    return build_frame(CMD_KEEPALIVE, tid, bytes(payload))


class FrameReader:
    """從 socket 串流中一次讀出一個完整封包（依 [2:6] 長度欄位切框，處理黏包/半包）。"""

    def __init__(self, sock):
        self.sock = sock
        self.buf = bytearray()

    def _fill(self, need):
        while len(self.buf) < need:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("連線被對方關閉")
            self.buf.extend(chunk)

    def read_frame(self):
        # 對齊到 STX(0x09/0x07) + SOH(0x03)
        while True:
            self._fill(2)
            if self.buf[0] in (STX_READER, STX_PC) and self.buf[1] == SOH:
                break
            del self.buf[0]                          # 丟棄雜訊 byte，重新對齊
        self._fill(6)
        length = int.from_bytes(self.buf[2:6], "big")
        if length < 11 or length > 2_000_000:        # 長度不合理 → 視為雜訊
            del self.buf[0]
            return self.read_frame()
        self._fill(length)
        frame = bytes(self.buf[:length])
        del self.buf[:length]
        return frame


# ============================ 欄位解碼（對應 Func.*）============================

def be_uint(b):
    return int.from_bytes(b, "big")


def dec_string(b):
    """UTF8 字串，去掉尾端 NUL / 空白（對應 GetStringFromBytes）。"""
    return b.split(b"\x00", 1)[0].decode("utf-8", "ignore").strip()


def dec_cardno(b8):
    """8 bytes big-endian → 十進位卡號字串（對應 GetInt64ofHexFromBytes）。"""
    return str(be_uint(b8))


def dec_password(b8):
    """8 bytes 逐 byte 轉字元、去 NUL；"0" 視為空（對應 GetUserDataEntity）。"""
    s = "".join(chr(x) for x in b8).replace("\x00", "").strip()
    return "" if s == "0" else s


def dec_date(byte_year, month, day, hour, minute):
    if month == 0 or day == 0:
        return ""
    try:
        return "%04d-%02d-%02d %02d:%02d" % (byte_year + 2000, month, day, hour, minute)
    except Exception:
        return ""


# ============================ 回應解析 ============================

def parse_user_id_list(frame):
    """0x06 回應 → [uid, ...]（GetRetrievingUserIDListEntity）。
    byte[8] 為結果碼：0=成功、非0=錯誤/無資料。"""
    if len(frame) < 20 or frame[8] != 0:
        return []
    count = be_uint(frame[16:20])
    ids = []
    for i in range(count):
        off = 20 + i * 4
        if off + 4 > len(frame):
            break
        ids.append(be_uint(frame[off:off + 4]))
    return ids


def parse_user_count(frame):
    """0x04 回應 → dict（GetQueryTheNumberOfAlreadyRegisteredUsersEntity）。"""
    if len(frame) < 28 or frame[8] != 0:
        return None
    return {
        "registered": be_uint(frame[16:20]),
        "available": be_uint(frame[20:24]),
        "max_capacity": be_uint(frame[24:28]),
    }


def parse_user_data(frame):
    """0x08 回應 → dict 或 None（GetUserDataEntity）。
    依封包長度分三種版面：>=98 含員工編號、==96 一般、其它退化解析。"""
    if len(frame) < 20 or frame[8] != 0:
        return None                                  # byte[8]!=0：卡機回錯誤（此 UserID 不存在）

    L = len(frame)
    u = {"tid": be_uint(frame[6:8])}

    if L >= 98:
        # ---- 含 EmployeeID 版面 ----
        u["user_id"]   = be_uint(frame[16:20])
        u["card_no"]   = dec_cardno(frame[20:28])
        u["employee_id"] = dec_string(frame[28:38])
        u["user_name"] = dec_string(frame[38:69])
        u["check_expire"] = frame[0x45] == 1
        u["expire_from"] = dec_date(frame[0x46], frame[0x47], frame[0x48], frame[0x49], frame[0x4A])
        u["expire_to"]   = dec_date(frame[0x4B], frame[0x4C], frame[0x4D], frame[0x4E], frame[0x4F])
        u["enabled"]   = frame[0x50] == 1
        u["user_type"] = frame[0x51]
        u["groups"]    = [frame[0x52], frame[0x53], frame[0x54], frame[0x55]]
        u["bypass_tz"] = frame[0x56]
        u["password"]  = dec_password(frame[0x57:0x5F])
        u["timezones"] = list(frame[0x5F:0x67])
    elif L >= 96:
        # ---- 一般版面（無 EmployeeID）----
        u["user_id"]   = be_uint(frame[16:20])
        u["card_no"]   = dec_cardno(frame[20:28])
        u["employee_id"] = ""
        u["user_name"] = dec_string(frame[28:59])
        u["check_expire"] = frame[0x3B] == 1
        u["expire_from"] = dec_date(frame[0x3C], frame[0x3D], frame[0x3E], frame[0x3F], frame[0x40])
        u["expire_to"]   = dec_date(frame[0x41], frame[0x42], frame[0x43], frame[0x44], frame[0x45])
        u["enabled"]   = frame[0x46] == 1
        u["user_type"] = frame[0x47]
        u["groups"]    = [frame[0x48], frame[0x49], frame[0x4A], frame[0x4B]]
        u["bypass_tz"] = frame[0x4C]
        u["password"]  = dec_password(frame[0x4D:0x55])
        u["timezones"] = list(frame[0x55:0x5D])
    else:
        # ---- 退化：只抓得到的最小欄位 ----
        u["user_id"]   = be_uint(frame[16:20]) if L >= 20 else 0
        u["card_no"]   = dec_cardno(frame[20:28]) if L >= 28 else ""
        u["employee_id"] = ""
        u["user_name"] = dec_string(frame[28:min(59, L)]) if L > 28 else ""
        u["enabled"] = None
        u["user_type"] = None
        u["groups"] = []
        u["bypass_tz"] = None
        u["password"] = ""
        u["timezones"] = []
        u["check_expire"] = None
        u["expire_from"] = u["expire_to"] = ""
    return u


# ============================ 連線與請求 ============================

class Session:
    def __init__(self, sock, tid, timeout, verbose=False):
        self.sock = sock
        self.reader = FrameReader(sock)
        self.tid = tid
        self.verbose = verbose
        sock.settimeout(timeout)

    def _log(self, *a):
        if self.verbose:
            print(*a, file=sys.stderr)

    def request(self, cmd, payload=b"", expect=None, tries=2):
        """送出命令，讀回應直到拿到 byte[8]==expect 的框；途中回覆 keepalive、忽略其它推播。"""
        if expect is None:
            expect = cmd
        for _ in range(tries):
            frame = build_frame(cmd, self.tid, payload)
            self._log(">> send cmd=0x%02X len=%d" % (cmd, len(frame)))
            self.sock.sendall(frame)
            deadline_frames = 0
            while deadline_frames < 50:
                deadline_frames += 1
                try:
                    resp = self.reader.read_frame()
                except socket.timeout:
                    break
                # 卡機→PC 回應：byte[8]=狀態旗標、byte[9]=命令碼(GetCommandType)
                status = resp[8]
                c = resp[9]
                self._log("<< recv cmd=0x%02X status=0x%02X len=%d tid=%d  hex=%s"
                          % (c, status, len(resp), be_uint(resp[6:8]), resp.hex()))
                if c == CMD_KEEPALIVE:
                    try:
                        self.sock.sendall(build_keepalive_reply(self.tid))
                    except Exception:
                        pass
                    continue
                if c == expect:
                    return resp
                # 其它為即時刷卡/推播，忽略，繼續等
        return None

    def wait_first_frame(self):
        """listen 模式：等卡機第一個封包以取得 TerminalID，並回覆 keepalive。"""
        frame = self.reader.read_frame()
        self.tid = be_uint(frame[6:8])
        self._log("偵測到卡機 TerminalID = %d (cmd=0x%02X status=0x%02X)  hex=%s"
                  % (self.tid, frame[9], frame[8], frame.hex()))
        if frame[9] == CMD_KEEPALIVE:
            try:
                self.sock.sendall(build_keepalive_reply(self.tid))
            except Exception:
                pass
        return self.tid


def connect_reader(ip, port, tid, timeout, verbose, tag=""):
    """connect 模式：主動連上卡機。tid 為 None 時嘗試從卡機主動送來的封包自動偵測。"""
    s = socket.create_connection((ip, port), timeout=timeout)
    sess = Session(s, tid or 0, timeout, verbose)
    if tid is None:
        try:
            s.settimeout(min(timeout, 6.0))
            sess.wait_first_frame()                  # 讀卡機主動推播的框以取得 TID
        except socket.timeout:
            s.close()
            raise RuntimeError("未指定 tid 且卡機未主動送封包，無法自動偵測機號，請在清單或 --tid 指定")
        finally:
            s.settimeout(timeout)
    log(tag, "已連線 %s:%d TerminalID=%d" % (ip, port, sess.tid))
    return sess


def listen_reader(args):
    """listen 模式：監聽等卡機連入（單台，忽略 READERS 陣列）。"""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.bind, args.port))
    srv.listen(1)
    print("在 %s:%d 等待卡機連入…（把某台卡機的 Software IP:Port 指到這裡）"
          % (args.bind or "0.0.0.0", args.port))
    conn, addr = srv.accept()
    print("卡機已連入：%s:%d" % addr)
    sess = Session(conn, args.tid or 0, args.timeout, args.verbose)
    sess.wait_first_frame()
    if args.tid:
        sess.tid = args.tid
    print("使用 TerminalID = %d" % sess.tid)
    return sess


# ============================ 主流程 ============================

_print_lock = __import__("threading").Lock()


def log(tag, *a):
    prefix = ("[%s] " % tag) if tag else ""
    with _print_lock:
        print(prefix + " ".join(str(x) for x in a))


def collect_user_ids(sess, args, tag=""):
    if args.brute:
        lo, hi = args.brute
        log(tag, "暴力掃描 UserID %d..%d" % (lo, hi))
        return list(range(lo, hi + 1))

    resp = sess.request(CMD_USER_ID_LIST, expect=CMD_USER_ID_LIST)
    if resp is None:
        log(tag, "取得 UserID 清單失敗（逾時或卡機無回應）。可改用 --brute 掃描。")
        return []
    ids = parse_user_id_list(resp)
    log(tag, "卡機回報已註冊 UserID 共 %d 筆" % len(ids))
    return ids


def expand_targets(readers, default_port):
    """把 READERS 展開成一個個掃描目標。
    每台的 port 可以是單一值或清單（同一 IP 上多個控制器/埠），各展開成獨立目標。
    回傳 dict 清單：{ip, port, tid}。"""
    targets = []
    for r in readers:
        if not r.get("enabled"):
            continue
        ip = r["ip"]
        p = r.get("port", default_port)
        ports = list(p) if isinstance(p, (list, tuple, set)) else [p]
        for port in ports:
            targets.append({"ip": ip, "port": int(port), "tid": r.get("tid")})
    return targets


def read_one_reader(cfg, args):
    """處理一個目標（ip:port）：連線→列舉→讀取。回傳 users 清單（每筆含 reader_ip / reader_port）。"""
    ip = cfg["ip"]
    port = cfg.get("port", args.port)
    tid = cfg.get("tid", args.tid)
    tag = "%s:%d" % (ip, port)
    try:
        sess = connect_reader(ip, port, tid, args.timeout, args.verbose, tag)
    except (OSError, RuntimeError) as e:
        log(tag, "連線失敗：%s" % e)
        return []

    try:
        cnt = sess.request(CMD_QUERY_USER_COUNT, expect=CMD_QUERY_USER_COUNT)
        if cnt is not None:
            info = parse_user_count(cnt)
            if info:
                log(tag, "已註冊 %(registered)d / 可用 %(available)d / 上限 %(max_capacity)d" % info)

        ids = [args.uid] if args.uid is not None else collect_user_ids(sess, args, tag)

        users = []
        for i, uid in enumerate(ids, 1):
            resp = sess.request(CMD_GET_USER_DATA, payload=uid.to_bytes(4, "big"),
                                expect=CMD_GET_USER_DATA)
            if resp is None:
                log(tag, "UserID %d：逾時" % uid)
                continue
            u = parse_user_data(resp)
            if u is None:
                if not args.brute:
                    log(tag, "UserID %d：不存在" % uid)
                continue
            u["reader_ip"] = ip
            u["reader_port"] = port
            users.append(u)
            log(tag, "[%d/%d] UserID %-8d 卡號 %-12s 姓名 %s"
                % (i, len(ids), u["user_id"], u.get("card_no", ""), u.get("user_name", "")))
        log(tag, "完成，共 %d 筆" % len(users))
        return users
    finally:
        try:
            sess.sock.close()
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser(
        description="讀取 SEMAC/CHIYU 門禁卡機內的使用者資料（依 READERS 陣列逐台處理）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    ap.add_argument("--mode", choices=["connect", "listen"], default="connect",
                    help="connect=依 READERS 陣列主動連卡機(預設)；listen=監聽等單台卡機連入")
    ap.add_argument("--core", type=int, default=1, help="並行處理的卡機數（預設 1）")
    ap.add_argument("--bind", default="", help="listen 模式綁定的本機位址（預設全部）")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT,
                    help="TCP 埠（connect=卡機埠；listen=本機監聽埠；預設 %d）" % DEFAULT_PORT)
    ap.add_argument("--tid", type=int, help="TerminalID 機號（陣列未指定時的預設值；可自動偵測）")
    ap.add_argument("--uid", type=int, help="只讀取指定的單一 UserID")
    ap.add_argument("--brute", nargs=2, type=int, metavar=("START", "END"),
                    help="不用清單，改暴力掃描 UserID 區間")
    ap.add_argument("--timeout", type=float, default=10.0, help="Socket 逾時秒數（預設 10）")
    ap.add_argument("--csv", help="輸出 CSV 檔路徑（多台合併，含 reader_ip 欄）")
    ap.add_argument("--json", help="輸出 JSON 檔路徑")
    ap.add_argument("-v", "--verbose", action="store_true", help="印出封包收送記錄")
    args = ap.parse_args()

    if args.mode == "listen":
        # 單台：監聽等卡機連入（accept 等待期間不計時）
        sess = listen_reader(args)
        t0 = time.monotonic()                        # 收到卡機訊號的時間點
        try:
            users = read_session_users(sess, args, tag="")
        finally:
            try:
                sess.sock.close()
            except Exception:
                pass
    else:
        # connect：依陣列展開成 (ip:port) 目標逐一處理（可並行）
        targets = expand_targets(READERS, args.port)
        if not targets:
            sys.exit("READERS 陣列中沒有 enabled=True 的卡機。")
        print("要處理 %d 個目標，並行 %d：" % (len(targets), max(1, args.core)))
        for t in targets:
            print("  - %s:%d" % (t["ip"], t["port"]))

        t0 = time.monotonic()                        # 開始連線/處理的時間點
        users = []
        if max(1, args.core) == 1:
            for r in targets:
                users.extend(read_one_reader(r, args))
        else:
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=args.core) as ex:
                for res in ex.map(lambda r: read_one_reader(r, args), targets):
                    users.extend(res)

    print("\n總共讀取 %d 筆使用者。" % len(users))
    write_outputs(users, args)
    elapsed_ms = (time.monotonic() - t0) * 1000
    print("執行時間（收到卡機訊號 → 存檔完成）：%.1f 毫秒" % elapsed_ms)


def read_session_users(sess, args, tag=""):
    """listen 模式用：在既有連線上列舉並讀取（單台）。"""
    cnt = sess.request(CMD_QUERY_USER_COUNT, expect=CMD_QUERY_USER_COUNT)
    if cnt is not None:
        info = parse_user_count(cnt)
        if info:
            log(tag, "已註冊 %(registered)d / 可用 %(available)d / 上限 %(max_capacity)d" % info)
    ids = [args.uid] if args.uid is not None else collect_user_ids(sess, args, tag)
    users = []
    for i, uid in enumerate(ids, 1):
        resp = sess.request(CMD_GET_USER_DATA, payload=uid.to_bytes(4, "big"),
                            expect=CMD_GET_USER_DATA)
        if resp is None:
            log(tag, "UserID %d：逾時" % uid)
            continue
        u = parse_user_data(resp)
        if u is None:
            if not args.brute:
                log(tag, "UserID %d：不存在" % uid)
            continue
        u["reader_ip"] = ""
        users.append(u)
        log(tag, "[%d/%d] UserID %-8d 卡號 %-12s 姓名 %s"
            % (i, len(ids), u["user_id"], u.get("card_no", ""), u.get("user_name", "")))
    return users


def write_outputs(users, args):
    if args.csv:
        cols = ["reader_ip", "reader_port", "user_id", "card_no", "employee_id", "user_name", "enabled",
                "user_type", "bypass_tz", "password", "groups", "timezones",
                "check_expire", "expire_from", "expire_to", "tid"]
        with open(args.csv, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(cols)
            for u in users:
                w.writerow([_csv_val(u.get(c, "")) for c in cols])
        print("已寫出 CSV：%s" % args.csv)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(users, f, ensure_ascii=False, indent=2)
        print("已寫出 JSON：%s" % args.json)


def _csv_val(v):
    if isinstance(v, list):
        return ",".join(str(x) for x in v)
    return v


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n中斷。")
    except (ConnectionError, OSError) as e:
        sys.exit("連線錯誤：%s" % e)
