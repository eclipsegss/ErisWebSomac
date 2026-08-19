#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
semac_read_users.py — 讀取 SEMAC / CHIYU 門禁卡機內的使用者資料

協定逆向自 lib/SemacV14.dll（詳見 COMMAND.md）：
  SemacV14.Request.ParentRequest   … 封包表頭 / checksum
  SemacV14.Request.CommonRequest   … 0x06 / 0x04 無酬載命令
  SemacV14.Request.GetUserDataRequest (0x08)
  SemacV14.GetEntity.*             … 回應解析
  SemacV14.Func.Get*FromBytes      … 欄位解碼（皆為 big-endian）

連線模型：
  卡機是 TCP client，開機後主動連到它設定的 Software IP:Port。
  本工具當 TCP server：監聽一個埠，等卡機連進來，再從那條 socket 下命令、收結果。
  作法：把卡機的 Software IP 指到執行本腳本的電腦，Software Port = --port。

限制：假設卡機未啟用傳輸加密(AES)、TLS、或連線密碼(Terminal Passcode)。
     若有啟用，需要金鑰，本工具無法解讀（會逾時或拿到亂碼）。
"""

import argparse
import csv
import datetime
import json
import socket
import sys
import threading
import time

# ---- 命令碼（對應 SemacV14 CommandType enum）----
CMD_QUERY_USER_COUNT = 0x04   # QueryTheNumberOfAlreadyRegisteredUsers
CMD_USER_ID_LIST     = 0x06   # RetrievingUserIDList
CMD_REGISTER         = 0x07   # RegisterModifyUserData（寫入使用者）
CMD_GET_USER_DATA    = 0x08   # GetUserData
CMD_KEEPALIVE        = 0x50   # KeepAliveCheck（卡機主動送，伺服器回同碼含時間）
CMD_REALTIME         = 0x51   # RealtimeTransaction（卡機主動上傳即時刷卡）
CMD_OFFLINE_LOG      = 0x59   # OffLineLogTransaction（離線補傳，record 同 0x51）

# 進出別 / 驗證方式代碼 → 文字（對應 Define.GetInOut/VerificationSourceString）
INOUT_MAP = {1: "進", 2: "出", 33: "進(Bypass ON)", 34: "出(Bypass ON)",
             49: "進(Bypass OFF)", 50: "出(Bypass OFF)"}
VERIFY_MAP = {0: "None", 1: "Card", 2: "CommonPassword", 4: "PersonalPassword",
              5: "Card+PersonalPassword", 8: "AdminPassword", 10: "Fingerprint",
              11: "Card+Fingerprint", 64: "Face", 65: "Card+Face",
              99: "QRCode", 128: "VeinFinger", 129: "Card+VeinFinger"}

# 事件/警報碼 → 文字（對應 Define.GetEventAlarmCodeString，index = 代碼）
EVENT_ALARM = [
    "None", "Door open too long", "Door closed after alert", "Force Open", "Force Close",
    "Back to Normal", "Unauthorized User", "Unregistered User", "Deactivated User",
    "Expired User", "Anti Pass Back Violation", "Not Allowed Door", "Door Intruded",
    "Multi-Badge Violation", "Tamper Switch Breakdown", "Exit Button Pressed",
    "Door Normal Closed", "Duress Alarm On", "Fire Alarm On", "Defense On", "Defense Off",
    "Tamper Switch Closed", "Time Zone Violation", "Lock Forced Release Time Start",
    "Lock Forced Release Time End", "System Warm Start", "System Cold Start",
    "Using Battery Power", "Using Normal Power", "BF50 On", "BF50 Off",
    "Door Sensor short circuit", "Door Sensor open circuit", "Invalid Password",
    "Interlock Violation", "Emergency Open", "Emergency Close",
    "Fire Alarm Detection Enabled", "Fire Alarm Detection Disabled", "Door Normal Opened",
    "Turn Off Alarm Trigger Manually", "Turn Off Alarm Trigger Automatically", "IP Conflict",
    "Keypad is locked due to password error try", "Keypad recover", "Webpass On Line",
    "Webpass Off Line", "Pulse Open Door", "Exit Button Short", "Exit Button Open",
    "Fire Button Short", "Fire Button Open", "TerminalID Error", "Degrade All Pass",
    "Degrade FC Pass", "DEGRADE REG PASS", "W Series FastReg", "Fire Alarm Off", "Black List",
    "Reserved (BF333 Online only for S3V3)", "Reserved (BF333 Offline only for S3V3)",
    "Reserved(Semac-D only)", "EMERGANCY_BUTTON_ENABLE", "EMERGANCY_BUTTON_DISABLE",
    "LIFT_REPAIR_ON", "LIFT_REPAIR_OFF", "BATTERY_OK", "BATTERY_BD", "OSDP_ONLINE",
    "OSDP_OFFLINE", "Temperature Abnormal", "Temperature Online", "Temperature Offline",
]
FUNCKEY_MAP = {0: "None", 1: "F1", 101: "F2", 201: "F3", 301: "F4",
               100: "F1+", 200: "F2+", 300: "F3+", 400: "F4+"}


def event_str(code):
    return EVENT_ALARM[code] if 0 <= code < len(EVENT_ALARM) else "Code:%d" % code


def funckey_str(code):
    return FUNCKEY_MAP.get(code, "0x%X" % code)

STX_PC     = 0x07             # PC → 卡機
STX_READER = 0x09            # 卡機 → PC
SOH        = 0x03
ETX        = 0x04

DEFAULT_PORT = 1621           # --port 的預設值；實際請設成卡機的 Software Port

# 軟體版本日期（YYYYMMDD）。卡機用它判定「軟體是否支援」，太舊或 0 會顯示『軟體不支援』。
# 對應 Somac 的 SoftwareVersionDate（= Somac.exe 檔案日期）。過舊的話可改新一點的日期。
SOFTWARE_VERSION_DATE = "20240205"

DEFAULT_CONTROL_PORT = 12000  # monitor 控制通道預設埠（save 也用同一個，免手動對）


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
    """回覆卡機 keepalive：0x50 + 目前時間 + 軟體版本日期，共 64 bytes。
    對應 KeepAliveCheckRequest.GetByteData 的欄位順序。
    ⚠️ byte[24..26] 是「軟體版本日期」(SoftwareVersionDate=Somac.exe 檔案日期 yyyyMMdd)、
       byte[27]=1；卡機用這個判定「軟體是否支援」。若送 0，卡機 LCD 會顯示『軟體不支援』。"""
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
    # 軟體版本日期（YYYYMMDD）→ byte 24=年%100、byte 25=月、byte 26=日、byte 27=1
    try:
        y, mo, d = int(SOFTWARE_VERSION_DATE[0:4]), int(SOFTWARE_VERSION_DATE[4:6]), int(SOFTWARE_VERSION_DATE[6:8])
        payload[15] = y % 100                        # byte 24
        payload[16] = mo                             # byte 25
        payload[17] = d                              # byte 26
    except Exception:
        pass
    payload[18] = 1                                  # byte 27
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
        u["layout"]    = "empid"                     # 寫入(0x07)也要用含員工編號的版面
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
        u["layout"]    = "basic"
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
        u["layout"]    = "short"
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


def _fmt_dt(y, mo, d, h, mi, s):
    """組 YYYY-mm-dd HH:mm:ss；欄位不合理則回空字串（避免顯示假時間）。"""
    if 1 <= mo <= 12 and 1 <= d <= 31 and h < 24 and mi < 60 and s < 60:
        return "%04d-%02d-%02d %02d:%02d:%02d" % (y, mo, d, h, mi, s)
    return ""


def _decorate(r, tid):
    r["tid"] = tid
    r["inout"] = INOUT_MAP.get(r["inout_code"], "Code:%d" % r["inout_code"])
    r["verify"] = VERIFY_MAP.get(r["verify_code"], "Code:%d" % r["verify_code"])
    r["event"] = event_str(r["event_code"])
    r["func_key"] = funckey_str(r.get("func_key_code", 0))
    return r


def _pick_stride(frame, count, header):
    """由總長反推每筆 record 長度（20 或 32）：len == count*stride + header + 2。"""
    body = len(frame) - header - 2
    if count > 0 and body == count * 32:
        return 32
    if count > 0 and body == count * 20:
        return 20
    return body // count if count else 32


def parse_door_log(frame):
    """0x51 / 0x59 → 刷卡紀錄清單。兩者版面不同：
      0x51 RealtimeTransaction → GetRealtimeTransactionEntity（count=byte[16]，record 由 [17] 起，LogIndex 在最前）
      0x59 OffLineLogTransaction → GetDoorLogEntity（count=int32[16:20]，record 由 [20] 起）"""
    if len(frame) < 20:
        return []
    cmd = frame[9]
    tid = be_uint(frame[6:8])
    recs = []

    if cmd == CMD_REALTIME:
        count = frame[16]                            # 單一 byte
        if count <= 0:
            return []
        stride = _pick_stride(frame, count, 17)
        for k in range(count):
            r = 17 + k * stride                      # record 起點（LogIndex 在最前）
            if r + 18 > len(frame):
                break
            rec = {
                "log_index": be_uint(frame[r:r + 4]),
                "time": _fmt_dt(2000 + frame[r + 9], frame[r + 8], frame[r + 7],
                                frame[r + 6], frame[r + 5], frame[r + 4]),
                "inout_code": frame[r + 10],
                "verify_code": frame[r + 11],
                "event_code": frame[r + 12],
                "door_no": frame[r + 13],
                "user_id": be_uint(frame[r + 14:r + 18]),
            }
            _fill_extra(rec, frame, r, stride)       # 卡號/功能鍵/繼電器/體溫/型別
            recs.append(_decorate(rec, tid))
        return recs

    if cmd == CMD_OFFLINE_LOG:
        count = be_uint(frame[16:20])                # int32
        if count <= 0:
            return []
        stride = _pick_stride(frame, count, 20)
        for k in range(count):
            r = 20 + k * stride                      # record 起點（時間在最前）
            if r + 18 > len(frame):
                break
            rec = {
                "time": _fmt_dt(2000 + frame[r + 5], frame[r + 4], frame[r + 3],
                                frame[r + 2], frame[r + 1], frame[r + 0]),
                "inout_code": frame[r + 6],
                "verify_code": frame[r + 7],
                "event_code": frame[r + 8],
                "door_no": frame[r + 9],
                "user_id": be_uint(frame[r + 10:r + 14]),
                "log_index": be_uint(frame[r + 14:r + 18]),
            }
            _fill_extra(rec, frame, r, stride)
            recs.append(_decorate(rec, tid))
        return recs

    return []


def _fill_extra(rec, frame, r, stride):
    """32-byte record 才有的擴充欄位：卡號、功能鍵、繼電器、體溫、使用者型別。"""
    if stride >= 32 and r + 32 <= len(frame):
        rec["card_no"] = str(be_uint(frame[r + 18:r + 26]))
        rec["func_key_code"] = be_uint(frame[r + 26:r + 28])
        rec["relay_type"] = frame[r + 28]
        rec["temperature"] = "%d.%d" % (frame[r + 29], frame[r + 30])
        rec["user_type"] = frame[r + 31]
    else:
        rec["card_no"] = ""
        rec["func_key_code"] = 0
        rec["relay_type"] = 0
        rec["temperature"] = "0.0"
        rec["user_type"] = 0


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
        """送出命令，讀回應直到拿到 byte[9]==expect 的框；途中回覆 keepalive、忽略其它推播。
        （卡機→PC 回應：byte[8]=結果碼、byte[9]=命令碼；見 COMMAND.md）"""
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
        """等卡機第一個封包以取得 TerminalID，並回覆 keepalive。"""
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


def listen_reader(args):
    """監聽等卡機連入，回傳 (Session, 卡機IP)。"""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.bind, args.port))
    srv.listen(1)
    print("在 %s:%d 等待卡機連入…（把卡機的 Software IP:Port 指到這裡）"
          % (args.bind or "0.0.0.0", args.port))
    conn, addr = srv.accept()
    srv.close()
    print("卡機已連入：%s:%d" % addr)
    sess = Session(conn, args.tid or 0, args.timeout, args.verbose)
    sess.wait_first_frame()
    if args.tid:
        sess.tid = args.tid
    print("使用 TerminalID = %d" % sess.tid)
    return sess, addr[0]


# ============================ 主流程 ============================

def collect_user_ids(sess, args):
    if args.brute:
        lo, hi = args.brute
        print("暴力掃描 UserID %d..%d" % (lo, hi))
        return list(range(lo, hi + 1))

    resp = sess.request(CMD_USER_ID_LIST, expect=CMD_USER_ID_LIST)
    if resp is None:
        print("取得 UserID 清單失敗（逾時或卡機無回應）。可改用 --brute 掃描。")
        return []
    ids = parse_user_id_list(resp)
    print("卡機回報已註冊 UserID 共 %d 筆" % len(ids))
    return ids


def read_users(sess, reader_ip, args):
    """在已連線的 session 上列舉並讀取全部（或指定）使用者。"""
    cnt = sess.request(CMD_QUERY_USER_COUNT, expect=CMD_QUERY_USER_COUNT)
    if cnt is not None:
        info = parse_user_count(cnt)
        if info:
            print("已註冊 %(registered)d / 可用 %(available)d / 上限 %(max_capacity)d" % info)

    ids = [args.uid] if args.uid is not None else collect_user_ids(sess, args)

    users = []
    for i, uid in enumerate(ids, 1):
        resp = sess.request(CMD_GET_USER_DATA, payload=uid.to_bytes(4, "big"),
                            expect=CMD_GET_USER_DATA)
        if resp is None:
            print("  UserID %d：逾時" % uid)
            continue
        u = parse_user_data(resp)
        if u is None:
            if not args.brute:
                print("  UserID %d：不存在" % uid)
            continue
        u["reader_ip"] = reader_ip
        u["reader_port"] = args.port
        users.append(u)
        print("  [%d/%d] UserID %-8d 卡號 %-12s 姓名 %s"
              % (i, len(ids), u["user_id"], u.get("card_no", ""), u.get("user_name", "")))
    return users


def write_outputs(users, args):
    if args.csv:
        cols = ["reader_ip", "reader_port", "user_id", "card_no", "employee_id", "user_name",
                "enabled", "user_type", "bypass_tz", "password", "groups", "timezones",
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


def _open_swipe_csv(path):
    """開一個附加寫入的刷卡 log CSV，回傳 write(rec, reader_ip) 函式。"""
    import os
    new = (not os.path.exists(path)) or os.path.getsize(path) == 0
    f = open(path, "a", newline="", encoding="utf-8-sig")
    w = csv.writer(f)
    cols = ["time", "reader_ip", "tid", "log_index", "door_no", "user_id", "card_no",
            "inout_code", "inout", "verify_code", "verify", "event_code", "event",
            "func_key_code", "func_key", "relay_type", "temperature", "user_type"]
    if new:
        w.writerow(cols)
        f.flush()

    def write(r, reader_ip):
        w.writerow([r.get(c, "") if c != "reader_ip" else reader_ip for c in cols])
        f.flush()
    return write


def _hhmmss():
    return datetime.datetime.now().strftime("%H:%M:%S")


def _print_swipe(r, reader_ip):
    print("[%s] %s TID%s LogIdx=%s 門%s %s(%d) 驗證:%s(%d) 事件:%s(%d) "
          "UserID=%s 卡號=%s FuncKey:%s(%d) Relay=%s 溫度=%s UserType=%s"
          % (r["time"] or "??", reader_ip, r["tid"], r["log_index"], r["door_no"],
             r["inout"], r["inout_code"], r["verify"], r["verify_code"],
             r["event"], r["event_code"], r["user_id"], r["card_no"] or "-",
             r["func_key"], r["func_key_code"], r["relay_type"],
             r["temperature"], r["user_type"]))


class Bridge:
    """monitor 內部：持有目前卡機連線，讓控制指令（寫入/讀取）借用同一條 socket。
    reader thread 一條在讀框；控制指令送出後，由 reader thread 把對應回應交還。"""

    def __init__(self):
        self.cmd_lock = threading.Lock()             # 一次只跑一個控制指令
        self.send_lock = threading.Lock()            # socket 寫入互斥（keepalive/指令）
        self.sess = None
        self.reader_ip = None
        self.reader_port = None
        self.connected_at = None                     # 卡機這條連線接上的時間（unix）
        self.last_seen = None                        # 最後收到卡機任何封包的時間（unix）
        self.swipes = 0                              # 這條連線收到的刷卡筆數
        self.pending = None                          # {"expect":int,"event":Event,"frame":bytes|None}

    def attach(self, sess, reader_ip, reader_port=None):
        self.sess, self.reader_ip, self.reader_port = sess, reader_ip, reader_port
        self.connected_at = self.last_seen = time.time()
        self.swipes = 0

    def detach(self):
        self.sess = self.reader_ip = self.reader_port = None
        self.connected_at = None
        if self.pending is not None:
            self.pending["event"].set()              # 叫醒等待中的指令（會拿到 None）

    def send_raw(self, data):
        with self.send_lock:
            self.sess.sock.sendall(data)

    def deliver(self, frame):
        """reader loop 呼叫：若有指令在等這個命令碼，交給它並回 True。"""
        p = self.pending
        if p is not None and len(frame) > 9 and frame[9] == p["expect"]:
            p["frame"] = frame
            p["event"].set()
            return True
        return False

    def request(self, cmd, payload, expect, timeout):
        """從控制指令端呼叫：在卡機 socket 送出請求，等 reader thread 回傳對應框。"""
        with self.cmd_lock:
            sess = self.sess
            if sess is None:
                return None                          # 目前沒有卡機連線
            ev = threading.Event()
            self.pending = {"expect": expect, "event": ev, "frame": None}
            try:
                self.send_raw(build_frame(cmd, sess.tid, payload))
            except (OSError, AttributeError):
                self.pending = None
                return None
            ev.wait(timeout)
            fr = self.pending["frame"] if self.pending else None
            self.pending = None
            return fr


def _serve_monitor(conn, addr, args, csv_write, bridge):
    """在單一連線上持續讀框，印出即時刷卡，回覆 keepalive，把指令回應交給 bridge。"""
    reader_ip, reader_port = addr[0], addr[1]
    sess = Session(conn, args.tid or 0, args.timeout, args.verbose)
    bridge.attach(sess, reader_ip, reader_port)
    announced = False
    try:
        while True:
            try:
                frame = sess.reader.read_frame()
            except socket.timeout:
                continue                              # 沒資料，繼續等
            bridge.last_seen = time.time()            # 有訊號 → 給 status 查詢用
            if sess.tid == 0:
                sess.tid = be_uint(frame[6:8])
            if not announced:
                print("  → 已握手，TerminalID = %d，連線正常，等待刷卡…（Ctrl-C 結束）"
                      % sess.tid)
                announced = True
            cmd = frame[9]
            if args.verbose:
                print("<< cmd=0x%02X len=%d hex=%s" % (cmd, len(frame), frame.hex()),
                      file=sys.stderr)
            if cmd == CMD_KEEPALIVE:
                try:
                    bridge.send_raw(build_keepalive_reply(sess.tid))
                    print("  [%s] ♥ 收到 keepalive → 已回送 KeepAliveCheck 對時（TID%d）"
                          % (_hhmmss(), sess.tid))
                except Exception:
                    pass
            elif cmd in (CMD_REALTIME, CMD_OFFLINE_LOG):
                # 卡機紀錄只有「秒」解析度，毫秒補上「收到當下」的（時鐘已靠 keepalive 同步）
                ms = "%03d" % (datetime.datetime.now().microsecond // 1000)
                for r in parse_door_log(frame):
                    if r["time"]:
                        r["time"] += "." + ms
                    bridge.swipes += 1
                    _print_swipe(r, reader_ip)
                    if csv_write:
                        csv_write(r, reader_ip)
            else:
                bridge.deliver(frame)                # 控制指令（寫入/讀取）的回應
    except (ConnectionError, OSError):
        pass
    finally:
        bridge.detach()
        try:
            conn.close()
        except Exception:
            pass


# ---- 控制通道：其它工具（semac_save_users.py）把指令送進執行中的 monitor ----

def _bridge_read_users(bridge, args, only_uid=None):
    """透過 bridge 在既有卡機連線上讀取使用者（only_uid=None 讀全部）。"""
    users = []
    if only_uid is not None:
        ids = [only_uid]                             # 只讀一筆：省掉 0x06 取清單
    else:
        r6 = bridge.request(CMD_USER_ID_LIST, b"", CMD_USER_ID_LIST, args.timeout)
        ids = parse_user_id_list(r6) if r6 else []
    for uid in ids:
        r8 = bridge.request(CMD_GET_USER_DATA, uid.to_bytes(4, "big"),
                            CMD_GET_USER_DATA, args.timeout)
        u = parse_user_data(r8) if r8 else None
        if u:
            u["reader_ip"] = bridge.reader_ip
            u["reader_port"] = args.port
            users.append(u)
    return users


def _handle_control(bridge, conn, args):
    try:
        f = conn.makefile("rwb")
        line = f.readline()
        if not line:
            return
        req = json.loads(line.decode("utf-8"))
        action = req.get("action")
        if action == "status":
            sess = bridge.sess
            resp = {"ok": True, "connected": sess is not None,
                    "tid": sess.tid if sess else None,
                    "reader_ip": bridge.reader_ip,
                    "reader_port": bridge.reader_port,
                    "listen_port": args.port,          # monitor 等卡機連入的埠
                    "connected_at": bridge.connected_at,
                    "last_seen": bridge.last_seen,
                    "swipes": bridge.swipes,
                    "now": time.time()}                # 讓對方自己算「多久以前」免時鐘誤差
        elif action == "register":
            want = req.get("tid")
            if bridge.sess is None:
                resp = {"ok": False, "error": "no_reader"}
            elif want is not None and bridge.sess.tid != want:
                resp = {"ok": False, "error": "tid_mismatch", "reader_tid": bridge.sess.tid}
            else:
                fr = bridge.request(CMD_REGISTER, bytes.fromhex(req["payload"]),
                                    CMD_REGISTER, args.timeout)
                if fr is None:
                    resp = {"ok": False, "error": "timeout"}
                else:
                    resp = {"ok": fr[8] == 0, "status": fr[8], "tid": bridge.sess.tid}
        elif action == "read":
            if bridge.sess is None:
                resp = {"ok": False, "error": "no_reader"}
            else:
                resp = {"ok": True, "tid": bridge.sess.tid,
                        "users": _bridge_read_users(bridge, args, req.get("uid"))}
        else:
            resp = {"ok": False, "error": "unknown_action"}
        f.write((json.dumps(resp, ensure_ascii=False) + "\n").encode("utf-8"))
        f.flush()
    except Exception as e:
        try:
            conn.sendall((json.dumps({"ok": False, "error": str(e)}) + "\n").encode())
        except Exception:
            pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _control_server(bridge, args):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.control_bind, args.control_port))
    srv.listen(5)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=_handle_control, args=(bridge, conn, args), daemon=True).start()


def monitor(args):
    """--monitor：持續監聽卡機即時刷卡 + 開控制通道（Ctrl-C 結束）。卡機斷線自動等重連。"""
    bridge = Bridge()
    if args.control_port:
        threading.Thread(target=_control_server, args=(bridge, args), daemon=True).start()
        print("控制通道：%s:%d（semac_save_users.py 會把寫入指令送進來）"
              % (args.control_bind or "127.0.0.1", args.control_port))

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.bind, args.port))
    srv.listen(1)
    print("在 %s:%d 監聽即時刷卡…（把卡機的 Software IP:Port 指到這裡；Ctrl-C 結束）"
          % (args.bind or "0.0.0.0", args.port))
    csv_write = _open_swipe_csv(args.csv) if args.csv else None
    if csv_write:
        print("刷卡紀錄同時附加寫入：%s" % args.csv)
    try:
        while True:
            conn, addr = srv.accept()
            print("✓ [%s] 卡機 socket 已連上：%s:%d" % (_hhmmss(), addr[0], addr[1]))
            _serve_monitor(conn, addr, args, csv_write, bridge)
            print("✗ [%s] 卡機連線中斷，繼續等待重連…" % _hhmmss())
    finally:
        srv.close()


def main():
    ap = argparse.ArgumentParser(
        description="讀取 SEMAC/CHIYU 門禁卡機內的使用者資料（listen 模式）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    ap.add_argument("--port", type=int, default=DEFAULT_PORT,
                    help="本機監聽埠，設成卡機的 Software Port（預設 %d）" % DEFAULT_PORT)
    ap.add_argument("--bind", default="", help="綁定的本機位址（多網卡時可指定，預設全部）")
    ap.add_argument("--tid", type=int, help="TerminalID 機號（連入後會自動辨識，通常免填）")
    ap.add_argument("--monitor", action="store_true",
                    help="持續監聽即時刷卡（0x51），有人刷卡就即時印出（Ctrl-C 結束）")
    ap.add_argument("--control-port", type=int, default=DEFAULT_CONTROL_PORT,
                    help="monitor 的控制通道埠（其它工具送指令進來；預設 %d，0 關閉）"
                    % DEFAULT_CONTROL_PORT)
    ap.add_argument("--control-bind", default="127.0.0.1",
                    help="控制通道綁定位址（預設 127.0.0.1，只允許本機）")
    ap.add_argument("--uid", type=int, help="只讀取指定的單一 UserID")
    ap.add_argument("--brute", nargs=2, type=int, metavar=("START", "END"),
                    help="不用清單，改暴力掃描 UserID 區間")
    ap.add_argument("--timeout", type=float, default=10.0, help="Socket 逾時秒數（預設 10）")
    ap.add_argument("--csv", help="輸出 CSV 檔路徑")
    ap.add_argument("--json", help="輸出 JSON 檔路徑")
    ap.add_argument("-v", "--verbose", action="store_true", help="印出封包收送記錄（含 hex）")
    args = ap.parse_args()

    if args.monitor:
        monitor(args)
        return

    sess, reader_ip = listen_reader(args)            # accept 等待期間不計時
    t0 = time.monotonic()                            # 收到卡機訊號的時間點
    try:
        users = read_users(sess, reader_ip, args)
    finally:
        try:
            sess.sock.close()
        except Exception:
            pass

    print("\n總共讀取 %d 筆使用者。" % len(users))
    write_outputs(users, args)
    elapsed_ms = (time.monotonic() - t0) * 1000
    print("執行時間（收到卡機訊號 → 存檔完成）：%.1f 毫秒" % elapsed_ms)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n中斷。")
    except (ConnectionError, OSError) as e:
        sys.exit("連線錯誤：%s" % e)
