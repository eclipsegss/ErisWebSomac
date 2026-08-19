#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
semac_save_users.py — 下傳（寫入）一筆使用者/卡片到 SEMAC / CHIYU 門禁卡機

用 0x07 RegisterModifyUserData（96-byte 封包，見 COMMAND.md §4-5）。

連線模型：卡機同一時間只維持「一條」TCP 連線，那條連線由執行中的
`semac_read_users.py --monitor` 佔著。所以本工具不自己監聽卡機，一律把指令送進
monitor 的控制通道，由 monitor 借那條卡機 socket 送出。**請先啟動 monitor。**

  1) 先跑：  python3 semac_read_users.py --port 2000 --monitor
  2) 再寫：  python3 semac_save_users.py -d 1 --uid 2719 --card 3646021037 --name 艾迪
     或查看：python3 semac_save_users.py --show

⚠️ 寫入會實際改變卡機的門禁名單（誰能進門）。請確認 UserID / 卡號 無誤。
"""

import argparse
import datetime
import json
import socket
import sys
import unicodedata

import semac_read_users as semac

CMD_REGISTER = 0x07             # RegisterModifyUserData
CONNECT_TIMEOUT = 3.0           # 連 monitor 控制通道的連線逾時（本機，很快）


# ============================ 組 0x07 酬載 ============================

def build_register_payload(uid, card, name, employee_id="", layout="basic",
                           overwrite=True, enabled=True, user_type=0,
                           groups=(1, 0, 0, 0), bypass_tz=0, password="",
                           timezones=(0,) * 8, check_expire=False,
                           expire_from=None, expire_to=None):
    """組 0x07 的酬載（封包 byte[9:] 起）。索引 = 封包 byte - 9。

    layout="basic"：基本 AC 版面（96-byte 封包，酬載 85B，COMMAND.md §4-5）。
    layout="empid"：GetBytesDataWithEmployeeID 版面（105-byte 封包，酬載 94B）——
        CardNo 後面多一個 10-byte EmployeeID，UserName 之後所有欄位往後移 10 bytes。
        位移由讀取 0x08 的「含 EmployeeID 版面」反推（寫入位移 = 讀取位移 - 6）。
    ⚠️ 用錯版面卡機仍會回結果碼 0，但姓名之後的欄位會全部錯位（啟用/群組寫不進去）。
    """
    # basic=85B 酬載→96B 封包；empid=94B 酬載→105B 封包（尾端 face/finger 區比 basic 少 1B）
    shift = 10 if layout == "empid" else 0
    p = bytearray(94 if layout == "empid" else 85)

    def put(byte_off, data):
        p[byte_off - 9:byte_off - 9 + len(data)] = data

    put(9, (uid & 0xFFFFFFFF).to_bytes(4, "big"))          # [9:13]  UserID
    p[13 - 9] = 1 if overwrite else 0                       # [13]    OverWrite
    put(14, (int(card) & (2 ** 64 - 1)).to_bytes(8, "big"))# [14:22] CardNo 8B BE
    if shift:
        put(22, employee_id.encode("utf-8")[:10])          # [22:32] EmployeeID（僅 empid）
    put(22 + shift, name.encode("utf-8")[:31])             # [22:53] UserName（補0）
    p[53 + shift - 9] = 1 if check_expire else 0            # [53]    CheckExpire
    ef = expire_from or (0, 0, 0, 0, 0)
    put(54 + shift, bytes([ef[0] % 100, ef[1], ef[2], ef[3], ef[4]]))   # [54:59] 有效起
    et = expire_to or (0, 0, 0, 0, 0)
    put(59 + shift, bytes([et[0] % 100, et[1], et[2], et[3], et[4]]))   # [59:64] 有效迄
    p[64 + shift - 9] = 1 if enabled else 0                 # [64]    EnabledStatus
    p[65 + shift - 9] = user_type & 0xFF                    # [65]    UserType
    put(66 + shift, bytes((list(groups) + [0, 0, 0, 0])[:4]))          # [66:70] Group01~04
    p[70 + shift - 9] = bypass_tz & 0xFF                    # [70]    BypassTimeZoneLevel
    put(71 + shift, password.encode("ascii", "ignore")[:8])            # [71:79] PersonalPassword
    put(79 + shift, bytes((list(timezones) + [0] * 8)[:8]))            # [79:87] TimeZone1~8
    # [87:94] 保留 = 0
    return bytes(p)


# ============================ 參數解析輔助 ============================

def parse_dt(s):
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            dt = datetime.datetime.strptime(s, fmt)
            return (dt.year, dt.month, dt.day, dt.hour, dt.minute)
        except ValueError:
            pass
    raise argparse.ArgumentTypeError("日期格式錯誤：%s（用 YYYY-MM-DD 或 YYYY-MM-DD HH:MM）" % s)


def parse_ints(s, n):
    vals = [int(x) for x in s.split(",")] if s else []
    return tuple((vals + [0] * n)[:n])


# ============================ 控制通道（送進 monitor） ============================

def control_request(args, req, timeout):
    """送一筆 JSON 指令進 monitor 控制通道，回傳回應 dict。連不到 monitor 就結束。"""
    try:
        c = socket.create_connection((args.control_host, args.control_port),
                                     timeout=CONNECT_TIMEOUT)
    except OSError:
        sys.exit("✗ 連不到 monitor 控制通道 %s:%d\n"
                 "  請先啟動：python3 semac_read_users.py --port <卡機Software Port> --monitor\n"
                 "  （monitor 若改了 --control-port，這裡要用 --control-port 指同一個）"
                 % (args.control_host, args.control_port))
    try:
        c.settimeout(timeout)
        if args.verbose:
            print(">> %s" % json.dumps(req, ensure_ascii=False), file=sys.stderr)
        c.sendall((json.dumps(req) + "\n").encode("utf-8"))
        line = c.makefile("rb").readline()
    except socket.timeout:
        sys.exit("✗ monitor 在 %g 秒內沒回應（卡機沒連上或正在忙；可調 --timeout）" % timeout)
    finally:
        c.close()
    if not line:
        sys.exit("✗ monitor 沒有回應內容（控制通道被關掉了）")
    if args.verbose:
        print("<< %s" % line.decode("utf-8", "replace").strip(), file=sys.stderr)
    return json.loads(line.decode("utf-8"))


def die_on_error(result, args):
    """把 monitor 回的錯誤碼翻成人看得懂的訊息並結束。"""
    err = result.get("error")
    if err == "no_reader":
        sys.exit("\n✗ monitor 目前沒有卡機連線（等卡機連上再試）")
    if err == "tid_mismatch":
        sys.exit("\n✗ 目標機號不符：monitor 上的卡機是 TID%s，與 -d %s 不同"
                 % (result.get("reader_tid"), args.device))
    if err == "timeout":
        sys.exit("\n✗ 逾時：卡機沒回應（機號正確嗎？是否啟用了加密/密碼？）")
    sys.exit("\n✗ 失敗：%s" % (err or ("結果碼 %s" % result.get("status"))))


def detect_layout(args, timeout):
    """讀一筆回來看卡機用哪種版面（0x08 回應含 EmployeeID → 0x07 也要用 empid）。"""
    resp = control_request(args, {"action": "read", "uid": args.uid}, timeout)
    if not resp.get("ok"):
        die_on_error(resp, args)
    users = resp.get("users") or []
    if not users:                                    # 這個 UserID 還不存在 → 拿名單裡任一筆判斷
        resp = control_request(args, {"action": "read"}, max(timeout, 300.0))
        if not resp.get("ok"):
            die_on_error(resp, args)
        users = resp.get("users") or []
    if not users:
        print("  ⚠ 卡機上沒有任何使用者可判斷版面 → 先用 basic（若寫不進去請加 --layout empid）")
        return "basic"
    lay = users[0].get("layout")
    if lay is None:                                  # monitor 還在跑沒有 layout 欄的舊版
        lay = "empid" if users[0].get("employee_id") else "basic"
        print("  ⚠ monitor 是舊版（回應沒有 layout 欄）→ 改用 employee_id 推測為 %s；"
              "請重開 monitor 讓判斷可靠" % lay)
    return "empid" if lay == "empid" else "basic"


# ============================ 顯示 ============================

def _w(s):
    """字串顯示寬度（全形字算 2 格）。"""
    return sum(2 if unicodedata.east_asian_width(ch) in "WF" else 1 for ch in str(s))


def _pad(s, n):
    s = str(s)
    return s + " " * max(0, n - _w(s))


def print_summary(args, enabled, layout):
    print("  UserID     : %d" % args.uid)
    print("  卡號       : %s" % args.card)
    print("  姓名       : %s" % (args.name or "(空)"))
    print("  封包版面   : %s%s" % (layout, "（含員工編號，105B）" if layout == "empid"
                                   else "（基本 AC，96B）"))
    if layout == "empid":
        print("  員工編號   : %s" % (args.employee_id or "(空)"))
    print("  啟用/覆寫  : %s / %s" % (enabled, not args.no_overwrite))
    print("  UserType   : %d" % args.user_type)
    print("  群組       : %s" % (parse_ints(args.groups, 4),))
    print("  時區       : %s" % (parse_ints(args.timezones, 8),))
    print("  Bypass時區 : %d" % args.bypass_tz)
    if args.password:
        print("  密碼       : %s" % args.password)
    if args.check_expire:
        print("  有效期     : %s ~ %s" % (args.expire_from, args.expire_to))


def print_users(users, tid):
    """印出卡機上的人員完整列表（--show）。"""
    print("\n卡機 TID%s 上的使用者：共 %d 筆" % (tid, len(users)))
    if not users:
        return
    emp = any(u.get("employee_id") for u in users)    # 有員工編號才多印一欄
    cols = [("UserID", 8), ("卡號", 12), ("姓名", 16)]
    if emp:
        cols.append(("員工編號", 10))
    cols += [("狀態", 6), ("型別", 5), ("群組", 13), ("時區(8門)", 16),
             ("Bypass", 7), ("密碼", 8), ("有效期", 0)]
    print("  " + " ".join(_pad(h, w) for h, w in cols))
    print("  " + "-" * (sum(w for _, w in cols) + len(cols)))
    for u in sorted(users, key=lambda x: x.get("user_id") or 0):
        state = {True: "啟用", False: "停用"}.get(u.get("enabled"), "?")
        groups = ",".join(str(g) for g in (u.get("groups") or []))
        tzs = ",".join(str(t) for t in (u.get("timezones") or []))
        expire = ("%s ~ %s" % (u.get("expire_from", ""), u.get("expire_to", ""))
                  if u.get("check_expire") else "")
        vals = [u.get("user_id", ""), u.get("card_no", ""), u.get("user_name", "")]
        if emp:
            vals.append(u.get("employee_id", ""))
        vals += [state, u.get("user_type", ""), groups, tzs,
                 u.get("bypass_tz", ""), u.get("password", "") or "", expire]
        print("  " + " ".join(_pad(v, w) for v, (_, w) in zip(vals, cols)))


# ============================ 主流程 ============================

def do_show(args, timeout):
    """--show：透過 monitor 讀回卡機上的全部使用者並列出。"""
    print("向 monitor（%s:%d）要卡機上的人員列表…（逐筆讀取，人多會慢）"
          % (args.control_host, args.control_port))
    resp = control_request(args, {"action": "read"}, timeout)
    if not resp.get("ok"):
        die_on_error(resp, args)
    print_users(resp.get("users") or [], resp.get("tid"))


def fetch_user(args, uid, timeout):
    """透過 monitor 讀一筆使用者，回傳解析後的 dict（找不到回 None）。"""
    resp = control_request(args, {"action": "read", "uid": uid}, timeout)
    if not resp.get("ok"):
        die_on_error(resp, args)
    users = resp.get("users") or []
    return users[0] if users else None


def _src_dt(s):
    """把讀回的日期字串（YYYY-MM-DD[ HH:MM]）轉成 (年,月,日,時,分)；空的回 None。"""
    if not s:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            dt = datetime.datetime.strptime(str(s), fmt)
            return (dt.year, dt.month, dt.day, dt.hour, dt.minute)
        except ValueError:
            pass
    return None


def do_register(args, timeout):
    """寫入一筆使用者（0x07），經由 monitor 送出。"""
    layout = args.layout
    if layout == "auto":
        print("偵測卡機的 0x07 封包版面…")
        layout = detect_layout(args, timeout)

    if args.clone is not None:
        src = fetch_user(args, args.clone, timeout)
        if src is None:
            sys.exit("✗ 找不到來源 UserID %d（先用 --show 看有哪些）" % args.clone)
        print("\n== 來源 UserID %d 的完整欄位（複製來源；門權限就靠這些）==" % args.clone)
        for k in ("user_id", "card_no", "user_name", "employee_id", "enabled",
                  "user_type", "bypass_tz", "groups", "timezones", "password",
                  "check_expire", "expire_from", "expire_to"):
            print("   %-13s = %r" % (k, src.get(k)))
        # 除了 UserID / 卡號 / 姓名，其餘全部照抄來源
        f = dict(
            enabled=bool(src.get("enabled", True)),
            user_type=int(src.get("user_type") or 0),
            groups=tuple((list(src.get("groups") or []) + [0, 0, 0, 0])[:4]),
            bypass_tz=int(src.get("bypass_tz") or 0),
            timezones=tuple((list(src.get("timezones") or []) + [0] * 8)[:8]),
            password=src.get("password") or "",
            employee_id=src.get("employee_id") or "",
            check_expire=bool(src.get("check_expire")),
            expire_from=_src_dt(src.get("expire_from")),
            expire_to=_src_dt(src.get("expire_to")),
            name=args.name or src.get("user_name") or "",
        )
    else:
        f = dict(
            enabled=not args.disable, user_type=args.user_type,
            groups=parse_ints(args.groups, 4), bypass_tz=args.bypass_tz,
            timezones=parse_ints(args.timezones, 8), password=args.password,
            employee_id=args.employee_id, check_expire=args.check_expire,
            expire_from=args.expire_from, expire_to=args.expire_to, name=args.name,
        )

    payload = build_register_payload(
        uid=args.uid, card=args.card, name=f["name"],
        employee_id=f["employee_id"], layout=layout,
        overwrite=not args.no_overwrite, enabled=f["enabled"],
        user_type=f["user_type"], groups=f["groups"], bypass_tz=f["bypass_tz"],
        password=f["password"], timezones=f["timezones"],
        check_expire=f["check_expire"], expire_from=f["expire_from"],
        expire_to=f["expire_to"])

    print("\n把寫入送進 monitor（%s:%d）…" % (args.control_host, args.control_port))
    print("準備寫入 → UserID %d / 卡號 %s / 姓名 %s（版面 %s）" %
          (args.uid, args.card, f["name"] or "(空)", layout))
    print("  啟用=%s UserType=%d 群組=%s 時區=%s Bypass=%d" %
          (f["enabled"], f["user_type"], f["groups"], f["timezones"], f["bypass_tz"]))
    if args.verbose:
        print("  payload    : %s" % payload.hex())

    req = {"action": "register", "payload": payload.hex()}
    if args.device:
        req["tid"] = args.device
    result = control_request(args, req, timeout)
    if not result.get("ok"):
        die_on_error(result, args)
    print("\n✓ 寫入成功（卡機回結果碼 0，TID=%s）" % result.get("tid"))


def main():
    ap = argparse.ArgumentParser(
        description="下傳（寫入）一筆使用者/卡片到 SEMAC/CHIYU 門禁卡機（0x07）；"
                    "需要先啟動 semac_read_users.py --monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("-d", "--device", type=int, metavar="TID",
                    help="指定卡機機號 TerminalID（不符就不寫；不填則寫 monitor 上那台）")
    ap.add_argument("--control-host", default="127.0.0.1", help="monitor 控制通道位址（預設 127.0.0.1）")
    ap.add_argument("--control-port", type=int, default=semac.DEFAULT_CONTROL_PORT,
                    help="monitor 控制通道埠（預設 %d，要和 monitor 一致）" % semac.DEFAULT_CONTROL_PORT)
    ap.add_argument("--timeout", type=float, default=None,
                    help="等 monitor 回應的秒數（寫入預設 30；--show 預設 300）")
    ap.add_argument("-v", "--verbose", action="store_true", help="印出控制通道的往返 JSON 與 payload")
    # ---- 查看 ----
    ap.add_argument("--show", action="store_true",
                    help="顯示卡機上目前的人員列表（不寫入任何東西）")
    # ---- 要寫入的資料 ----
    ap.add_argument("--uid", type=int, help="UserID（寫入時必填）")
    ap.add_argument("--card", default="0", help="卡號（十進位，預設 0）")
    ap.add_argument("--name", default="", help="姓名")
    ap.add_argument("--clone", type=int, metavar="SRC_UID",
                    help="從某個能開門的 UserID 複製全部權限（群組/時區/型別…）到新卡，"
                         "只換 --uid / --card / --name")
    ap.add_argument("--employee-id", default="", help="員工編號（只有 empid 版面的卡機有，≤10 字元）")
    ap.add_argument("--layout", choices=("auto", "basic", "empid"), default="auto",
                    help="0x07 封包版面：auto=先讀一筆自動判斷（預設）、"
                         "basic=96B 基本 AC、empid=105B 含員工編號")
    ap.add_argument("--user-type", type=int, default=0, help="使用者型別（預設 0）")
    en = ap.add_mutually_exclusive_group()
    en.add_argument("--enable", action="store_true", help="啟用此使用者（預設就是啟用）")
    en.add_argument("--disable", action="store_true", help="停用此使用者（資料留著但不能進門）")
    ap.add_argument("--no-overwrite", action="store_true", help="不覆寫既有資料（預設覆寫）")
    ap.add_argument("--password", default="", help="個人密碼（最多 8 碼）")
    ap.add_argument("--groups", default="1,0,0,0", help="4 個群組，逗號分隔（預設 1,0,0,0）")
    ap.add_argument("--bypass-tz", type=int, default=0, help="Bypass 時區等級（預設 0）")
    ap.add_argument("--timezones", default="0,0,0,0,0,0,0,0",
                    help="8 個門對應時區，逗號分隔（預設全 0）")
    ap.add_argument("--check-expire", action="store_true", help="啟用有效期限檢查")
    ap.add_argument("--expire-from", type=parse_dt, help="有效起（YYYY-MM-DD[ HH:MM]）")
    ap.add_argument("--expire-to", type=parse_dt, help="有效迄（YYYY-MM-DD[ HH:MM]）")
    args = ap.parse_args()

    if args.uid is None and not args.show:
        ap.error("要寫入請給 --uid；只是想看卡機上有誰請用 --show")

    if args.uid is not None:                         # 有 --uid 就先寫入
        do_register(args, args.timeout if args.timeout is not None else 30.0)
    if args.show:                                    # --show 最後才讀，看得到寫入後的結果
        do_show(args, args.timeout if args.timeout is not None else 300.0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n中斷。")
    except (ConnectionError, OSError) as e:
        sys.exit("連線錯誤：%s" % e)
