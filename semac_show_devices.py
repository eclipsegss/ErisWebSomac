#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
semac_show_devices.py — 顯示目前在線上的 SEMAC / CHIYU 門禁卡機

跟 semac_save_users.py 一樣走 monitor 的控制通道（--control-host / --control-port），
對每個控制通道送一筆 {"action":"status"}，把回報的卡機狀態列成表。

一個 monitor 同時只握著「一台」卡機的連線，所以多台卡機 = 多個 monitor
（各自不同的 --port 與 --control-port）。要一次看全部，把控制埠都列出來：

  1) 每台卡機各開一個 monitor：
     python3 semac_read_users.py --port 2000 --monitor --control-port 12000
     python3 semac_read_users.py --port 2001 --monitor --control-port 12001

  2) 一次查全部：
     python3 semac_show_devices.py --control-port 12000-12009

不下任何指令給卡機，只問 monitor 目前的連線狀態（不影響刷卡監聽）。
"""

import argparse
import json
import socket
import sys
import threading
import unicodedata

import semac_read_users as semac

MAX_PORTS = 256                 # 一次最多查幾個控制通道（避免手滑掃整個埠段）
DEFAULT_TIMEOUT = 3.0           # 控制通道在本機，通常毫秒等級就回


# ============================ 參數：控制埠清單 ============================

def parse_ports(specs):
    """把 --control-port 的值展開成埠清單。支援 '12000'、'12000,12001'、'12000-12009'。"""
    ports = []
    for spec in specs:
        for part in str(spec).split(","):
            part = part.strip()
            if not part:
                continue
            try:
                if "-" in part.lstrip("-"):
                    a, b = part.split("-", 1)
                    lo, hi = int(a), int(b)
                    if lo > hi:
                        lo, hi = hi, lo
                    rng = range(lo, hi + 1)
                else:
                    rng = [int(part)]
            except ValueError:
                raise SystemExit("✗ --control-port 格式錯誤：%s（用 12000、12000,12001 或 12000-12009）" % part)
            for p in rng:
                if not 1 <= p <= 65535:
                    raise SystemExit("✗ 控制埠超出範圍：%d" % p)
                if p not in ports:
                    ports.append(p)
    if not ports:
        raise SystemExit("✗ 沒有指定任何控制埠")
    if len(ports) > MAX_PORTS:
        raise SystemExit("✗ 一次最多查 %d 個控制埠（目前 %d 個）" % (MAX_PORTS, len(ports)))
    return ports


# ============================ 控制通道查詢 ============================

def query_status(host, port, timeout, verbose):
    """對一個控制通道問 status，回傳結果 dict（reachable=False 表示連不到 monitor）。"""
    req = {"action": "status"}
    try:
        c = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        return {"port": port, "reachable": False, "error": e.strerror or str(e)}
    try:
        c.settimeout(timeout)
        if verbose:
            print(">> %s:%d %s" % (host, port, json.dumps(req)), file=sys.stderr)
        c.sendall((json.dumps(req) + "\n").encode("utf-8"))
        line = c.makefile("rb").readline()
    except socket.timeout:
        return {"port": port, "reachable": False, "error": "逾時（monitor 沒回應）"}
    except OSError as e:
        return {"port": port, "reachable": False, "error": e.strerror or str(e)}
    finally:
        c.close()
    if not line:
        return {"port": port, "reachable": False, "error": "沒有回應內容"}
    if verbose:
        print("<< %s:%d %s" % (host, port, line.decode("utf-8", "replace").strip()), file=sys.stderr)
    try:
        resp = json.loads(line.decode("utf-8"))
    except ValueError:
        return {"port": port, "reachable": False, "error": "回應不是 JSON"}
    resp["port"], resp["reachable"] = port, True
    return resp


def query_all(host, ports, timeout, verbose):
    """同時問所有控制通道（連不到的會擋滿 timeout，所以要並行）。"""
    results = [None] * len(ports)

    def work(i, p):
        results[i] = query_status(host, p, timeout, verbose)

    threads = [threading.Thread(target=work, args=(i, p), daemon=True)
               for i, p in enumerate(ports)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout + 2.0)
    return [r for r in results if r is not None]


# ============================ 顯示 ============================

def _w(s):
    """字串顯示寬度（全形字算 2 格）。"""
    return sum(2 if unicodedata.east_asian_width(ch) in "WF" else 1 for ch in str(s))


def _pad(s, n):
    s = str(s)
    return s + " " * max(0, n - _w(s))


def fmt_duration(sec):
    """秒數 → 3 天 04:05:06 / 04:05:06 / 05:06。"""
    if sec is None or sec < 0:
        return "-"
    sec = int(sec)
    d, rem = divmod(sec, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    if d:
        return "%d 天 %02d:%02d:%02d" % (d, h, m, s)
    if h:
        return "%02d:%02d:%02d" % (h, m, s)
    return "%02d:%02d" % (m, s)


def fmt_ago(sec):
    """幾秒前 → 人看的字串。"""
    if sec is None or sec < 0:
        return "-"
    if sec < 1:
        return "剛剛"
    if sec < 60:
        return "%d 秒前" % int(sec)
    if sec < 3600:
        return "%d 分前" % int(sec // 60)
    return fmt_duration(sec) + "前"


def _row(r, host):
    """把一筆 status 回應整理成表格欄位（tid 為 None 代表沒有卡機在線上）。"""
    if not r.get("reachable"):
        return {"ctrl": "%s:%d" % (host, r["port"]), "tid": None,
                "note": "✗ 連不到 monitor（%s）" % r.get("error", "?")}
    if not r.get("ok"):
        return {"ctrl": "%s:%d" % (host, r["port"]), "tid": None,
                "note": "✗ monitor 回報錯誤：%s" % r.get("error", "?")}
    if not r.get("connected"):
        return {"ctrl": "%s:%d" % (host, r["port"]), "tid": None,
                "note": "（monitor 在跑，但卡機還沒連進來；監聽埠 %s）"
                        % (r.get("listen_port") if r.get("listen_port") is not None else "?")}
    now = r.get("now")
    up = (now - r["connected_at"]) if (now and r.get("connected_at")) else None
    ago = (now - r["last_seen"]) if (now and r.get("last_seen")) else None
    addr = str(r.get("reader_ip") or "?")
    if r.get("reader_port"):
        addr += ":%d" % r["reader_port"]
    return {"ctrl": "%s:%d" % (host, r["port"]), "tid": r.get("tid"), "addr": addr,
            "listen": r.get("listen_port"), "up": fmt_duration(up), "ago": fmt_ago(ago),
            "swipes": r.get("swipes", 0)}


def print_devices(results, host):
    rows = [_row(r, host) for r in sorted(results, key=lambda x: x["port"])]
    online = [r for r in rows if r["tid"] is not None]

    if online:
        cw = max([_w(r["ctrl"]) for r in online] + [_w("控制通道")])
        aw = max([_w(r["addr"]) for r in online] + [_w("卡機 IP:Port")])
        head = "  %s %s %s %s %s %s %s" % (
            _pad("控制通道", cw), _pad("機號", 6), _pad("卡機 IP:Port", aw),
            _pad("監聽埠", 7), _pad("已上線", 12), _pad("最後訊號", 10), "刷卡")
        print(head)
        print("  " + "-" * (_w(head) - 2))
        for r in online:
            print("  %s %s %s %s %s %s %s" % (
                _pad(r["ctrl"], cw), _pad("TID%s" % r["tid"], 6), _pad(r["addr"], aw),
                _pad(r["listen"] if r["listen"] is not None else "?", 7),
                _pad(r["up"], 12), _pad(r["ago"], 10), r["swipes"]))

    offline = [r for r in rows if r["tid"] is None]
    if offline:
        if online:
            print()
        for r in offline:
            print("  %s %s" % (_pad(r["ctrl"], 21), r["note"]))

    reached = sum(1 for r in results if r.get("reachable"))
    print("\n線上卡機：%d 台（查詢 %d 個控制通道，%d 個有 monitor 回應）"
          % (len(online), len(results), reached))
    return len(online), reached


# ============================ 主流程 ============================

def main():
    ap = argparse.ArgumentParser(
        description="顯示目前在線上的 SEMAC/CHIYU 門禁卡機（問 monitor 的控制通道）",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("--control-host", default="127.0.0.1",
                    help="monitor 控制通道位址（預設 127.0.0.1）")
    ap.add_argument("--control-port", action="append", metavar="PORT",
                    help="monitor 控制通道埠，可用逗號或區間並可重複指定"
                         "（如 12000,12001 或 12000-12009；預設 %d）"
                         % semac.DEFAULT_CONTROL_PORT)
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                    help="等 monitor 回應的秒數（預設 %g）" % DEFAULT_TIMEOUT)
    ap.add_argument("--json", action="store_true", help="輸出原始 JSON（給程式用）")
    ap.add_argument("-v", "--verbose", action="store_true", help="印出控制通道往返的 JSON")
    args = ap.parse_args()

    ports = parse_ports(args.control_port or [str(semac.DEFAULT_CONTROL_PORT)])
    if not args.json:
        print("查詢控制通道 %s 埠 %s…"
              % (args.control_host, ",".join(str(p) for p in ports)))
    results = query_all(args.control_host, ports, args.timeout, args.verbose)

    if args.json:
        print(json.dumps(sorted(results, key=lambda x: x["port"]),
                         ensure_ascii=False, indent=2))
        return 0 if any(r.get("reachable") for r in results) else 1

    online, reached = print_devices(results, args.control_host)
    if not reached:
        sys.stdout.flush()                           # 讓下面的 stderr 訊息接在表格後面
        print("\n沒有任何 monitor 回應。請先啟動：\n"
              "  python3 semac_read_users.py --port <卡機Software Port> --monitor"
              " --control-port <控制埠>", file=sys.stderr)
        return 1
    if not online:
        print("  提示：monitor 有在跑但卡機沒連進來 → 確認卡機的 Software IP:Port"
              " 指到 monitor，或從卡機網頁重開機它。")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n中斷。")
