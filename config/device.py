# -*- coding: utf-8 -*-
"""
卡機清單設定，供 semac_read_users.py 執行時引用。

每台一筆字典：
    ip      : 卡機 IP（必填）
    enabled : True=這台要掃描/讀取；False=略過
可選欄位：
    port    : 該台的 TCP 埠（不填則用命令列 --port，預設 DEFAULT_PORT）
    tid     : TerminalID 機號（不填則自動偵測或用 --tid）
"""

READERS = [{
    "ip": "192.168.2.216",
    "port": 2000,
    "enabled": True
}]
