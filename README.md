# Eris Web Somac

`semac_read_users.py` — 讀取 SEMAC / CHIYU 門禁卡機內已註冊的使用者資料
（UserID、卡號、姓名、員工編號、群組、時區、密碼、有效期限…），輸出成 CSV / JSON。

協定逆向自 `lib/SemacV14.dll`，與 Somac 主程式使用同一套 TCP 封包格式。

## 需求

- Python 3.6+（只用標準函式庫，免安裝套件）

## 設定卡機清單

編輯 `config/device.py`，把要讀取的卡機填進 `READERS`：

```python
READERS = [
    {"ip": "192.168.2.216", "port": 2000, "enabled": True},
    # 同一 IP 多個埠（多台控制器）：port 用清單，會各自展開成獨立目標
    # {"ip": "192.168.2.217", "port": [2000, 2001, 2002], "enabled": True},
    # {"ip": "192.168.2.218", "port": 2000, "enabled": False, "tid": 8625},
]
```

| 欄位 | 說明 |
|---|---|
| `ip` | 卡機 IP（必填） |
| `enabled` | `True` 才會掃描這台；`False` 略過 |
| `port` | 該台的埠。可為單一值 `2000`，或清單 `[2000, 2001]`（同一 IP 上多個控制器，會各自展開成獨立目標）。不填則用 `--port` |
| `tid` | 選填，TerminalID 機號；不填則自動偵測，或用 `--tid` |

執行時程式會自動讀取這個檔，只處理 `enabled=True` 的卡機，並把每個 `(ip, port)`
展開成一個獨立目標（可用 `--core` 並行）。

> 註：`config/device.py` 可選擇性提供 `DEFAULT_PORT`；未提供時預設為 `1621`。

## 使用方式

最簡單，依 `config/device.py` 的清單逐台讀取並印出：

```bash
python3 semac_read_users.py
```

輸出成檔案：

```bash
python3 semac_read_users.py --csv users.csv --json users.json
```

多台並行（例如 4 台同時讀）：

```bash
python3 semac_read_users.py --core 4 --csv users.csv
```

只讀某一台的單一 UserID（除錯用）：

```bash
python3 semac_read_users.py --uid 1001
```

## 參數

| 參數 | 預設 | 說明 |
|---|---|---|
| `--mode {connect,listen}` | `connect` | `connect`：依 `READERS` 陣列主動連卡機。`listen`：本機監聽，等單台卡機連進來（見下方） |
| `--core N` | `1` | 同時處理的卡機數量（並行度） |
| `--port PORT` | `1621` | 卡機 TCP 埠（`listen` 時為本機監聽埠） |
| `--tid TID` | 自動偵測 | 機號；陣列未指定時的預設值 |
| `--uid UID` | — | 只讀取單一 UserID |
| `--brute START END` | — | 不用清單，改暴力掃描 UserID 區間（如 `--brute 1 5000`） |
| `--timeout SEC` | `10` | Socket 逾時秒數 |
| `--csv PATH` | — | 輸出 CSV（多台合併，含 `reader_ip` 欄） |
| `--json PATH` | — | 輸出 JSON |
| `--bind ADDR` | 全部 | `listen` 模式綁定的本機位址 |
| `-v, --verbose` | — | 印出封包收送記錄（除錯用） |

## 兩種連線模式

卡機與軟體的連線方向有兩種，依你的卡機設定選擇：

### connect 模式（預設）

腳本主動連上卡機的 IP:Port。適用於卡機本身在「伺服器模式」監聽的情況。
`config/device.py` 的陣列就是給這個模式用的。

```bash
python3 semac_read_users.py --core 4
```

### listen 模式

腳本自己開一個埠監聽，等卡機連進來 —— 這與 Somac 主程式的行為相同
（卡機開機後主動連向設定好的 Software IP:Port）。

用這個模式時，需要把某一台卡機的 **Software IP:Port** 指到執行腳本的這台電腦
（用 `SeMacSearch.exe` 設定，或先關掉 Somac 讓腳本佔用同一個埠）：

```bash
python3 semac_read_users.py --mode listen --port 7000
```

程式會等第一台卡機連入、自動辨識機號，再讀取資料。此模式一次處理一台。

## 輸出欄位

| 欄位 | 說明 |
|---|---|
| `reader_ip` | 來源卡機 IP |
| `reader_port` | 來源卡機埠 |
| `user_id` | 使用者編號 |
| `card_no` | 卡號（十進位） |
| `employee_id` | 員工編號（僅支援的機型有） |
| `user_name` | 姓名 |
| `enabled` | 是否啟用 |
| `user_type` | 使用者類型代碼 |
| `bypass_tz` | Bypass 時區等級 |
| `password` | 個人密碼 |
| `groups` | 4 個群組代碼 |
| `timezones` | 各門對應時區 |
| `check_expire` / `expire_from` / `expire_to` | 有效期限設定與起訖 |
| `tid` | 卡機機號 |

## 限制

- 假設卡機**未啟用**傳輸加密（AES）、TLS 或連線密碼（Terminal Passcode）。
  若有啟用，需要對應金鑰，本工具無法解讀（會逾時或拿到亂碼）。
- `connect` 模式能否連上，取決於卡機是否允許被主動連入；若你的卡機是設定成
  「連出到 Somac」，請改用 `listen` 模式。

## 疑難排解

| 現象 | 可能原因 |
|---|---|
| 連線逾時 | 卡機不接受主動連線 → 改用 `--mode listen`；或埠不對（試 `--port`） |
| 讀到清單但每筆都逾時 | 機號（tid）不符，卡機不回應 → 在陣列或 `--tid` 指定正確機號 |
| 姓名/卡號是亂碼 | 卡機啟用了加密傳輸，本工具不支援 |
| UserID 清單為空 | 卡機無使用者，或韌體不支援 0x06；可改 `--brute 1 N` 掃描 |

用 `-v` 可看到每個封包的收送記錄，方便判斷卡在哪一步。
