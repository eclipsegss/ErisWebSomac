# Eris Web Somac

`semac_read_users.py` — 讀取 SEMAC / CHIYU 門禁卡機內已註冊的使用者資料
（UserID、卡號、姓名、員工編號、群組、時區、密碼、有效期限…），輸出成 CSV / JSON。

協定逆向自 `lib/SemacV14.dll`，與 Somac 主程式使用同一套 TCP 封包格式，
已在實機（CHIYU 卡機，TerminalID=403）驗證，可一次讀出全部使用者。
封包收送格式細節見 [`COMMAND.md`](COMMAND.md)。

## 需求

- Python 3.6+（只用標準函式庫，免安裝套件）

## 原理

CHIYU 卡機是**主動連出**到伺服器的（自己不開資料埠），所以本工具走 **listen 模式**：
腳本開一個埠監聽，等卡機連進來，再從那條 socket 下指令、收回結果。

## 使用方式

```bash
python3 semac_read_users.py --port 2000 --csv users.csv
```

要點：

1. `--port` 用**卡機設定裡的 Software Port**（例：2000）。
2. 把卡機的 **Software IP** 指到「執行這支腳本的電腦」（用 `SeMacSearch.exe` 設定，
   或先關掉 Somac 讓腳本佔用同一個 IP:Port）。
3. 執行後會停在「等待卡機連入…」，等卡機**重連**（想快點就從卡機網頁重開機它）。
4. 卡機連入後會自動辨識機號、讀出全部使用者、寫檔，最後印出**執行時間（毫秒）**。

輸出範例：

```
在 0.0.0.0:2000 等待卡機連入…
卡機已連入：192.168.2.216:4833
使用 TerminalID = 403
已註冊 49 / 可用 951 / 上限 1000
卡機回報已註冊 UserID 共 49 筆
  [1/49] UserID 2719     卡號 3646021037   姓名 艾迪
  ...
總共讀取 49 筆使用者。
已寫出 CSV：users.csv
執行時間（收到卡機訊號 → 存檔完成）：xxx.x 毫秒
```

## 即時刷卡監聽（--monitor）

持續監聽卡機主動上傳的刷卡紀錄（`0x51`），有人刷卡就即時印出，`Ctrl-C` 結束。
卡機斷線會自動等待重連。加 `--csv` 會把每筆刷卡**附加**寫入 CSV（可一邊 `tail -f`）。

```bash
python3 semac_read_users.py --port 2000 --monitor --csv swipes.csv
```

輸出範例：

```
在 0.0.0.0:2000 監聽即時刷卡…（把卡機的 Software IP:Port 指到這裡；Ctrl-C 結束）
✓ [09:00:12] 卡機 socket 已連上：192.168.2.216:4833
  → 已握手，TerminalID = 403，連線正常，等待刷卡…（Ctrl-C 結束）
  [09:00:12] ♥ 收到 keepalive → 已回送 KeepAliveCheck 對時（TID403）
[2026-01-04 09:09:37.564] 192.168.2.216   TID403 門1  進    驗證:Card       UserID=2719     卡號=3646021037
[2026-01-04 09:10:05.812] 192.168.2.216   TID403 門2  進    驗證:Face       UserID=2719     卡號=3646021037  事件=5
```

- `✓ 卡機 socket 已連上` — TCP 連上的當下就會顯示，知道卡機有沒有連進來。
- `♥ 收到 keepalive → 已回送 KeepAliveCheck 對時` — 卡機每次送 keepalive 就回一個帶
  目前時間的封包幫它**對時**，同時也代表連線還活著。
- `✗ 卡機連線中斷` — 斷線時顯示，並自動繼續等待重連。

刷卡時間格式為 `YYYY-mm-dd HH:mm:ss.xxx`；日期時間（到秒）來自卡機紀錄，毫秒 `.xxx`
是收到當下補上的（卡機硬體只有秒解析度，時鐘已靠 keepalive 對時）。

CSV 欄位：`time, reader_ip, tid, door_no, user_id, card_no, inout, verify, event, log_index`。
封包格式與代碼對照見 [`COMMAND.md`](COMMAND.md) §4-7。

## 參數

| 參數 | 預設 | 說明 |
|---|---|---|
| `--port PORT` | `1621` | 本機監聽埠，設成卡機的 **Software Port** |
| `--monitor` | — | 持續監聽即時刷卡（`0x51`），Ctrl-C 結束；配 `--csv` 附加寫檔 |
| `--tid TID` | 自動偵測 | 機號；連入後會自動辨識，通常免填 |
| `--uid UID` | — | 只讀取單一 UserID（除錯用） |
| `--brute START END` | — | 不用清單，改暴力掃描 UserID 區間（如 `--brute 1 5000`） |
| `--timeout SEC` | `10` | Socket 逾時秒數 |
| `--csv PATH` | — | 輸出 CSV（含 `reader_ip` / `reader_port` 欄） |
| `--json PATH` | — | 輸出 JSON |
| `--bind ADDR` | 全部 | 綁定的本機位址（多網卡時可指定） |
| `-v, --verbose` | — | 印出每個封包的收送記錄（含完整 hex 與 `status`），除錯用 |

## 輸出欄位

| 欄位 | 說明 |
|---|---|
| `reader_ip` / `reader_port` | 來源卡機 IP / 埠 |
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

## 協定

收送的封包格式（框架、命令碼、各欄位 byte 位移、實際 hex 範例）整理在
[`COMMAND.md`](COMMAND.md)。重點：

- 請求(PC→卡機)命令碼在 `byte[8]`；回應(卡機→PC)`byte[8]` 是**結果碼（0=成功）**、
  命令碼在 `byte[9]`、資料從 `byte[16]` 起。
- 讀使用者用三個命令：`0x04` 查人數、`0x06` 取 UserID 清單、`0x08` 讀單筆。
- 全程要回覆卡機的 keepalive（`0x50`）維持連線。

## 限制

- 假設卡機**未啟用**傳輸加密（AES）、TLS 或連線密碼（Terminal Passcode）。
  若有啟用，酬載為密文，需對應金鑰，本工具無法解讀。

## 疑難排解

| 現象 | 可能原因 / 解法 |
|---|---|
| 一直停在「等待卡機連入…」 | 卡機還沒重連 → 從卡機網頁重開機它；確認它的 Software IP 指到本機、Software Port = `--port` |
| `Address already in use` | 上一個執行沒關乾淨 → `lsof -iTCP:<port> -sTCP:LISTEN` 找到並關掉 |
| 讀到清單但每筆逾時 | 機號不符 → 用 `--tid` 指定正確機號 |
| `-v` 看到某指令 `status` 非 0 | 該命令被卡機拒絕（權限/機號/加密）→ 貼該行 hex 分析 |
| 姓名/卡號是亂碼 | 卡機啟用了加密傳輸，本工具不支援 |
| UserID 清單為空 | 卡機無使用者，或韌體不支援 `0x06` → 試 `--brute 1 N` |

用 `-v` 可看到每個封包的完整 hex 與 `status`，方便判斷卡在哪一步。
