# Eris Web Somac

`semac_read_users.py` — 讀取 SEMAC / CHIYU 門禁卡機內已註冊的使用者資料
（UserID、卡號、姓名、員工編號、群組、時區、密碼、有效期限…），輸出成 CSV / JSON。
`semac_save_users.py` 寫入卡片、`semac_show_devices.py` 查看線上卡機。

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
[2026-01-04 09:09:37.564] 192.168.2.216 TID403 LogIdx=100 門1 進(1) 驗證:Card(1) 事件:None(0) UserID=2719 卡號=3646021037 FuncKey:None(0) Relay=0 溫度=0.0 UserType=0
[2026-08-19 13:39:00.577] 192.168.0.166 TID1 LogIdx=1234 門1 進(1) 驗證:Card(1) 事件:Unregistered User(7) UserID=0 卡號=3496509115 FuncKey:None(0) Relay=1 溫度=36.5 UserType=2
```

每筆會印出**卡機上傳的所有欄位**（括號內是原始代碼）：進出別、驗證方式、事件/警報、
門號、UserID、卡號、功能鍵、繼電器、體溫、使用者型別、LogIndex。

- `✓ 卡機 socket 已連上` — TCP 連上的當下就會顯示，知道卡機有沒有連進來。
- `♥ 收到 keepalive → 已回送 KeepAliveCheck 對時` — 卡機每次送 keepalive 就回一個帶
  目前時間的封包幫它**對時**，同時也代表連線還活著。
- `✗ 卡機連線中斷` — 斷線時顯示，並自動繼續等待重連。

刷卡時間格式為 `YYYY-mm-dd HH:mm:ss.xxx`；日期時間（到秒）來自卡機紀錄，毫秒 `.xxx`
是收到當下補上的（卡機硬體只有秒解析度，時鐘已靠 keepalive 對時）。

CSV 欄位：`time, reader_ip, tid, log_index, door_no, user_id, card_no, inout_code, inout,
verify_code, verify, event_code, event, func_key_code, func_key, relay_type, temperature, user_type`。
封包格式與各欄位代碼對照見 [`COMMAND.md`](COMMAND.md) §4-7。

## 參數

| 參數 | 預設 | 說明 |
|---|---|---|
| `--port PORT` | `1621` | 本機監聽埠，設成卡機的 **Software Port** |
| `--monitor` | — | 持續監聽即時刷卡（`0x51`），Ctrl-C 結束；配 `--csv` 附加寫檔 |
| `--control-port PORT` | `12000` | monitor 控制通道埠（其它工具送指令進來；`0` 關閉） |
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

## 寫入卡片到卡機（semac_save_users.py）

下傳一筆使用者/卡片到卡機（`0x07 RegisterModifyUserData`），資料全部用參數指定。

> **卡機同一時間只有一條 TCP 連線**，那條連線由執行中的 `--monitor` 佔著。
> 所以本工具不自己監聽卡機，一律把指令**送進正在跑的 monitor**（透過它的控制通道），
> 由 monitor 借那條卡機 socket 送出。**請先啟動 monitor**：

```bash
# 1) 先開 monitor（持有卡機連線 + 控制通道）
python3 semac_read_users.py --port 2000 --monitor

# 2) 另一個視窗寫入（送進 monitor）
python3 semac_save_users.py -d 1 --uid 2719 --card 3646021037 --name 艾迪

# 查看卡機上目前有哪些人（不寫入任何東西）
python3 semac_save_users.py --show

# 寫入後順便讀回來確認（--uid 和 --show 併用＝先寫再列）
python3 semac_save_users.py -d 1 --uid 2719 --card 3496509115 --name 貴賓卡 --show
```

連不到 monitor 控制通道會直接報錯結束（不會自己去搶卡機連線）。
`-d/--device` 指定目標機號 TID：monitor 上的卡機機號不符就不寫。

> **封包版面（`--layout`）**：`0x07` 有兩種版面 —— 基本 AC（96B）和含員工編號的
> `WithEmployeeID`（106B，姓名之後所有欄位往後移 10 bytes，見 COMMAND.md §4-5b）。
> **用錯版面卡機照樣回結果碼 0，但寫進去的人永遠是「停用」、群組全 0。**
> 預設 `--layout auto` 會先讀一筆回來自動判斷，通常不用管。

| 參數 | 預設 | 說明 |
|---|---|---|
| `--show` | — | 顯示卡機上目前的人員列表（走 monitor 的 `read`，不寫入） |
| `-d, --device TID` | — | 目標卡機機號；不符就不寫 |
| `--control-host/-port` | `127.0.0.1` / `12000` | monitor 控制通道位址（要和 monitor 一致） |
| `--timeout SEC` | 寫入 `30` / `--show` `300` | 等 monitor 回應的秒數 |
| `-v, --verbose` | — | 印出控制通道往返的 JSON 與 payload hex |
| `--uid N` | 寫入時必填 | UserID |
| `--card N` | `0` | 卡號（十進位） |
| `--name S` | 空 | 姓名 |
| `--employee-id S` | 空 | 員工編號（只有 `empid` 版面的卡機有，≤10 字元） |
| `--layout auto\|basic\|empid` | `auto` | `0x07` 封包版面；`auto` 先讀一筆自動判斷 |
| `--user-type N` | `0` | 使用者型別 |
| `--enable` / `--disable` | 啟用 | 啟用（預設）／停用此使用者（資料留著但不能進門） |
| `--no-overwrite` | （覆寫） | 不覆寫既有資料 |
| `--password S` | 空 | 個人密碼（≤8 碼） |
| `--groups a,b,c,d` | `1,0,0,0` | 4 個群組 |
| `--bypass-tz N` | `0` | Bypass 時區等級 |
| `--timezones ...` | `0,0,0,0,0,0,0,0` | 8 個門對應時區 |
| `--check-expire` + `--expire-from/-to` | — | 有效期限（`YYYY-MM-DD[ HH:MM]`） |

> ⚠️ 這會實際改變卡機門禁名單（誰能進門）。確認 UserID / 卡號無誤再送。
> 沒有「一次傳整批」的命令，要下傳多筆就對每筆各跑一次（各送一包 `0x07`）。

## 查看線上卡機（semac_show_devices.py）

顯示目前**在線上的卡機**。跟 `semac_save_users.py` 一樣走 monitor 的控制通道
（`--control-host` / `--control-port`），只送一筆 `status` 查詢，不對卡機下任何指令、
不影響正在跑的刷卡監聽。

一個 monitor 同時只握著**一台**卡機的連線，所以多台卡機 = 多個 monitor
（各自不同的 `--port` 與 `--control-port`）。要一次看全部，把控制埠都列出來：

```bash
# 每台卡機各一個 monitor
python3 semac_read_users.py --port 2000 --monitor --control-port 12000
python3 semac_read_users.py --port 2001 --monitor --control-port 12001

# 一次查全部（可用逗號或區間）
python3 semac_show_devices.py --control-port 12000-12009
```

輸出範例：

```
查詢控制通道 127.0.0.1 埠 12000,12001,12002…
  控制通道        機號   卡機 IP:Port         監聽埠  已上線       最後訊號   刷卡
  --------------------------------------------------------------------------------
  127.0.0.1:12000 TID403 192.168.2.216:4833   2000    01:12:33     3 秒前     5
  127.0.0.1:12001 TID1   192.168.0.166:5120   2001    00:04:07     剛剛       0

  127.0.0.1:12002       （monitor 在跑，但卡機還沒連進來；監聽埠 2002）

線上卡機：2 台（查詢 3 個控制通道，3 個有 monitor 回應）
```

欄位：**控制通道**（哪個 monitor）、**機號** TerminalID、**卡機 IP:Port**（卡機連進來的來源）、
**監聽埠**（monitor 的 `--port`）、**已上線**（這條連線接上多久）、
**最後訊號**（最後收到卡機封包，正常時每次 keepalive 都會更新）、**刷卡**（這條連線收到幾筆）。

沒有 monitor 回應時離開碼為 `1`（方便寫在監控腳本裡）。

| 參數 | 預設 | 說明 |
|---|---|---|
| `--control-host HOST` | `127.0.0.1` | monitor 控制通道位址 |
| `--control-port PORT` | `12000` | 控制通道埠，可用 `12000,12001` 或 `12000-12009`，也可重複指定 |
| `--timeout SEC` | `3` | 等 monitor 回應的秒數 |
| `--json` | — | 輸出原始 JSON（給程式用） |
| `-v, --verbose` | — | 印出控制通道往返的 JSON |

## 控制通道（monitor 當常駐服務）

`--monitor` 除了印刷卡，也會開一個本機**控制通道**（預設 `127.0.0.1:12000`），
讓其它工具把指令送進來、借用那條卡機 socket。目前支援：`register`（寫入）、
`read`（讀全部使用者）、`status`（回報目前卡機連線：機號、來源 IP:Port、監聽埠、
上線時間、最後訊號時間、刷卡筆數）。`semac_save_users.py`（`register`/`read`）與
`semac_show_devices.py`（`status`）就是走這個通道。
控制通道只綁 `127.0.0.1`（僅本機）；要關掉用 `--control-port 0`。

## 協定

收送的封包格式（框架、命令碼、各欄位 byte 位移、實際 hex 範例）整理在
[`COMMAND.md`](COMMAND.md)。重點：

- 請求(PC→卡機)命令碼在 `byte[8]`；回應(卡機→PC)`byte[8]` 是**結果碼（0=成功）**、
  命令碼在 `byte[9]`、資料從 `byte[16]` 起。
- 讀使用者用三個命令：`0x04` 查人數、`0x06` 取 UserID 清單、`0x08` 讀單筆。
- 寫使用者用 `0x07`（96-byte）；即時刷卡是卡機主動送 `0x51`。
- 全程要回覆卡機的 keepalive（`0x50`，含軟體版本，否則卡機顯示「軟體不支援」）維持連線。

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
