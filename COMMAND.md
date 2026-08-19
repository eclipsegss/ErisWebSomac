# SEMAC / CHIYU 卡機 Socket 通訊指令

逆向自 `lib/SemacV14.dll`，並用實機（192.168.2.216，TerminalID=403）驗證過。
本文件記錄「讀取使用者資料」實際會用到的封包收送格式。

---

## 1. 連線模型

- 卡機是 **TCP client**：開機後主動連到它設定的 `Software IP : Software Port`。
- 軟體（或本工具 `--mode listen`）是 **TCP server**：監聽、等卡機連入。
- 連上後就是**一條雙向 socket**：卡機持續送 keepalive、軟體從同一條 socket 下指令、
  卡機從同一條 socket 回結果。軟體**不會**另外開連線去連卡機。

---

## 2. 封包框架

共通外框：

```
+------+------+-----------+-----------+-----  ...  -----+----------+------+
| STX  | SOH  |  Length   | TerminalID|     內容        | Checksum | ETX  |
| 1 B  | 1 B  |  4 B BE   |  2 B BE   |                 |   1 B    | 1 B  |
+------+------+-----------+-----------+-----------------+----------+------+
 [0]    [1]    [2:6]       [6:8]        [8:len-2]         [len-2]   [len-1]
```

| 欄位 | 說明 |
|---|---|
| STX | PC→卡機 = `0x07`；卡機→PC = `0x09` |
| SOH | 固定 `0x03` |
| Length | **整包總長度**，4 bytes big-endian |
| TerminalID | 機號，2 bytes big-endian |
| Checksum | `sum(frame[0 : len-2]) & 0xFF`（含表頭，不含 checksum 與 ETX 自己） |
| ETX | 固定 `0x04` |

> 所有多位元組數值一律 **big-endian**。

### 2-1. 關鍵差異：請求與回應的「內容」排版不同 ⚠️

這是最容易踩雷的地方 —— 請求把命令放 `[8]`，回應把命令放 `[9]`（回應表頭多 7 bytes）。

**請求 (PC→卡機)：**

```
[8]      命令碼 (Command)
[9:]     酬載 (依命令而定)
```

**回應 (卡機→PC)：**

```
[8]      結果碼 (Status)   0 = 成功、非 0 = 失敗/無資料
[9]      命令碼 (Command)  ← Func.GetCommandType 讀這個 byte
[10:16]  卡機 MAC (6 B)
[16:]    資料酬載
```

對應 DLL：`Func.GetCommandType` 讀 `byte[9]`；各 `GetEntity.*` 以 `byte[8]==0`
（brfalse→解析）判定成功，資料欄位從 `byte[16]` 起算。

---

## 3. 命令碼（本工具用到的）

| 碼 | 名稱 | 用途 |
|----|------|------|
| `0x01` | UserDeletion | 刪除單一使用者 |
| `0x02` | AllUsersDeletion | 刪除全部使用者 |
| `0x04` | QueryTheNumberOfAlreadyRegisteredUsers | 查詢已註冊人數 |
| `0x06` | RetrievingUserIDList | 取得已註冊的 UserID 清單 |
| `0x08` | GetUserData | 讀取單一 UserID 的完整資料 |
| `0x07` | RegisterModifyUserData | **寫入 / 更新單一使用者（下傳）** |
| `0x50` | KeepAliveCheck | 卡機主動送；伺服器回同碼（含時間，順便對時） |
| `0x51` | RealtimeTransaction | **卡機主動上傳：即時刷卡紀錄** |
| `0x59` | OffLineLogTransaction | 卡機補傳離線刷卡紀錄（record 格式同 `0x51`） |

（完整命令列舉見 `SemacV14.CommandType`，例如 `0x51` 即時刷卡…）

---

## 4. 各指令收送格式

範例機號 TerminalID = 403 = `0x0193`。

### 4-1. `0x04` 查詢人數

**送 (11 bytes)：**

```
07 03 0000000B 0193 04 AD 04
```
```
07030000000b019304ad04
```

**收：** `status=byte[8]==0` 成功；酬載三個 big-endian int32：

| 位移 | 欄位 |
|------|------|
| `[16:20]` | RegisteredCount 已註冊數 |
| `[20:24]` | AvailableCount 可用數 |
| `[24:28]` | MaxCapacity 上限 |

範例回應（2 人 / 可用 998 / 上限 1000，總長 30 = `0x1E`）：
```
09030000001e01930004aabbccddeeff00000002000003e6000003e89304
```

### 4-2. `0x06` 取得 UserID 清單

**送 (11 bytes)：**

```
07 03 0000000B 0193 06 AF 04
```
```
07030000000b019306af04
```

**收：**

| 位移 | 欄位 |
|------|------|
| `[16:20]` | Count 清單筆數 (int32 BE) |
| `[20:24]`, `[24:28]`, … | 每筆 UserID (uint32 BE) |

範例回應（2 筆：1001、1002）：
```
09030000001e01930006aabbccddeeff00000002000003e9000003ea9a04
```

### 4-3. `0x08` 讀取使用者資料

**送 (15 bytes)：** 酬載 = UserID (uint32 BE) 放在 `[9:13]`

```
07 03 0000000F 0193 08 000003E9 A1 04         (uid=1001)
```
```
07030000000f019308000003e9a104
```

**收：** `status=byte[8]==0` 成功。**依整包長度分兩種版面**
（卡機是否啟用員工編號 EmployeeID 而定）：

共同欄位：

| 位移 | 欄位 | 解碼 |
|------|------|------|
| `[16:20]` | UserID | uint32 BE |
| `[20:28]` | CardNo 卡號 | 8 bytes BE → 十進位 |

**版面 A — 長度 ≥ 98（含 EmployeeID）：**

| 位移 | 欄位 |
|------|------|
| `[28:38]` | EmployeeID（UTF-8, 去 NUL/空白） |
| `[38:69]` | UserName 姓名（UTF-8） |
| `[0x45]` | CheckExpire（==1） |
| `[0x46]`+2000, `[0x47]`, `[0x48]`, `[0x49]`, `[0x4A]` | 有效起 年/月/日/時/分 |
| `[0x4B]`+2000, `[0x4C]`, `[0x4D]`, `[0x4E]`, `[0x4F]` | 有效迄 年/月/日/時/分 |
| `[0x50]` | Enabled（==1） |
| `[0x51]` | UserType |
| `[0x52:0x56]` | Group01~04 |
| `[0x56]` | BypassTimeZoneLevel |
| `[0x57:0x5F]` | PersonalPassword（8 B 逐字元、去 NUL；"0"視為空） |
| `[0x5F:0x67]` | TimeZone1~8 |

**版面 B — 長度 == 96（無 EmployeeID）：**

| 位移 | 欄位 |
|------|------|
| `[28:59]` | UserName 姓名（UTF-8） |
| `[0x3B]` | CheckExpire |
| `[0x3C]`+2000, `[0x3D]`, `[0x3E]`, `[0x3F]`, `[0x40]` | 有效起 年/月/日/時/分 |
| `[0x41]`+2000, `[0x42]`, `[0x43]`, `[0x44]`, `[0x45]` | 有效迄 年/月/日/時/分 |
| `[0x46]` | Enabled |
| `[0x47]` | UserType |
| `[0x48:0x4C]` | Group01~04 |
| `[0x4C]` | BypassTimeZoneLevel |
| `[0x4D:0x55]` | PersonalPassword（8 B） |
| `[0x55:0x5D]` | TimeZone1~8 |

### 4-4. `0x50` KeepAlive（維持連線）

卡機每隔一段會送 `0x50`（`byte[9]==0x50`）。伺服器要回一個 `0x50`，
內容帶目前時間（會順便幫卡機對時）+ **軟體版本日期**。不回可能被卡機斷線。

**回覆 (64 bytes)：** 酬載從 `[9]` 起

| 位移 | 欄位 |
|------|------|
| `[9]` | 秒 |
| `[10]` | 分 |
| `[11]` | 時 |
| `[12]` | 星期（週日=0） |
| `[13]` | 月 |
| `[14]` | 日 |
| `[15]` | 年 − 2000 |
| `[19]` | 固定 `0x64` |
| `[20:24]` | 天氣/溫度/濕度/空氣（未啟用天氣則為 0） |
| **`[24]`** | **軟體版本 年 % 100** |
| **`[25]`** | **軟體版本 月** |
| **`[26]`** | **軟體版本 日** |
| **`[27]`** | 固定 `1` |

⚠️ **`[24:27]` 軟體版本日期是「卡機判定軟體是否支援」的依據**（對應
`Settings.SoftwareVersionDate` = `Somac.exe` 檔案日期的 `yyyyMMdd`）。
若送 `00-00-00`，卡機 LCD 會一直顯示 **「軟體不支援」**（但對時、收刷卡仍正常）。
填一個夠新的日期（如 `20240205`）即可消除。

範例（機號 403、時間隨當下、軟體版本 2024-02-05）：`… [24]=0x18(24) [25]=0x02 [26]=0x05 [27]=0x01 …`
```
0703000000400193501c240d0308131a000000640000000018020501...3704
```

### 4-5. `0x07` 寫入 / 更新使用者（下傳）

把一筆使用者資料寫進卡機。對應 `RegisterModifyUserDataRequest.GetByteData`。
**請求固定 96 bytes**，是讀取 `0x08` 的反向操作，欄位位移大致對稱。

**送 (96 bytes)：**

| 位移 | 欄位 | 編碼 |
|------|------|------|
| `[8]` | 命令碼 `0x07` | |
| `[9:13]` | UserID | uint32 BE |
| `[13]` | OverWrite | 1=覆寫既有資料、0=不覆寫 |
| `[14:22]` | CardNo 卡號 | 8 bytes BE（十進位卡號 → 大端整數，與讀取相同） |
| `[22:53]` | UserName 姓名 | UTF-8，補 `0x00`，31 bytes |
| `[53]` | CheckExpire | 1/0 是否檢查有效期 |
| `[54:59]` | 有效起 | 年%100, 月, 日, 時, 分 |
| `[59:64]` | 有效迄 | 年%100, 月, 日, 時, 分 |
| `[64]` | EnabledStatus | 1=啟用、0=停用 |
| `[65]` | UserType | |
| `[66:70]` | Group01~04 | 各 1 byte |
| `[70]` | BypassTimeZoneLevel | |
| `[71:79]` | PersonalPassword | ASCII，8 bytes（無密碼填 `0x00`） |
| `[79:87]` | TimeZone1~8 | 各 1 byte |
| `[87:94]` | 保留 | `0x00` |
| `[94]` | Checksum | |
| `[95]` | ETX `0x04` | |

> 年份寫的是 **西元年後兩位**（`year % 100`）；讀取時是 `byte + 2000`，兩者一致。

**收：** 卡機回一框，`byte[8]==0` 表示寫入成功（同讀取的結果碼判定）。

範例（機號 403、UserID 1001、卡號 3646021037、姓名 "ALICE"、
啟用、OverWrite、Group01=50，其餘預設）：
```
070300000060019307000003e90100000000d951ddad414c494345000000000000000000000000000000000000000000000000000000000000000000000000000100320000000000000000000000000000000000000000000000000000003704
```
拆解：`07 03 00000060 0193 07` ｜ `000003E9`(uid) `01`(overwrite)
`00000000D951DDAD`(卡號=3646021037) ｜ `414C494345`("ALICE")+補0 … `01`(enabled@64)
`00`(type) `32000000`(groups=50,0,0,0) … `37`(checksum) `04`(ETX)。

> 其它機型 / 功能有變體：`GetBytesDataWithEmployeeID`（含員工編號，較長）、
> `GetBytesDataOfAC` / `GetBytesDataOfTA`、`GetBytesDataLiftV3`（電梯）…
> 由 `SendingQueue.ToSend` 依 ModelType 自動選用。上面是基本 AC 版面（96 bytes）。

#### 4-5b. `GetBytesDataWithEmployeeID` 版面（105 bytes）

含員工編號的機型要用這個版面：`CardNo` 後面多一個 **10-byte EmployeeID**，
**`UserName` 以後的每個欄位都往後移 10 bytes**。位移由讀取 `0x08` 的「含
EmployeeID 版面」反推（寫入位移 = 讀取位移 − 6）。

| 位移 | 欄位 | 對應基本版面 |
|------|------|--------------|
| `[9:13]` / `[13]` / `[14:22]` | UserID / OverWrite / CardNo | 同上，不變 |
| `[22:32]` | **EmployeeID** | 基本版面沒有 |
| `[32:63]` | UserName | `[22:53]` |
| `[63]` | CheckExpire | `[53]` |
| `[64:69]` / `[69:74]` | 有效起 / 有效迄 | `[54:59]` / `[59:64]` |
| `[74]` | EnabledStatus | `[64]` |
| `[75]` | UserType | `[65]` |
| `[76:80]` | Group01~04 | `[66:70]` |
| `[80]` | BypassTimeZoneLevel | `[70]` |
| `[81:89]` | PersonalPassword | `[71:79]` |
| `[89:97]` | TimeZone1~8 | `[79:87]` |
| `[97:104]` | 保留 | `[87:94]` |
| `[103]` / `[104]` | Checksum / ETX | `[94]` / `[95]` |

> ⚠️ **用錯版面卡機照樣回結果碼 0（假成功）**，但 UserName 之後全部錯位：姓名會
> 掉進 EmployeeID 欄、EnabledStatus 落在有效期區塊 → 寫進去的人永遠是「停用」、
> 群組全 0。判斷方法：先讀一次 `0x08`，**回應長度 ≥ 98**（有 EmployeeID 欄）就
> 要用這個版面。`semac_save_users.py --layout auto` 就是這樣自動判斷的。

**下傳整份名單**：沒有「一次傳整批」的命令，就是**對每個使用者送一包 `0x07`**、
逐筆寫入（Somac 的 `AsyncDownloadPersonControl` 就是這樣一筆一筆下傳）。每包之間
一樣要回覆卡機的 keepalive、等每包的成功回應再送下一包。

### 4-6. `0x01` / `0x02` 刪除使用者

- **`0x01` 刪一人 (15 bytes)：** 與 `0x08` 讀取請求同格式，只是命令碼不同：
  `[8]=0x01`、`[9:13]=UserID (uint32 BE)`、`[13]=checksum`、`[14]=ETX`。
- **`0x02` 刪全部 (11 bytes)：** 無酬載，同 `0x04`/`0x06` 的通用請求，`[8]=0x02`。

### 4-7. `0x51` 即時刷卡紀錄（卡機主動上傳）

有人刷卡時，卡機**主動**把紀錄推上來（不是回應我方的請求）。因此接收端要在
socket 收框迴圈裡，看到 `byte[9] == 0x51` 就當作一筆（或多筆）刷卡紀錄處理。
對應 `GetEntity.GetRealtimeTransactionEntity`。

**如何接收：** 就在原本的收框迴圈裡分辨命令碼（`byte[9]`）：

- `0x50` → keepalive，回覆一個 `0x50`（見 4-4，順便幫卡機對時）
- `0x51` → 即時刷卡 → 解析（見下）
- 其它 → 我方指令的回應

> 即時刷卡**不需回 ACK**，持續回覆 keepalive 維持連線即可。

⚠️ **`0x51` 與 `0x59` 版面不同**（用錯會整包錯位、時間變亂碼）：
> - `0x51` RealtimeTransaction → `GetRealtimeTransactionEntity`：**Count 是 1 byte**、record 由 `[17]` 起、**LogIndex 在最前面**。
> - `0x59` OffLineLogTransaction → `GetDoorLogEntity`：Count 是 `int32 [16:20]`、record 由 `[20]` 起、時間在最前面、LogIndex 在中間。

以下是 **`0x51`** 的版面。

**訊框結構：**

```
[8]      Status（0=正常）
[9]      0x51
[10:16]  卡機 MAC
[16]     Count  紀錄筆數（單一 byte）    ← 即時通常為 1
[17:]    Count 筆定長 record
[len-2]  Checksum
[len-1]  ETX
```

**record 長度（stride）**：每筆 20 或 32 bytes，由整包長度反推
（`len == Count*stride + 19`）；含卡號的是 32 bytes。
第 k 筆（k 由 0 起）record 起點 `r = 17 + stride×k`，欄位（相對 `r`）：

| 相對位移 | 欄位 | 解碼 |
|------|------|------|
| `[r+0:r+4]` | LogIndex 紀錄序號 | int32 BE |
| `[r+4]` | 秒 | EntryDate |
| `[r+5]` | 分 | |
| `[r+6]` | 時 | |
| `[r+7]` | 日 | |
| `[r+8]` | 月 | |
| `[r+9]` | 年 − 2000 | |
| `[r+10]` | InOutIndication 進出別 | 見下方代碼 |
| `[r+11]` | VerificationSource 驗證方式 | 見下方代碼 |
| `[r+12]` | EventAlarmCode 事件/警報碼 | 0=正常，其餘為事件碼 |
| `[r+13]` | DoorNo 門號 | |
| `[r+14:r+18]` | UserID | uint32 BE |
| `[r+18:r+26]` | CardNo 卡號 | 8 bytes BE →十進位（僅 32-byte record） |
| `[r+26:r+28]` | FunctionKey 功能鍵 | uint16 BE，見下方代碼 |
| `[r+28]` | RelayType 繼電器 | |
| `[r+29:r+31]` | Temperature 體溫 | 兩 byte（整數.小數，如 36.5；無測溫機種為 0.0） |
| `[r+31]` | UserType 使用者型別 | |

> 以上 `[r+18]` 之後（卡號起）僅 **32-byte record** 才有。20-byte record 到 `[r+18]` 為止。

**InOutIndication 代碼**（`Define.GetInOutIndicationString`）：

| 值 | 意義 |
|----|------|
| `1` / `2` | 進 / 出（一般狀態 Normal） |
| `33` / `34` | 進 / 出（Bypass ON） |
| `49` / `50` | 進 / 出（Bypass OFF） |
| 其它 | 開鎖時段等狀態；未知則顯示 `Code:N` |

**VerificationSource 代碼**（`Define.GetVerificationSourceString`）：

| 值 | 意義 | | 值 | 意義 |
|----|------|---|----|------|
| `0` | None | | `10` | Fingerprint 指紋 |
| `1` | Card 卡片 | | `11` | Card + Fingerprint |
| `2` | CommonPassword | | `64` | Face 人臉 |
| `4` | Personal Password | | `65` | Card + Face |
| `5` | Card + PersonalPassword | | `128` | Vein Finger 指靜脈 |
| `8` | Admin Password | | `99` | QRCode |

（完整對照見 `Define.GetVerificationSourceString`；未知值顯示 `Code:N`。）

**EventAlarmCode 代碼**（`Define.GetEventAlarmCodeString`，代碼 = 索引；常見值）：

| 值 | 意義 | | 值 | 意義 |
|----|------|---|----|------|
| `0` | None（正常） | | `9` | Expired User 已過期 |
| `6` | Unauthorized User 未授權 | | `10` | Anti Pass Back Violation |
| `7` | Unregistered User 未註冊卡 | | `15` | Exit Button Pressed 按鈕開門 |
| `8` | Deactivated User 已停用 | | `17` | Duress Alarm 脅迫 |

（完整 0~72 對照見 `Define.GetEventAlarmCodeString`；未知值顯示 `Code:N`。）

**FunctionKey 代碼**（`Define.GetFunctionKeyString`）：
`0`=None、`1`=F1、`101`=F2、`201`=F3、`301`=F4（`100/200/300/400` 為 F1+~F4+）。

**範例**（1 筆：LogIndex 100、UserID 2719、卡號 3646021037、門1、進、刷卡、
2026-01-04 09:09:37，32-byte record，總長 51）：
```
09030000003301930051aabbccddeeff010000006425090904011a0101000100000a9f00000000d951ddad0000000000003a04
```
拆解：`…0051`(cmd) ｜ `aabbccddeeff`(MAC) ｜ `01`(count=1，單 byte) ｜
record 由 `[17]` 起：`00000064`(LogIndex=100) `25 09 09 04 01 1a`(秒37 分9 時9 日4 月1 年26)
`01`(進) `01`(刷卡) `00`(事件) `01`(門1) `00000a9f`(UserID=2719)
`00000000d951ddad`(卡號=3646021037) … ｜ `3a`(checksum) `04`。

---

## 5. 讀取全部使用者的流程

```
1. (server) 監聽，等卡機連入
2. (卡機→server) 送 keepalive 0x50 → server 記下 TerminalID(byte[6:8])、回 0x50
3. (server→卡機) 0x04           → 取得已註冊人數（可選，做為總量）
4. (server→卡機) 0x06           → 取得 UserID 清單 [uid, ...]
5. 對每個 uid：
   (server→卡機) 0x08 + uid     → 回應解析出該使用者完整資料
6. 過程中遇到卡機送來的 0x50 就回覆、遇到即時刷卡(0x51)等推播就略過
```

判斷回應是否為「我這次指令的答案」：比對 **`byte[9] == 送出的命令碼`**，
且 **`byte[8] == 0`（成功）**。

---

## 6. Checksum 範例

`sum(frame[0 : len-2]) & 0xFF`：

- `07 03 0000000B 0193 04` → 0x07+0x03+0x00+0x00+0x00+0x0B+0x01+0x93+0x04 = `0xAD` ✓

---

## 7. 注意

- 以上假設卡機**未啟用**傳輸加密（AES）、TLS、連線密碼（Terminal Passcode）。
  若有啟用，酬載會是密文，需對應金鑰。
- `byte[8]` 語意：**請求**是命令碼、**回應**是結果碼（0=成功）。務必分清楚。
