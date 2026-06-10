# 🌐 SNMP 網路拓樸自動發現與 NetFlow/sFlow 流量數據分析

本專案是一套整合網路遙測（Telemetry）、自動拓樸發現、組態管理（NCM）與網路通訊軌跡深層檢索的企業級網路管理平台。生產環境採用 **Waitress** 作為 WSGI 伺服器，配置多執行緒並行架構。系統底層透過非同步 SNMP 探測技術、LLDP 鄰居發現演算法與 NetFlow/sFlow 異步收集鏈路，實現實體網路拓樸自動解構、硬碟空間永續循環與秒級資安事件追溯稽核。

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![Flask](https://img.shields.io/badge/Framework-Flask-black.svg)
![InfluxDB](https://img.shields.io/badge/Database-InfluxDB%20V2-purple.svg)
![Telegraf](https://img.shields.io/badge/Agent-Telegraf-orange.svg)
![Bootstrap](https://img.shields.io/badge/UI-Bootstrap%205-563D7C.svg)

---

## 🏗️ 系統運作環境與架構概述

平台拋棄傳統 Web 框架內建之單執行緒開發用伺服器，於生產環境全面掛載 **Waitress** 伺服器引擎，配置 12 個獨立並行執行緒（`threads=12`）常駐監聽 `Port 5000`。

本系統採行收集、儲存、分析、呈現完全分離之鬆耦合架構：
* **網路遙測模組**：底層採用 Python `pysnmp` 原生非同步非阻塞（`asyncio`）架構發送設備探測；組態管理（NCM）部分則透過 `paramiko` 建立 Socket 管道，以常態化線程池（固定 8 台設備並發限制）執行 CLI 組態自動化提取。
* **流量採集引擎**：背景常駐 `Telegraf` 代理程式監聽 `UDP 2055` 連接埠，進行 NetFlow v9 / sFlow 標準化採集，並設定高吞吐量快取池（Batch Size 10,000）大批量倒進 InfluxDB 時序資料庫。

---

## 🗄️ 多庫分流與分層儲存架構 (Database Infrastructure)

為保障高並發寫入時的資料完整性並防止硬碟空間無限制膨脹，系統捨棄單一巨大資料庫，全面採用**「多庫分流 + 時間序列分層儲存（Multi-DB Tiered Storage）」**架構。所有 SQLite 資料庫連線均硬性啟用 `WAL (Write-Ahead Logging)` 模式，並透過跨執行緒排他鎖（`DB_LOCKS`）實作安全併發存取。

### 1. 靜態配置與組態管理資料庫
* **`config.db` (靜態設定庫)**：儲存設備資產、RBAC 帳號權限、全域系統變數、萬國通訊埠標準維運字典，以及拓樸圖固定座標與視角記憶槽位。
* **`bkpswcfg.db` (NCM 組態庫)**：包含 `config_history` 表格，限制每個 IP 在歷史紀錄中僅滾動式保留最新 3 次的備份快照（版本索引序號為 0、1、2），文字與二進位組態均採安全 Base64 格式編碼儲存以防文字變形。

### 2. 遙測效能歷史資料庫 (時序分層)
* **`telemetry_hot.db` (熱庫 - 30 日內)**：儲存每輪常態輪詢寫入之原始介面流量計數、CPU 負載、記憶體佔用與硬體溫度指標。
* **`telemetry_warm.db` (溫庫 - 1 至 6 個月)**：定期將超過 30 天的熱數據，經由資料生命週期引擎執行降採樣（Data Downsampling）均值聚合演算法後，移往此庫搬移封存。
* **`telemetry_cold.db` (冷庫 - 7 個月至 3 年)**：封存經二次壓縮之極低密度長期維運與 SLA 分析數據。

### 3. 安全稽核日誌資料庫 (軌跡追蹤分層)
* **`audit_hot.db` (熱庫 - 30 日內)**：記錄使用者操作、身分登入、資安攔截事件與系統底層警報日誌。
* **`audit_warm.db` (溫庫 - 1 至 6 個月)**：存放歷史稽核紀錄。
* **`audit_cold.db` (冷庫 - 7 個月至 3 年)**：長期歸檔保存之資安稽核軌跡，滿足合規性審計需求。

---

## ⚙️ 六大背景守護行程 (Background Daemons)

伺服器初始化啟動時，會於背景同步拉起 6 個常駐型背景守護執行緒（Daemon Threads）分離運作：

| 守護行程名稱 | 輪詢週期 | 核心運作邏輯與防禦機制 |
| --- | --- | --- |
| `traffic_polling_worker` | 自訂間隔 | 遍歷設備清單，非同步拉取介面流量與效能指標。同步抓取國際標準之 `ifOperStatus` 與 `ifAdminStatus` 揉入記憶體快取，確保前端無須執行完整掃描即可獲得實體孔位連線狀態。 |
| `topology_scan_worker` | 排程觸發 | 常態性對全網設備執行深度 SNMP Walk，讀取標準 `LLDP-MIB` 與交換器核心 `dot1dTpFdbTable`（MAC 轉發學習表），自動更新與繪製全網骨幹與接入層之實體連線幾何關係。 |
| `data_retention_worker` | 24 小時 | 自動啟動資料生命週期管理。將熱庫中超過 30 天的資料經由Flux Task 降維壓縮後往溫庫搬移，搬移完畢自動對檔案執行 `VACUUM` 實體釋放硬碟空間。 |
| `ntp_sync_worker` | 定期執行 | 依據設定之 NTP 伺服器位址，定期對外部時間源進行自動校時，保障系統所有時間戳記與稽核日誌具備時序法律效力。 |
| `snmp_trap_receiver_worker` | 即時監聽 | 背景綁定 `UDP 162` 埠。套用 1.0 秒超時機制以動態檢查 Web 前台傳遞之持久化持久化控制開關。**內建網孔震盪保護演算法**：當特定網孔發生 `LinkDown` 時實施 60 秒冷卻靜音，`LinkUp` 則無視冷卻即時推播，重置計時。 |
| `auto_backup_worker` | 每日排程 | NCM 排程自動備份守護行程。一旦抵達設定點，即派發 **`max_workers=8`（固定 8 台設備並發限制線程池）**，同時登入 8 台設備提取組態，在極短時間內完成全網備份。 |

---

## ✨ 核心前端功能與實作原理

### 1. 🗺️ 拓樸版面記憶與「上帝視角」功能
* **網孔線路自動生成**：系統巡邏設備之 LLDP 鄰居表，自動拉回遠端交換器之 Chassis ID、Port ID 與設備名稱，無痛建立全網骨幹 Mesh 連線。
* **版面固定插槽 (Slot 1~3)**：提供 3 組實體記憶插槽。除了能永久保存每台設備在畫布上自訂挪動後的 X/Y 軸幾何座標，更**具備完整的「上帝視角 (Viewport Status) 記憶功能」**。系統會自動將當前畫布的平移位移量（Translation Coordinates）與滑鼠滾輪縮放比例（Zoom Level）轉為 JSON 字串存入 `config.db` 的靜態設定庫。當網管人員切換不同版面槽位時，畫布會自動平滑移動至當時儲存的全局縱覽視角。

### 2. 🔍 雙棧流量檢索與智慧模糊尋址
* **全域時間排序修正**：為解決 InfluxDB 時序資料庫因 Tag 標籤自動分表（Table Grouping）導致 Python 迴圈串接後在前端產生時間錯亂與跳躍的痛點。後端在 InfluxDB 回傳結果後，強制於 Python 記憶體進行全域時間戳（Timestamp）降冪排序，確保流量明細由新到舊工整對齊。
* **智慧局部搜尋引擎 (Regex Engine)**：
  * **IPv4 後綴模糊比對**：輸入末兩碼（如 `2.3`），後端自動換算為 InfluxDB Flux 正則語法 `/(^|\.)2\.3$/`，精確撈出所有結尾為 `.2.3` 的紀錄。
  * **IPv6 前綴模糊比對**：輸入前段區塊（如 `2001:288`），後端自動換算為 `^2001:288` 正規表達式篩選，並原生支援 IPv6 鏈路本地（Link-Local `fe80::`）、多播（Multicast `ff02::`）與自訂 `/48` 大網段之智慧二進位字串遮罩比對。
* **自主感知健康探測防呆**：前台網頁在載入瞬間即非同步探測 InfluxDB 官方 `/health` HTTP 端點與作業系統 `telegraf.exe` 進程。一旦發現大數據底層組件當機，網頁會立即跳出阻斷式警告，並**實體物理鎖死**前台「執行、重置、上方三大流量卡片」等全數使用者操作按鈕。

### 3. 🎨 獨立彈出式統計圖表與深淺主題記憶
* **無頁面跳動彈窗**：將 Chart.js 流量統計圖表全面封裝於獨立的彈出式 Modal 中，防止圖表內嵌於網頁時因忽隱忽現造成排版上下跳動。折線圖強制開啟精準數據原點（Data Points）並明確標示 Y 軸為 MB 單位。
* **智慧反轉對比切換**：純 CSS 變數驅動之一鍵深/淺色模式切換，可完美白化/黑化表格、選單與彈窗。當主題切換時，彈出視窗內圖表的背景格線、標題文字、甜甜圈圖縫隙與右上角 X 關閉按鈕，均會智慧進行黑白對比反轉。

---

## ⚙️ 安裝建置與生產部署指南

本系統已將全數 HTTP API 及全域請求勾子（Request Hooks）從 `app.py` 移出，集中配置於 `routes.py` 的 `main_bp` 藍圖中。

### 1. 自訂 InfluxDB V2 大數據路徑與配置
1. 將下載的 InfluxDB V2 解壓縮至 `D:\ops_tools\influxdb\`。在 D 槽建立高速存取目錄：`D:\InfluxDB_Data\`。
2. 在 `influxd.exe` 同級目錄下建立 **`config.toml`**，強制將Bolt與Engine指定至 D 槽，撐大快取快照並限制並發保護 CPU：
   ```toml
   bolt-path = "D:\\InfluxDB_Data\\influxd.bolt"
   engine-path = "D:\\InfluxDB_Data\\engine"
   storage-wal-fsync-delay = "50ms"
   storage-cache-snapshot-memory-size = "100m"
   query-concurrency = 20

```

3. 以管理員權限打開 PowerShell，綁定環境變數並註冊背景服務：
```powershell
[System.Environment]::SetEnvironmentVariable('INFLUXD_CONFIG_PATH', 'D:\ops_tools\influxdb\config.toml', 'Machine')
nssm install InfluxDB "D:\ops_tools\influxdb\influxd.exe"
net start InfluxDB

```



### 2. 佈署 Telegraf 流量採集器

1. 解壓縮 Telegraf 至 `D:\ops_tools\telegraf\`，修改 `telegraf.conf` 以調大緩衝池防止海量封包丟包，放寬寫入硬碟頻率：
```toml
[agent]
  interval = "10s"
  metric_batch_size = 10000       # 加大單次批次寫入量
  metric_buffer_limit = 100000    # 擴充記憶體緩衝池
  flush_interval = "30s"          # 放寬寫入頻率，給予時序庫消化時間
  flush_jitter = "5s"

[[outputs.influxdb_v2]]
  urls = ["[http://127.0.0.1:8086](http://127.0.0.1:8086)"]
  token = "您的_INFLUXDB_安全防護_TOKEN"
  organization = "您的_ORGANIZATION_NAME"
  bucket = "netflow_db"

[[inputs.netflow]]
  listen = "udp://:2055"
  protocol = "netflow_v9"

```


2. 啟動並常駐服務：
```powershell
.\telegraf.exe --service install --config .\telegraf.conf
net start telegraf

```



### 3. 掛載 Waitress 生產級伺服器

1. 安裝 Python 3.9+ 生產相依套件清單：
```bash
pip install flask waitress influxdb-client pysnmp paramiko

```


2. 本系統之 `app.py` 內部已預先封裝好 Waitress 執行緒池配置。直接執行啟動器，系統即會自動調用多執行緒引擎常駐服務：
```bash
python app.py

```



---

## 🛠️ 維運現場調試特殊技巧

### 1. InfluxDB 終端機日誌時區即時校正

由於 InfluxDB 官方規定主程式在 Console 印出的 Console Log 一律固定為 UTC 時間（帶有 `Z` 尾綴）。手動關閉背景服務進行現場除錯時，請改在 PowerShell 中透過以下**正則表達式串流管道腳本**啟動。它會在記憶體中即時攔截時間戳並自動加 8 小時，將畫面上的日誌完美轉換為台灣在地時間，並保留微秒精確度：

```powershell
cd D:\ops_tools\influxdb\
.\influxd.exe 2>&1 | ForEach-Object {
    if ($_ -match '(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)') {
        $utcTime = [datetime]::Parse($Matches[1])
        $localTime = $utcTime.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss.ffffff")
        $_ -replace $Matches[1], $localTime
    } else { $_ }
}

```

### 2. Telegraf 與開埠狀態查驗

若網頁出現健康檢查告警，請在 CMD 或 PowerShell 輸入以下指令，確認本地 `UDP 2055` 連接埠是否有成功被 Telegraf 行程霸據監聽，確保交換器的 NetFlow 封包能正常饋入：

```powershell
netstat -ano | findstr 2055
# 預期輸出：UDP    0.0.0.0:2055    *:* [Telegraf的背景PID行程代碼]

```

---

## 📄 授權條款 (License)

本專案核心架構代碼採用 **[MIT License](https://opensource.org/licenses/MIT)** 開源授權協議釋出。您可以自由地在商業或非商業環境中重構、修改或整合本程式碼，唯必須在複本中保留原作者之版權聲明。

```

```
