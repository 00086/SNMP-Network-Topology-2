import os
import csv
import sqlite3
import threading
import json
from utils import log_info, is_valid_ipv4, safe_int
from flask import has_request_context, session  # 🌟 新增這行：讓資料庫能偷看瀏覽器的 Session

# 🛡️ 宣告全域常駐連線，確保 WAL/SHM 檔永遠不被刪除
_KEEP_ALIVE_CONNS = []

# ==========================================
# 📊 InfluxDB v2 時序流量資料庫配置
# ==========================================
INFLUXDB_URL = "http://192.50.1.41:8086"
INFLUXDB_TOKEN = "KLZQksXn_0WmjO0awXYcTMtVhkGiXVmz3tGOZ1tyqJwPVx0nAOfqXO9j2qOmwDhNntBHZynLxY0ot7aJv8fqWQ=="  # 🔴 請替換成您複製的實際 Token
INFLUXDB_ORG = "SNMP_Topology"                  # 🔴 請替換成您設定的 Org 名稱
INFLUXDB_BUCKET = "flow_data"

# ==========================================
# 🗄️ 1. ISMS 實體分層資料庫路徑配置 (完全對稱架構)
# ==========================================
DB_CONFIG = 'config.db'           # 靜態配置庫 (設備、拓樸座標、連線、系統設定)

DB_HOT = 'telemetry_hot.db'        # 時序熱數據 (最近 30 天，1分鐘1筆)
DB_WARM = 'telemetry_warm.db'      # 時序溫數據 (1~6 個月，10分鐘1筆)
DB_COLD = 'telemetry_cold.db'      # 時序冷數據 (7個月~3年, 1小時1筆)

DB_AUDIT_HOT = 'audit_hot.db'      # 💡 稽核日誌熱庫 (最近 30 天，原汁原味)
DB_AUDIT_WARM = 'audit_warm.db'    # 💡 稽核日誌溫庫 (1~6 個月，原汁原味)
DB_AUDIT_COLD = 'audit_cold.db'    # 💡 稽核日誌冷庫 (7個月~3年, 原汁原味)

# 👇 🌟 新增這一行：定義總部大腦的資料庫檔案名稱
DB_HQ_MASTER = 'hq_master.db'      # 🌟 總部專用：全域戰情大腦與註冊表

# 🔒 各資料庫獨立的執行緒鎖，徹底消滅 SQLite Database Locked 死鎖衝突
# 🌟 關鍵修正：將 Lock() 升級為 RLock() (可重入鎖)，完美解決同一 API 請求重複索取鑰匙導致的 Deadlock 轉圈問題！
DB_LOCKS = {
    'config': threading.RLock(),
    'hot': threading.RLock(),
    'warm': threading.RLock(),
    'cold': threading.RLock(),
    'audit_hot': threading.RLock(),  # 💡 日誌熱鎖
    'audit_warm': threading.RLock(), # 💡 日誌溫鎖
    'audit_cold': threading.RLock(), # 💡 日誌冷鎖
    'hq_master': threading.RLock()   # 🌟 總部大腦鎖
}

# ==========================================
# 🧠 2. 方案 4：全記憶體變數快取層 (Python RAM Cache)
# ==========================================
_DEVICE_CACHE = []            # 存放全網設備的常駐記憶體陣列
_CACHE_LOCK = threading.Lock() # 快取專屬執行緒鎖

# 🌟 全新擴充：翻譯字典全記憶體高速快取層
_TRANSLATION_CACHE = {}         # 格式: { "eng_text": "zh_text" }
_TRANSLATION_LOCK = threading.Lock()

# ========================================================
# ⚙️ 核心資料庫連線工廠 (內建 SQLite 性能優化)
# ========================================================
def get_db(db_name='config', bypass_shard=False):
    db_path = DB_CONFIG
    if db_name == 'hot': db_path = DB_HOT
    elif db_name == 'warm': db_path = DB_WARM
    elif db_name == 'cold': db_path = DB_COLD
    elif db_name == 'audit_hot': db_path = DB_AUDIT_HOT
    elif db_name == 'audit_warm': db_path = DB_AUDIT_WARM
    elif db_name == 'audit_cold': db_path = DB_AUDIT_COLD
    elif db_name == 'hq_master': db_path = DB_HQ_MASTER # 🌟 總部專用路徑

    # 👇 🌟 魔法攔截器：跨站點切換 (Site Switcher)
    is_sharded = False
    try:
        # 🌟 核心防護：只要 bypass_shard=True，就絕對不分流，強制讀取主庫！
        if not bypass_shard and has_request_context() and db_name in ['config', 'hot', 'warm', 'cold']:
            target_site = session.get('target_site_code')
            if target_site:
                # 瞬間將連線導向該分區專屬的資料庫！
                db_path = os.path.join('hq_sites', f'site_{target_site}.db')
                is_sharded = True
    except Exception as e:
        pass
    # 👆 攔截器結束

    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    
    # ⚡ 啟動預寫式日誌模式，允許高並發讀寫並行
    conn.execute('PRAGMA journal_mode=WAL;')

    # 👇 🌟 總部防呆機制：當總部調閱分區資料庫時，自動補齊 UI 需要的空表與欄位，防止報錯
    if is_sharded and db_name == 'config':
        conn.execute('CREATE TABLE IF NOT EXISTS edges (id TEXT PRIMARY KEY, source TEXT, target TEXT, speed INTEGER, OID_info TEXT, port_info TEXT, from_port TEXT, to_port TEXT)')
        conn.execute('CREATE TABLE IF NOT EXISTS layout_slots (slot_id INTEGER, ip TEXT, x REAL, y REAL, PRIMARY KEY (slot_id, ip))')
        conn.execute('CREATE TABLE IF NOT EXISTS system_settings (key TEXT PRIMARY KEY, value TEXT)')
        conn.execute('CREATE TABLE IF NOT EXISTS device_ports (ip TEXT, port_idx TEXT, port_name TEXT, speed INTEGER, PRIMARY KEY (ip, port_idx))')
        
        # 🌟 動態修復：為精簡版的分區庫補齊前端繪圖需要的欄位
        try: conn.execute("ALTER TABLE devices ADD COLUMN visible INTEGER DEFAULT 1")
        except: pass
        try: conn.execute("ALTER TABLE devices ADD COLUMN x REAL")
        except: pass
        try: conn.execute("ALTER TABLE devices ADD COLUMN y REAL")
        except: pass
        
        # 動態修復：為精簡版的網孔表補齊快取需要的欄位
        try: conn.execute("ALTER TABLE device_ports ADD COLUMN memorized_ips TEXT DEFAULT ''")
        except: pass

    # 🚀 根據庫的屬性分配精確的 SQLite 內部 Page Cache
    if db_name in ['hot', 'audit_hot']:
        conn.execute('PRAGMA cache_size=-500000;') # 配置 500MB 記憶體緩衝池
        conn.execute('PRAGMA synchronous=NORMAL;')  # 放寬磁碟寫入同步
        conn.execute('PRAGMA temp_store=MEMORY;')   # 🌟 強固微調：暫存表完全鎖在記憶體
        conn.execute('PRAGMA wal_autocheckpoint=10000;') # 🌟 新增：拉高寫入閾值至約 40MB，大幅降低硬碟 I/O
    elif db_name == 'config':
        conn.execute('PRAGMA cache_size=-20000;')  # 配置 20MB 記憶體常駐靜態庫
        conn.execute('PRAGMA synchronous=NORMAL;')
    elif db_name in ['warm', 'cold', 'audit_warm', 'audit_cold']:
        conn.execute('PRAGMA cache_size=-50000;')  # 歷史庫給予適當的快取
        conn.execute('PRAGMA synchronous=NORMAL;')
        
    return conn

# ==========================================
# 🏗️ 4. 資料庫與基礎表初始化架構
# ==========================================
def init_telemetry_db(conn, db_tier='hot'):
    """建置時序資料庫專用表與高效能複合索引 (支援動態降採樣欄位)"""
    conn.execute('''CREATE TABLE IF NOT EXISTS metrics_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        ip TEXT, cpu REAL, memory REAL, poe_w REAL DEFAULT 0.0, temp_c REAL DEFAULT 0.0,
        session_util REAL DEFAULT 0.0,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # 🌟 無痛升級：系統重啟時，自動幫舊庫補上 session_util 與 latency_ms 欄位
    try: conn.execute("ALTER TABLE metrics_history ADD COLUMN session_util REAL DEFAULT 0.0")
    except: pass
    try: conn.execute("ALTER TABLE metrics_history ADD COLUMN latency_ms REAL DEFAULT 0.0")
    except: pass
    
    # 🌟 無痛升級：系統重啟時，自動幫舊的熱/溫/冷庫補上 session_util 欄位
    try: conn.execute("ALTER TABLE metrics_history ADD COLUMN session_util REAL DEFAULT 0.0")
    except: pass
    
    conn.execute('CREATE INDEX IF NOT EXISTS idx_metrics_ip_ts ON metrics_history(ip, timestamp)')
    
    # 💡 判斷如果是熱庫，保持原始計數器 (in_bytes)
    if db_tier == 'hot':
        conn.execute('''CREATE TABLE IF NOT EXISTS traffic_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            ip TEXT, port_idx TEXT, in_bytes INTEGER, out_bytes INTEGER, 
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
    # 💡 如果是溫庫或冷庫，改為儲存已解算好的 BPS 平均值與峰值
    else:
        conn.execute('''CREATE TABLE IF NOT EXISTS traffic_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            ip TEXT, port_idx TEXT, timestamp DATETIME,
            avg_in_bps REAL, max_in_bps REAL, 
            avg_out_bps REAL, max_out_bps REAL
        )''')
        
    conn.execute('CREATE INDEX IF NOT EXISTS idx_traffic_ip_port ON traffic_history(ip, port_idx)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON traffic_history(timestamp)')
    
    # 💡 [效能修復] 新增時序資料專用「複合索引」，查詢特定 IP 的時間區間將從 2 秒縮短到 10 毫秒！
    conn.execute('CREATE INDEX IF NOT EXISTS idx_traffic_ip_ts ON traffic_history(ip, timestamp)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_traffic_ip_ts_port ON traffic_history(ip, timestamp, port_idx)')
    
    conn.commit()
    
def init_hq_master_db():
    """🌟 總部專用：初始化全域戰情大腦 (自動註冊表、排行榜與六都行政區)"""
    with DB_LOCKS['hq_master']:
        conn = get_db('hq_master')
        # 表1：分區心跳與註冊總表
        conn.execute('''CREATE TABLE IF NOT EXISTS global_sites (
            site_code TEXT PRIMARY KEY, site_name TEXT, district TEXT,
            status TEXT DEFAULT 'up', last_sync_time DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
        # 表2：全域 CPU 負載排行榜
        conn.execute('''CREATE TABLE IF NOT EXISTS global_top_cpu (
            site_code TEXT, ip TEXT, device_name TEXT, cpu_load REAL, mem_load REAL,
            PRIMARY KEY (site_code, ip)
        )''')
        
        # 👇 🌟 新增表3：六都行政區固定資料表 (供戰情大廳逐層鑽取使用)
        conn.execute('''CREATE TABLE IF NOT EXISTS city_districts (
            city_key TEXT, district_name TEXT, PRIMARY KEY (city_key, district_name)
        )''')
        
        # 檢查是否為空，若空則自動無痛匯入台灣六都全數行政區
        cnt = conn.execute("SELECT COUNT(*) FROM city_districts").fetchone()[0]
        if cnt == 0:
            districts_data = [
                ('TPE', '中正區'), ('TPE', '大同區'), ('TPE', '中山區'), ('TPE', '松山區'), ('TPE', '大安區'), ('TPE', '萬華區'), ('TPE', '信義區'), ('TPE', '士林區'), ('TPE', '北投區'), ('TPE', '內湖區'), ('TPE', '南港區'), ('TPE', '文山區'),
                ('NTPC', '板橋區'), ('NTPC', '三重區'), ('NTPC', '中和區'), ('NTPC', '永和區'), ('NTPC', '新莊區'), ('NTPC', '新店區'), ('NTPC', '樹林區'), ('NTPC', '鶯歌區'), ('NTPC', '三峽區'), ('NTPC', '淡水區'), ('NTPC', '汐止區'), ('NTPC', '瑞芳區'), ('NTPC', '土城區'), ('NTPC', '蘆洲區'), ('NTPC', '五股區'), ('NTPC', '泰山區'), ('NTPC', '林口區'), ('NTPC', '深坑區'), ('NTPC', '石碇區'), ('NTPC', '坪林區'), ('NTPC', '三芝區'), ('NTPC', '石門區'), ('NTPC', '八里區'), ('NTPC', '平溪區'), ('NTPC', '雙溪區'), ('NTPC', '貢寮區'), ('NTPC', '金山區'), ('NTPC', '萬里區'), ('NTPC', '烏來區'),
                ('TYC', '桃園區'), ('TYC', '中壢區'), ('TYC', '大溪區'), ('TYC', '楊梅區'), ('TYC', '蘆竹區'), ('TYC', '大園區'), ('TYC', '龜山區'), ('TYC', '八德區'), ('TYC', '龍潭區'), ('TYC', '平鎮區'), ('TYC', '新屋區'), ('TYC', '觀音區'), ('TYC', '復興區'),
                ('TC', '中區'), ('TC', '東區'), ('TC', '南區'), ('TC', '西區'), ('TC', '北區'), ('TC', '西屯區'), ('TC', '南屯區'), ('TC', '北屯區'), ('TC', '豐原區'), ('TC', '東勢區'), ('TC', '大甲區'), ('TC', '清水區'), ('TC', '沙鹿區'), ('TC', '梧棲區'), ('TC', '后里區'), ('TC', '神岡區'), ('TC', '潭子區'), ('TC', '大雅區'), ('TC', '新社區'), ('TC', '石岡區'), ('TC', '外埔區'), ('TC', '大安區'), ('TC', '烏日區'), ('TC', '大肚區'), ('TC', '龍井區'), ('TC', '霧峰區'), ('TC', '太平區'), ('TC', '大里區'), ('TC', '和平區'),
                ('TN', '新營區'), ('TN', '鹽水區'), ('TN', '白河區'), ('TN', '柳營區'), ('TN', '後壁區'), ('TN', '東山區'), ('TN', '麻豆區'), ('TN', '下營區'), ('TN', '六甲區'), ('TN', '官田區'), ('TN', '大內區'), ('TN', '佳里區'), ('TN', '學甲區'), ('TN', '西港區'), ('TN', '七股區'), ('TN', '將軍區'), ('TN', '北門區'), ('TN', '新化區'), ('TN', '善化區'), ('TN', '新市區'), ('TN', '安定區'), ('TN', '山上區'), ('TN', '玉井區'), ('TN', '楠西區'), ('TN', '南化區'), ('TN', '左鎮區'), ('TN', '仁德區'), ('TN', '歸仁區'), ('TN', '關廟區'), ('TN', '龍崎區'), ('TN', '永康區'), ('TN', '東區'), ('TN', '南區'), ('TN', '北區'), ('TN', '安南區'), ('TN', '安平區'), ('TN', '中西區'),
                ('KHH', '鹽埕區'), ('KHH', '鼓山區'), ('KHH', '左營區'), ('KHH', '楠梓區'), ('KHH', '三民區'), ('KHH', '新興區'), ('KHH', '前金區'), ('KHH', '苓雅區'), ('KHH', '前鎮區'), ('KHH', '旗津區'), ('KHH', '小港區'), ('KHH', '鳳山區'), ('KHH', '林園區'), ('KHH', '大寮區'), ('KHH', '大樹區'), ('KHH', '大社區'), ('KHH', '仁武區'), ('KHH', '鳥松區'), ('KHH', '岡山區'), ('KHH', '橋頭區'), ('KHH', '燕巢區'), ('KHH', '田寮區'), ('KHH', '阿蓮區'), ('KHH', '路竹區'), ('KHH', '湖內區'), ('KHH', '茄萣區'), ('KHH', '永安區'), ('KHH', '彌陀區'), ('KHH', '梓官區'), ('KHH', '旗山區'), ('KHH', '美濃區'), ('KHH', '六龜區'), ('KHH', '甲仙區'), ('KHH', '杉林區'), ('KHH', '內門區'), ('KHH', '茂林區'), ('KHH', '桃源區'), ('KHH', '那瑪夏區')
            ]
            conn.executemany("INSERT INTO city_districts (city_key, district_name) VALUES (?, ?)", districts_data)
        
        conn.commit()
        conn.close()

def init_db():
    """系統啟動核心：初始化所有實體 .db 檔案與資料表結構 (修正死鎖與閉庫衝突版)"""
    with DB_LOCKS['config']:
        conn = get_db('config')
        
        # 1. 設備主表建置
        conn.execute('''CREATE TABLE IF NOT EXISTS devices (
            ip TEXT PRIMARY KEY, name TEXT, level INTEGER, community TEXT, location TEXT, 
            visible INTEGER, type TEXT, brand TEXT, model TEXT, sys_descr TEXT, 
            x REAL, y REAL, status TEXT DEFAULT 'up', snmp_raw TEXT DEFAULT '{}', 
            is_poe INTEGER DEFAULT 0, poe_data TEXT DEFAULT '{}', 
            cpu_load REAL DEFAULT 0.0, mem_load REAL DEFAULT 0.0,
            has_sensor INTEGER DEFAULT 0
        )''')
        
        # 💡 自動補齊新欄位 (防呆相容舊庫)
        try: conn.execute("ALTER TABLE devices ADD COLUMN has_sensor INTEGER DEFAULT 0")
        except: pass
        try: conn.execute("ALTER TABLE devices ADD COLUMN ssh_user TEXT DEFAULT ''")
        except: pass
        try: conn.execute("ALTER TABLE devices ADD COLUMN ssh_pass TEXT DEFAULT ''")
        except: pass
        try: conn.execute("ALTER TABLE devices ADD COLUMN ssh_secret TEXT DEFAULT ''")
        except: pass
        try: conn.execute("ALTER TABLE devices ADD COLUMN cli_type TEXT DEFAULT ''")
        except: pass
        # 🌟 無痛升級：新增設定檔備份啟用開關 (預設 1 開啟)
        try: conn.execute("ALTER TABLE devices ADD COLUMN is_backup INTEGER DEFAULT 1")
        except: pass
        # 🌟 無痛升級：新增設備規格設定 (SNMP版本與網孔實體規格)
        try: conn.execute("ALTER TABLE devices ADD COLUMN snmp_version TEXT DEFAULT 'v2c'")
        except: pass
        try: conn.execute("ALTER TABLE devices ADD COLUMN port_specs TEXT DEFAULT '[]'")
        except: pass
        # 🌟 無痛升級：新增延遲記錄欄位
        try: conn.execute("ALTER TABLE devices ADD COLUMN latency_ms REAL DEFAULT 0.0")
        except: pass
        
        # 2. 基礎核心維運子表建置
        conn.execute('CREATE TABLE IF NOT EXISTS layout_slots (slot_id INTEGER, ip TEXT, x REAL, y REAL, PRIMARY KEY (slot_id, ip))')
        conn.execute('CREATE TABLE IF NOT EXISTS edges (id TEXT PRIMARY KEY, source TEXT, target TEXT, speed INTEGER, OID_info TEXT, port_info TEXT, from_port TEXT, to_port TEXT)')
        conn.execute('CREATE TABLE IF NOT EXISTS anomaly_daily_stats (date TEXT PRIMARY KEY, runs INTEGER DEFAULT 0)')
        conn.execute('CREATE TABLE IF NOT EXISTS system_settings (key TEXT PRIMARY KEY, value TEXT)')
        conn.execute('''CREATE TABLE IF NOT EXISTS manual_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT, node_a TEXT, port_a TEXT, node_b TEXT, port_b TEXT, speed INTEGER DEFAULT 1000
        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS device_ports (
            ip TEXT, port_idx TEXT, port_name TEXT, speed INTEGER, PRIMARY KEY (ip, port_idx)
        )''')
        
        # 💡 [無痛升級] 自動補齊網孔快取新欄位 (防呆相容舊庫)
        try: conn.execute("ALTER TABLE device_ports ADD COLUMN memorized_ips TEXT DEFAULT ''")
        except: pass
        try: conn.execute("ALTER TABLE device_ports ADD COLUMN is_manual_uplink INTEGER DEFAULT 0")
        except: pass
        # 🌟 新增：手動標註 MGMT 欄位自動無痛補齊
        try: conn.execute("ALTER TABLE device_ports ADD COLUMN is_manual_mgmt INTEGER DEFAULT 0")
        except: pass
        
        # 3. Ntfy / Polling 預設環境參數初始化防禦
        has_custom = conn.execute("SELECT COUNT(*) FROM system_settings WHERE key='ntfy_url' AND value != 'http://localhost:8080/your_topic'").fetchone()[0]
        if has_custom > 0:
            conn.execute("DELETE FROM system_settings WHERE key='ntfy_url' AND value = 'http://localhost:8080/your_topic'")
        else:
            check_url = conn.execute("SELECT COUNT(*) FROM system_settings WHERE key='ntfy_url'").fetchone()[0]
            if check_url == 0:
                conn.execute("INSERT INTO system_settings (key, value) VALUES ('ntfy_enabled', '0')")
                conn.execute("INSERT INTO system_settings (key, value) VALUES ('ntfy_url', 'http://localhost:8080/your_topic')")
        
        conn.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('polling_interval', '3')")
        conn.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('topo_scan_interval', '0')")
        
        # 🌟 無痛升級：新增機構分區基本資料 (預設空值)
        conn.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('site_district', '')")
        conn.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('site_code', '')")
        conn.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('site_name', '')")
        
        # 🌟 無痛升級：新增推播排程引擎配置
        conn.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('sync_topo_start', '01:00')")
        conn.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('sync_topo_interval', '24')")
        conn.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('sync_status_start', '00:00')")
        conn.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('sync_status_interval', '5')")
        
        # 🌟 無痛升級：新增系統運作視角參數 (預設為 local 單一分區)
        conn.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('hq_view_mode', 'local')")
        # 🌟 無痛升級：新增總部伺服器位址參數 (預設為空)
        conn.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('hq_server_url', '')")
        
        # 👇 🌟 新增：無痛升級總部連線認證碼 (預設為空)
        conn.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('hq_sync_secret', '')")

        # 4. RBAC 使用者權限管理表建置
        conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
            role TEXT NOT NULL, status INTEGER DEFAULT 1, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # 自動寫入預設 Admin 帳號 (密碼: admin)
        count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if count == 0:
            import hashlib, secrets
            salt = secrets.token_hex(8)
            key = hashlib.pbkdf2_hmac('sha256', 'admin'.encode('utf-8'), salt.encode('utf-8'), 100000)
            pwd = f"{salt}${key.hex()}"
            conn.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", ('admin', pwd, 'admin'))
            log_info("🔐 RBAC 系統初始化完成：已建立預設 admin 帳號 (密碼: admin)")

        # 5. 🌟 【修正移入】建置運維翻譯字典資料表 (Translation Dictionary)
        conn.execute('''
        CREATE TABLE IF NOT EXISTS translation_dictionary (
            id INTEGER PRIMARY KEY AUTOINCREMENT, eng_text TEXT UNIQUE NOT NULL, zh_text TEXT NOT NULL,
            category TEXT NOT NULL, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_trans_eng ON translation_dictionary(eng_text)')
        
        # 自動灌入繁體中文自訂本地種子字典
        dict_count = conn.execute("SELECT COUNT(*) FROM translation_dictionary").fetchone()[0]
        if dict_count == 0:
            seed_data = [
                # 🏙️ 臺北市行政區 (District)
                ("Beitou", "臺北市北投區", "行政區"), ("Shilin", "臺北市士林區", "行政區"), ("Datong", "臺北市大同區", "行政區"),
                ("Zhongshan", "臺北市中山區", "行政區"), ("Songshan", "臺北市松山區", "行政區"), ("Neihu", "臺北市內湖區", "行政區"),
                ("Wanhua", "臺北市萬華區", "行政區"), ("Zhongzheng", "臺北市中正區", "行政區"), ("Da'an", "臺北市大安區", "行政區"),
                ("Daan", "臺北市大安區", "行政區"), ("Xinyi", "臺北市信義區", "行政區"), ("Nangang", "臺北市南港區", "行政區"),
                ("Wenshan", "臺北市文山區", "行政區"),
                # 🏙️ 新北市行政區 (District)
                ("Banqiao", "新北市板橋區", "行政區"), ("Sanchong", "新北市三重區", "行政區"), ("Zhonghe", "新北市中和區", "行政區"),
                ("Chunghe", "新北市中和區", "行政區"), ("Yonghe", "新北市永和區", "行政區"), ("Xinzhuang", "新北市新莊區", "行政區"),
                ("Hsinchuang", "新北市新莊區", "行政區"), ("Xindian", "新北市新店區", "行政區"), ("Hsintien", "新北市新店區", "行政區"),
                ("Shulin", "新北市樹林區", "行政區"), ("Yingge", "新北市鶯歌區", "行政區"), ("Sanxia", "新北市三峽區", "行政區"),
                ("Tamsui", "新北市淡水區", "行政區"), ("Xizhi", "新北市汐止區", "行政區"), ("Hsichih", "新北市汐止區", "行政區"),
                ("Tucheng", "新北市土城區", "行政區"), ("Wugu", "新北市五股區", "行政區"), ("Taishan", "新北市泰山區", "行政區"),
                ("Linkou", "新北市林口區", "行政區"), ("Bali", "新北市八里區", "行政區"), ("Shenkeng", "新北市深坑區", "行政區"),
                # 🏙️ 桃園市行政區 (District)
                ("Taoyuan District", "桃園市桃園區", "行政區"), ("Zhongli", "桃園市中壢區", "行政區"), ("Chungli", "桃園市中壢區", "行政區"),
                ("Pingzhen", "桃園市平鎮區", "行政區"), ("Bade", "桃園市八德區", "行政區"), ("Yangmei", "桃園市楊梅區", "行政區"),
                ("Luzhu", "桃園市蘆竹區", "行政區"), ("Dayuan", "桃園市大園區", "行政區"), ("Guishan", "桃園市龜山區", "行政區"),
                ("Kueishan", "桃園市龜山區", "行政區"), ("Longtan", "桃園市龍潭區", "行政區"), ("Xinwu", "桃園市新屋區", "行政區"),
                ("Guanyin", "桃園市觀音區", "行政區"),
                # 🏙️ 臺中市行政區 (District)
                ("Xitun", "臺中市西屯區", "行政區"), ("Beitun", "臺中市北屯區", "行政區"), ("Nantun", "臺中市南屯區", "行政區"),
                ("Fengyuan", "臺中市豐原區", "行政區"), ("Dali", "臺中市大里區", "行政區"), ("Taiping", "臺中市太平區", "行政區"),
                ("Shalu", "臺中市沙鹿區", "行政區"), ("Wuri", "臺中市烏日區", "行政區"), ("Wufeng", "臺中市霧峰區", "行政區"),
                ("Daya", "臺中市大雅區", "行政區"), ("Tanzi", "臺中市潭子區", "行政區"), ("Dadu", "臺中市大肚區", "行政區"),
                ("Longjing", "臺中市龍井區", "行政區"),
                # 🏙️ 臺南市行政區 (District)
                ("Yongkang", "臺南市永康區", "行政區"), ("Anping", "臺南市安平區", "行政區"), ("Annan", "臺南市安南區", "行政區"),
                ("Xinying", "臺南市新營區", "行政區"), ("Shanhua", "臺南市善化區", "行政區"), ("Xinshi", "臺南市新市區", "行政區"),
                ("Rende", "臺南市仁德區", "行政區"), ("Guiren", "臺南市歸仁區", "行政區"),
                # 🏙️ 高雄市行政區 (District)
                ("Sanmin", "高雄市三民區", "行政區"), ("Zuoying", "高雄市左營區", "行政區"), ("Fengshan", "高雄市鳳山區", "行政區"),
                ("Nanzi", "高雄市楠梓區", "行政區"), ("Nanzih", "高雄市楠梓區", "行政區"), ("Lingya", "高雄市苓雅區", "行政區"),
                ("Gushan", "高雄市鼓山區", "行政區"), ("Xiaogang", "高雄市小港區", "行政區"), ("Qianzhen", "高雄市前鎮區", "行政區"),
                ("Renwu", "高雄市仁武區", "行政區"), ("Dashe", "高雄市大社區", "行政區"), ("Gangshan", "高雄市岡山區", "行政區"),
                ("Qiaotou", "高雄市橋頭區", "行政區"), ("Linyuan", "高雄市林園區", "行政區"), ("Daliao", "高雄市大寮區", "行政區"),
                ("Niaosong", "高雄市鳥松區", "行政區"),
                # 🔬 臺灣高頻率出現之科技產業/科學園區
                ("Hsinchu Science Park", "新竹科學園區", "科技園區"), ("Central Taiwan Science Park", "中部科學園區", "科技園區"),
                ("Southern Taiwan Science Park", "南部科學園區", "科技園區"), ("Neihu Technology Park", "內湖科技園區", "科技園區"),
                ("Nankang Software Park", "南港軟體園區", "科技園區"), ("Nangang Software Park", "南港軟體園區", "科技園區"),
                # 🗺️ 臺灣縣市級基礎宣告
                ("Taipei", "臺北市", "縣市級"), ("Taipei City", "臺北市", "縣市級"), ("New Taipei", "新北市", "縣市級"),
                ("New Taipei City", "新北市", "縣市級"), ("Taoyuan", "桃園市", "縣市級"), ("Taoyuan City", "桃園市", "縣市級"),
                ("Taichung", "臺中市", "縣市級"), ("Taichung City", "臺中市", "縣市級"), ("Tainan", "臺南市", "縣市級"),
                ("Tainan City", "臺南市", "縣市級"), ("Kaohsiung", "高雄市", "縣市級"), ("Kaohsiung City", "高雄市", "縣市級"),
                ("Keelung", "基隆市", "縣市級"), ("Keelung City", "基隆市", "縣市級"), ("Hsinchu", "新竹市", "縣市級"),
                ("Hsinchu City", "新竹市", "縣市級"), ("Hsinchu County", "新竹縣", "縣市級"), ("Miaoli", "苗栗縣", "縣市級"),
                ("Miaoli County", "苗栗縣", "縣市級"), ("Changhua", "彰化縣", "縣市級"), ("Chang-hua", "彰化縣", "縣市級"),
                ("Changhua County", "彰化縣", "縣市級"), ("Nantou", "南投縣", "縣市級"), ("Nantou County", "南投縣", "縣市級"),
                ("Yunlin", "雲林縣", "縣市級"), ("Yunlin County", "雲林縣", "縣市級"), ("Chiayi", "嘉義市", "縣市級"),
                ("Chiayi City", "嘉義市", "縣市級"), ("Chiayi County", "嘉義縣", "縣市級"), ("Pingtung", "屏東縣", "縣市級"),
                ("Pingtung County", "屏東縣", "縣市級"), ("Yilan", "宜蘭縣", "縣市級"), ("Yilan County", "宜蘭縣", "縣市級"),
                ("Hualien", "花蓮縣", "縣市級"), ("Hualien County", "花蓮縣", "縣市級"), ("Taitung", "臺東縣", "縣市級"),
                ("Taitung County", "臺東縣", "縣市級"), ("Penghu", "澎湖縣", "縣市級"), ("Penghu County", "澎湖縣", "縣市級"),
                ("Kinmen", "金門縣", "縣市級"), ("Kinmen County", "金門縣", "縣市級"), ("Lienchiang", "連江縣 (馬祖)", "縣市級"),
                ("Matsu", "馬祖", "縣市級"),
                # 🏢 臺灣主要核心電信與固網 (ISP)
                ("Chunghwa Telecom Co. Ltd.", "中華電信", "電信固網"), ("Chunghwa Telecom", "中華電信", "電信固網"),
                ("HiNet", "中華電信 HiNet", "電信固網"), ("Taiwan Fixed Network Co., Ltd.", "台灣固網 (台灣大哥大)", "電信固網"),
                ("Taiwan Fixed Network", "台灣固網", "電信固網"), ("Taiwan Mobile Co., Ltd.", "台灣大哥大", "電信固網"),
                ("Taiwan Mobile", "台灣大哥大", "電信固網"), ("FarEasTone Telecommunications Co., Ltd.", "遠傳電信", "電信固網"),
                ("FarEasTone", "遠傳電信", "電信固網"), ("Asia Pacific Telecom Co., Ltd.", "亞太電信", "電信固網"),
                ("Asia Pacific Telecom", "亞太電信", "電信固網"), ("Kbro Co., Ltd.", "kbro 凱擘大寬頻", "電信固網"),
                ("Homeplus Digital Co., Ltd.", "中嘉數位寬頻", "電信固網"), ("TAIWAN CHIEF TELECOM", "方正電訊 (Chief)", "電信固網"),
                ("Chief Telecom Inc.", "方正電訊 (Chief)", "電信固網"), ("Vibrant Telecom Inc.", "亞太線上", "電信固網"),
                # ☁️ 全球雲端巨頭、CDN 與主流基礎建設
                ("Google LLC", "美商 Google 雲端服務", "雲端巨頭/CDN"), ("Google", "Google", "雲端巨頭/CDN"),
                ("Cloudflare, Inc.", "Cloudflare 網路防禦 CDN", "雲端巨頭/CDN"), ("Cloudflare", "Cloudflare", "雲端巨頭/CDN"),
                ("Akamai Technologies, Inc.", "Akamai 內容傳遞網路", "雲端巨頭/CDN"), ("Akamai", "Akamai", "雲端巨頭/CDN"),
                ("Amazon.com, Inc.", "亞馬遜網路服務 (Amazon AWS)", "雲端巨頭/CDN"), ("Amazon Technologies Inc.", "亞馬遜 AWS 服務", "雲端巨頭/CDN"),
                ("Amazon", "亞馬遜 (Amazon)", "雲端巨頭/CDN"), ("Microsoft Corporation", "微軟公司 (Microsoft Azure)", "雲端巨頭/CDN"),
                ("Microsoft", "微軟", "雲端巨頭/CDN"), ("Meta Platforms, Inc.", "Meta / Facebook 伺服器叢集", "雲端巨頭/CDN"),
                ("Facebook, Inc.", "Meta / Facebook", "雲端巨頭/CDN"), ("DigitalOcean, LLC", "DigitalOcean 雲端主機", "雲端巨頭/CDN"),
                ("DigitalOcean", "DigitalOcean", "雲端巨頭/CDN"), ("Linode, LLC", "Linode 雲端主機", "雲端巨頭/CDN"),
                ("Linode", "Linode", "雲端巨頭/CDN"), ("Vultr Holdings LLC", "Vultr 雲端主機", "雲端巨頭/CDN"),
                ("Fastly Inc.", "Fastly CDN 快取節點", "雲端巨頭/CDN"), ("Netflix Streaming Services Inc.", "Netflix 影音串流快取節點", "雲端巨頭/CDN"),
                ("Apple Inc.", "蘋果公司 (Apple iCloud)", "雲端巨頭/CDN"), ("Valve Corporation", "Valve / Steam 遊戲節點", "雲端巨頭/CDN"),
                # 🌍 常用國際國家與區域基礎名詞
                ("Taiwan", "臺灣", "國際網域/國家"), ("United States", "美國", "國際網域/國家"), ("Japan", "日本", "國際網域/國家"),
                ("Hong Kong", "香港", "國際網域/國家"), ("China", "中國", "國際網域/國家"), ("Singapore", "新加坡", "國際網域/國家"),
                ("South Korea", "韓國", "國際網域/國家"), ("Private Network", "內部私有網路", "國際網域/國家"), ("Internal Device", "內部網路設備", "國際網域/國家")
            ]
            conn.executemany("INSERT OR IGNORE INTO translation_dictionary (eng_text, zh_text, category) VALUES (?, ?, ?)", seed_data)
            conn.commit()
            log_info(f"📚 [靜態配置庫] 運維翻譯字典外掛擴充成功！已匯入 {len(seed_data)} 筆核心地名與機構專屬種子數據。")

        # 核心提交並關閉連線 (此時 config.db 完全就緒)
        conn.commit()
        conn.close()
    
    # 6. 初始化三層式冷熱時序資料庫 與 稽核日誌資料庫
    for db_tier in ['hot', 'warm', 'cold']:
        with DB_LOCKS[db_tier]:
            conn = get_db(db_tier)
            init_telemetry_db(conn, db_tier)
            conn.close()
            
        audit_tier = f'audit_{db_tier}'
        with DB_LOCKS[audit_tier]:
            conn_audit = get_db(audit_tier)
            conn_audit.execute('''CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                username TEXT, action TEXT, target TEXT, result TEXT, details TEXT
            )''')
            conn_audit.execute('CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp)')
            conn_audit.commit()
            conn_audit.close()

    # 7. 🌟 啟動總部戰情大腦資料庫
    init_hq_master_db()

    # 7. 將核心資料庫加入全域常駐陣列，鎖死 WAL 檔案
    global _KEEP_ALIVE_CONNS
    if not _KEEP_ALIVE_CONNS:
        _KEEP_ALIVE_CONNS.append(get_db('config'))
        _KEEP_ALIVE_CONNS.append(get_db('hot'))
        _KEEP_ALIVE_CONNS.append(get_db('audit_hot'))
        log_info("🚀 WAL 高速緩衝常駐連線已啟動 (徹底解決硬碟 -wal 頻繁產生/刪除之損耗)")
    
    # 8. 啟動成功後，熱加載記憶體快取層
    reload_device_cache()
    reload_translation_cache() # 🌟 加載字典快取到記憶體
    
    # 👇 🌟 請在 init_db() 的最後一行補上這句：
    init_security_db()

# ==========================================
# 🛡️ 8. 初始化 NetFlow 資安預警與閾值配置
# ==========================================
def init_security_db():
    with DB_LOCKS['config']:
        conn = get_db('config')
        # 1. 建立資安攻擊事件資料表
        conn.execute('''CREATE TABLE IF NOT EXISTS flow_security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            src_ip TEXT, dst_ip TEXT, attack_type TEXT, 
            severity TEXT, details TEXT, status TEXT DEFAULT 'unhandled'
        )''')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_sec_events_ts ON flow_security_events(timestamp)')
        
        # 2. 寫入 6 大資安預警靈敏度閾值預設值 (全套 7 項設定)
        conn.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('sec_scan_threshold', '50')")
        conn.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('sec_ddos_threshold_mb', '500')")
        conn.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('sec_scan_window_mins', '5')")
        conn.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('sec_brute_threshold', '80')")
        conn.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('sec_exfil_threshold_mb', '1000')")
        conn.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('sec_mining_threshold', '20')")
        conn.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('sec_lateral_threshold', '15')")
        conn.commit()
        conn.close()

# ==========================================
# 🧠 5. 記憶體快取維護核心管理引擎 (方案 4 落地)
# ==========================================
def reload_device_cache():
    """強制將 SQLite 中的設備資料進行多重 JSON 解算，同步更新至 Python 記憶體中"""
    global _DEVICE_CACHE
    try:
        conn = get_db('config')
        rows = conn.execute("SELECT * FROM devices").fetchall()
        conn.close()
        
        temp_list = []
        for r in rows:
            d = dict(r)
            # 🚀 方案 4 進階優化：在載入記憶體變數的這一刻，就把所有沈重的 JSON 字串解算好！
            try: d['poe_data_dict'] = json.loads(d['poe_data']) if d['poe_data'] else {}
            except: d['poe_data_dict'] = {}
            
            try: d['snmp_raw_dict'] = json.loads(d['snmp_raw']) if d['snmp_raw'] else {}
            except: d['snmp_raw_dict'] = {}
            
            temp_list.append(d)
            
        # 進行智慧 IP 排序，確保前端不管怎麼重整，設備列表順序皆完美對齊
        sorted_list = sorted(temp_list, key=lambda d: (0, [int(p) for p in d['ip'].split('.')], d['level']) if is_valid_ipv4(d['ip']) else (1, d['level'], d['ip']))
        
        with _CACHE_LOCK:
            _DEVICE_CACHE = sorted_list
        log_info(f"🧠 [快取引擎] 記憶體雙解算完成！已常駐 {len(_DEVICE_CACHE)} 台設備資料於全記憶體變數中。")
    except Exception as e:
        log_info(f"⚠️ [快取引擎] 刷新快取變數失敗: {e}")

def read_db_devices():
    """🟢 終極讀取：完全不驚動硬碟，Flask 與背景線程直接從高速 RAM 拿取設備資料"""
    with _CACHE_LOCK:
        return list(_DEVICE_CACHE)

def write_db_devices(devices):
    """寫入端：同時同步更新實體資料庫，並瞬間翻新全記憶體快取變數"""
    with DB_LOCKS['config']:
        conn = get_db('config')
        cursor = conn.cursor()
        for dev in devices:
            cursor.execute("SELECT ip FROM devices WHERE ip=?", (dev['ip'],))
            if cursor.fetchone():
                cursor.execute('''UPDATE devices SET name=?, level=?, community=?, location=?, visible=?, type=?, brand=?, model=?, sys_descr=COALESCE(?, sys_descr), status=?, snmp_raw=COALESCE(?, snmp_raw), is_poe=COALESCE(?, is_poe), poe_data=COALESCE(?, poe_data), cpu_load=COALESCE(?, cpu_load), mem_load=COALESCE(?, mem_load), has_sensor=COALESCE(?, has_sensor), ssh_user=COALESCE(?, ssh_user), ssh_pass=COALESCE(?, ssh_pass), ssh_secret=COALESCE(?, ssh_secret), cli_type=COALESCE(?, cli_type), is_backup=COALESCE(?, is_backup), snmp_version=COALESCE(?, snmp_version), port_specs=COALESCE(?, port_specs) WHERE ip=?''', 
                       (dev.get('name'), safe_int(dev.get('level')), dev.get('community'), dev.get('location'), safe_int(dev.get('visible', 1), 1), dev.get('type'), dev.get('brand'), dev.get('model'), dev.get('sys_descr'), dev.get('status', 'up'), dev.get('snmp_raw'), dev.get('is_poe'), dev.get('poe_data'), dev.get('cpu_load'), dev.get('mem_load'), safe_int(dev.get('has_sensor', 0), 0), dev.get('ssh_user'), dev.get('ssh_pass'), dev.get('ssh_secret'), dev.get('cli_type'), safe_int(dev.get('is_backup', 1), 1), dev.get('snmp_version', 'v2c'), dev.get('port_specs', '[]'), dev['ip']))
            else:
                cursor.execute('''INSERT INTO devices (ip, name, level, community, location, visible, type, brand, model, sys_descr, status, snmp_raw, is_poe, poe_data, cpu_load, mem_load, has_sensor, ssh_user, ssh_pass, ssh_secret, cli_type, is_backup, snmp_version, port_specs) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''', 
                       (dev['ip'], dev.get('name'), safe_int(dev.get('level')), dev.get('community'), dev.get('location'), safe_int(dev.get('visible', 1), 1), dev.get('type'), dev.get('brand'), dev.get('model'), dev.get('sys_descr'), dev.get('status', 'up'), dev.get('snmp_raw') or '{}', safe_int(dev.get('is_poe', 0), 0), dev.get('poe_data') or '{}', dev.get('cpu_load', 0.0), dev.get('mem_load', 0.0), safe_int(dev.get('has_sensor', 0), 0), dev.get('ssh_user', ''), dev.get('ssh_pass', ''), dev.get('ssh_secret', ''), dev.get('cli_type', ''), safe_int(dev.get('is_backup', 1), 1), dev.get('snmp_version', 'v2c'), dev.get('port_specs', '[]')))
        conn.commit()
        conn.close()
    
    reload_device_cache()

# ==========================================
# 🛠️ 6. 補回與優化系統維護函數
# ==========================================
def get_system_setting(key, default_value=""):
    """安全獲取系統設定參數"""
    try:
        conn = get_db('config')
        row = conn.execute("SELECT value FROM system_settings WHERE key=?", (key,)).fetchone()
        conn.close()
        return row['value'] if row else default_value
    except:
        return default_value

def update_system_setting(key, value):
    """安全更新系統設定參數"""
    with DB_LOCKS['config']:
        conn = get_db('config')
        conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES (?, ?)", (key, str(value)))
        conn.commit()
        conn.close()
        
def update_device_metrics_cache(updates):
    """
    🟢 方案 4 進階微創優化：
    只在記憶體中精確修改 CPU/RAM/Latency 數值，完全不碰硬碟、不重新解算 JSON！
    """
    if not updates: return
    # 🌟 修正點：這裡必須接收 4 個參數 (cpu, mem, lat, ip)，才能對齊 snmp_core 傳來的陣列！
    lookup = {ip: (cpu, mem, lat) for cpu, mem, lat, ip in updates}
    with _CACHE_LOCK:
        for dev in _DEVICE_CACHE:
            if dev['ip'] in lookup:
                cpu, mem, lat = lookup[dev['ip']]
                dev['cpu_load'] = cpu
                dev['mem_load'] = mem
                dev['latency_ms'] = lat  # 🌟 同步將延遲寫入記憶體快取

# ==========================================
# 🛡️ 7. 💡 新增：高安全性三層式稽核日誌讀寫 API
# ==========================================
def write_audit_log(username, action, target, result, details):
    import time
    try:
        # 1. 寫入主要的熱日誌庫
        with DB_LOCKS['audit_hot']:
            conn = get_db('audit_hot')
            # 💡 終極修正：移除 localtime，統一使用 CURRENT_TIMESTAMP (UTC)，與其他系統日誌對齊！
            conn.execute('''
                INSERT INTO audit_logs (timestamp, username, action, target, result, details) 
                VALUES (CURRENT_TIMESTAMP, ?, ?, ?, ?, ?)
            ''', (username, action, target, result, details))
            conn.commit()
            conn.close()
            
        # 2. 將「行為模組」與「操作權限」同步註冊到靜態設定庫的字典中
        with DB_LOCKS['config']:
            conn_c = get_db('config')
            conn_c.execute("CREATE TABLE IF NOT EXISTS audit_action_dict (action TEXT PRIMARY KEY, category TEXT)")
            conn_c.execute("CREATE TABLE IF NOT EXISTS audit_role_dict (role TEXT PRIMARY KEY)")
            
            cat = "✋ 前端與人為操作"
            if "HTTP" in action: cat = "🌐 系統通訊"
            elif any(x in action for x in ["輪詢", "排程", "引擎", "快取", "清道夫", "背景", "同步", "自動"]): cat = "⚙️ 背景自動引擎"
            elif any(x in action for x in ["掃描", "探索", "Ping", "連線"]): cat = "📡 網路主動探測"
            elif any(x in action for x in ["推播", "告警", "通知"]): cat = "🔔 系統主動告警"
            
            conn_c.execute("INSERT OR IGNORE INTO audit_action_dict (action, category) VALUES (?, ?)", (action, cat))
            conn_c.execute("INSERT OR IGNORE INTO audit_role_dict (role) VALUES (?)", (username,))
            conn_c.commit()
            conn_c.close()
            
    except Exception as e:
        print(f"⚠️ 寫入日誌或註冊字典失敗: {e}")

def read_audit_logs(limit=200):
    """前端調用：從高速熱日誌庫拉取近期明細"""
    try:
        conn = get_db('audit_hot')
        rows = conn.execute(
            "SELECT id, strftime('%Y-%m-%d %H:%M:%S', timestamp, 'localtime') as ts, username, action, target, result, details FROM audit_logs ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except:
        return []
        
def query_advanced_audit_logs(keyword='', action='', result='', username='', start_time='', end_time='', page=1, per_page=50):
    """
    💡 支援權限 (username) 過濾與全方位時間區間的聯合查詢引擎
    """
    try:
        conn = get_db('audit_hot')
        conn.execute("ATTACH DATABASE 'audit_warm.db' AS warm_audit")
        conn.execute("ATTACH DATABASE 'audit_cold.db' AS cold_audit")
        
        union_sql = """
            SELECT strftime('%Y-%m-%d %H:%M:%S', timestamp, 'localtime') as ts, username, action, target, result, details, timestamp FROM main.audit_logs
            UNION ALL
            SELECT strftime('%Y-%m-%d %H:%M:%S', timestamp, 'localtime') as ts, username, action, target, result, details, timestamp FROM warm_audit.audit_logs
            UNION ALL
            SELECT strftime('%Y-%m-%d %H:%M:%S', timestamp, 'localtime') as ts, username, action, target, result, details, timestamp FROM cold_audit.audit_logs
        """
        
        where_clauses = []
        params = []
        if keyword:
            where_clauses.append("(username LIKE ? OR target LIKE ? OR details LIKE ?)")
            kw = f"%{keyword}%"
            params.extend([kw, kw, kw])
        if action:
            where_clauses.append("action = ?")
            params.append(action)
        if result:
            where_clauses.append("result = ?")
            params.append(result)
        # 💡 新增：權限角色過濾
        if username:
            where_clauses.append("username = ?")
            params.append(username)
            
        if start_time:
            where_clauses.append("timestamp >= ?")
            params.append(start_time.replace('T', ' '))
        if end_time:
            where_clauses.append("timestamp <= ?")
            params.append(end_time.replace('T', ' '))
            
        where_str = " WHERE " + " AND ".join(where_clauses) if where_clauses else ""
        
        count_sql = f"SELECT COUNT(*) FROM ({union_sql}) {where_str}"
        total_count = conn.execute(count_sql, params).fetchone()[0]
        
        offset = (page - 1) * per_page
        data_sql = f"SELECT * FROM ({union_sql}) {where_str} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        
        query_params = list(params)
        query_params.extend([per_page, offset])
        
        rows = conn.execute(data_sql, query_params).fetchall()
        
        conn.execute("DETACH DATABASE warm_audit")
        conn.execute("DETACH DATABASE cold_audit")
        conn.close()
        
        return [dict(r) for r in rows], total_count
    except Exception as e:
        log_info(f"⚠️ [日誌中心引擎] 跨庫聯合過濾失敗: {e}")
        return [], 0

def reload_translation_cache():
    """強制將資料庫中的翻譯對照字典熱加載至 Python 記憶體快取變數中"""
    global _TRANSLATION_CACHE
    try:
        conn = get_db('config')
        rows = conn.execute("SELECT eng_text, zh_text FROM translation_dictionary").fetchall()
        conn.close()
        
        temp_dict = {}
        for r in rows:
            temp_dict[str(r['eng_text']).strip()] = str(r['zh_text']).strip()
            
        with _TRANSLATION_LOCK:
            _TRANSLATION_CACHE = temp_dict
        log_info(f"🧠 [快取引擎] 翻譯對照字典已成功載入記憶體！共計熱暫存 {len(_TRANSLATION_CACHE)} 組詞條。")
    except Exception as e:
        print(f"⚠️ 刷新翻譯快取失敗: {e}")

def read_translation_cache():
    """唯讀高並發取用：不驚動硬碟，Flask 直讀記憶體變數"""
    with _TRANSLATION_LOCK:
        return dict(_TRANSLATION_CACHE)