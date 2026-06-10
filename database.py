import os
import csv
import sqlite3
import threading
import json
from utils import log_info, is_valid_ipv4, safe_int

# 🛡️ 宣告全域常駐連線，確保 WAL/SHM 檔永遠不被刪除
_KEEP_ALIVE_CONNS = []

# ==========================================
# 📊 InfluxDB v2 時序流量資料庫配置
# ==========================================
INFLUXDB_URL = "http://localhost:8086"
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

# 🔒 各資料庫獨立的執行緒鎖，徹底消滅 SQLite Database Locked 死鎖衝突
DB_LOCKS = {
    'config': threading.Lock(),
    'hot': threading.Lock(),
    'warm': threading.Lock(),
    'cold': threading.Lock(),
    'audit_hot': threading.Lock(),  # 💡 日誌熱鎖
    'audit_warm': threading.Lock(), # 💡 日誌溫鎖
    'audit_cold': threading.Lock()  # 💡 日誌冷鎖
}

# ==========================================
# 🧠 2. 方案 4：全記憶體變數快取層 (Python RAM Cache)
# ==========================================
_DEVICE_CACHE = []            # 存放全網設備的常駐記憶體陣列
_CACHE_LOCK = threading.Lock() # 快取專屬執行緒鎖

# ========================================================
# ⚙️ 核心資料庫連線工廠 (內建 SQLite 性能優化)
# ========================================================
def get_db(db_name='config'):
    db_path = DB_CONFIG
    if db_name == 'hot': db_path = DB_HOT
    elif db_name == 'warm': db_path = DB_WARM
    elif db_name == 'cold': db_path = DB_COLD
    elif db_name == 'audit_hot': db_path = DB_AUDIT_HOT
    elif db_name == 'audit_warm': db_path = DB_AUDIT_WARM
    elif db_name == 'audit_cold': db_path = DB_AUDIT_COLD

    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    
    # ⚡ 啟動預寫式日誌模式，允許高並發讀寫並行
    conn.execute('PRAGMA journal_mode=WAL;')
    
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
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )''')
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

def init_db():
    """系統啟動核心：初始化所有實體 .db 檔案與資料表結構"""
    with DB_LOCKS['config']:
        conn = get_db('config')
        # 設備主表
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
        
        # 拓樸排版槽位表
        conn.execute('CREATE TABLE IF NOT EXISTS layout_slots (slot_id INTEGER, ip TEXT, x REAL, y REAL, PRIMARY KEY (slot_id, ip))')
        # 拓樸連線關係表
        conn.execute('CREATE TABLE IF NOT EXISTS edges (id TEXT PRIMARY KEY, source TEXT, target TEXT, speed INTEGER, OID_info TEXT, port_info TEXT, from_port TEXT, to_port TEXT)')
        # 每日異常統計表
        conn.execute('CREATE TABLE IF NOT EXISTS anomaly_daily_stats (date TEXT PRIMARY KEY, runs INTEGER DEFAULT 0)')
        # 系統核心參數排程表
        conn.execute('CREATE TABLE IF NOT EXISTS system_settings (key TEXT PRIMARY KEY, value TEXT)')
        
        # 💡 新增：手動連線拓樸表 (解決 LLDP 無法發現的孤島設備)
        conn.execute('''CREATE TABLE IF NOT EXISTS manual_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            node_a TEXT, port_a TEXT,
            node_b TEXT, port_b TEXT,
            speed INTEGER DEFAULT 1000
        )''')
        
        # 💡 新增：設備實體埠快取表 (加速介面載入，掃過一次就永存)
        conn.execute('''CREATE TABLE IF NOT EXISTS device_ports (
            ip TEXT,
            port_idx TEXT,
            port_name TEXT,
            speed INTEGER,
            PRIMARY KEY (ip, port_idx)
        )''')
        
        # 💡 [強固型防重複重置優化] 
        # 檢查是否存在非預設值的真實自訂網址，若有，無情清除所有殘留的本機佔位符，徹底解決重啟時設定消失的 Bug
        has_custom = conn.execute("SELECT COUNT(*) FROM system_settings WHERE key='ntfy_url' AND value != 'http://localhost:8080/your_topic'").fetchone()[0]
        if has_custom > 0:
            conn.execute("DELETE FROM system_settings WHERE key='ntfy_url' AND value = 'http://localhost:8080/your_topic'")
        else:
            # 如果資料庫完全全新、空無一物，才寫入匿名去識別化佔位符
            check_url = conn.execute("SELECT COUNT(*) FROM system_settings WHERE key='ntfy_url'").fetchone()[0]
            if check_url == 0:
                conn.execute("INSERT INTO system_settings (key, value) VALUES ('ntfy_enabled', '0')")
                conn.execute("INSERT INTO system_settings (key, value) VALUES ('ntfy_url', 'http://localhost:8080/your_topic')")
        
        # 寫入預設核心排程參數
        conn.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('polling_interval', '3')")
        conn.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('topo_scan_interval', '0')")
        conn.commit()
        
    # 🌟 【無痛升級新增】RBAC 使用者資料表
        conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            status INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # 🌟 自動寫入預設 Admin 帳號 (密碼: admin)
        count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if count == 0:
            import hashlib, secrets
            salt = secrets.token_hex(8)
            # 預設密碼為 'admin'
            key = hashlib.pbkdf2_hmac('sha256', 'admin'.encode('utf-8'), salt.encode('utf-8'), 100000)
            pwd = f"{salt}${key.hex()}"
            conn.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", ('admin', pwd, 'admin'))
            log_info("🔐 RBAC 系統初始化完成：已建立預設 admin 帳號 (密碼: admin)")

        conn.commit()
        conn.close()
    
    # 初始化三層式冷熱時序資料庫 與 稽核日誌資料庫
    for db_tier in ['hot', 'warm', 'cold']:
        # 1. 初始化流量時序分層庫
        with DB_LOCKS[db_tier]:
            conn = get_db(db_tier)
            init_telemetry_db(conn, db_tier) # 💡 將 db_tier 參數傳入
            conn.close()
            
        # 2. 💡 初始化稽核日誌分層庫 (結構完全對稱)
        audit_tier = f'audit_{db_tier}'
        with DB_LOCKS[audit_tier]:
            conn_audit = get_db(audit_tier)
            conn_audit.execute('''CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                username TEXT, action TEXT, target TEXT, result TEXT, details TEXT
            )''')
            conn_audit.execute('CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp)')
            conn_audit.commit()
            conn_audit.close()

    # 🌟 【終極防禦】將三個核心資料庫加入全域常駐陣列，鎖死 WAL 檔案！
    global _KEEP_ALIVE_CONNS
    if not _KEEP_ALIVE_CONNS:
        _KEEP_ALIVE_CONNS.append(get_db('config'))
        _KEEP_ALIVE_CONNS.append(get_db('hot'))
        _KEEP_ALIVE_CONNS.append(get_db('audit_hot'))
        log_info("🚀 WAL 高速緩衝常駐連線已啟動 (徹底解決硬碟 -wal 頻繁產生/刪除之損耗)")
    
    # 💡 啟動成功後，立刻將實體資料提煉並常駐至 Python 記憶體
    reload_device_cache()

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
                cursor.execute('''UPDATE devices SET name=?, level=?, community=?, location=?, visible=?, type=?, brand=?, model=?, sys_descr=COALESCE(?, sys_descr), status=?, snmp_raw=COALESCE(?, snmp_raw), is_poe=COALESCE(?, is_poe), poe_data=COALESCE(?, poe_data), cpu_load=COALESCE(?, cpu_load), mem_load=COALESCE(?, mem_load), has_sensor=COALESCE(?, has_sensor), ssh_user=COALESCE(?, ssh_user), ssh_pass=COALESCE(?, ssh_pass), ssh_secret=COALESCE(?, ssh_secret), cli_type=COALESCE(?, cli_type) WHERE ip=?''', 
                       (dev.get('name'), safe_int(dev.get('level')), dev.get('community'), dev.get('location'), safe_int(dev.get('visible', 1), 1), dev.get('type'), dev.get('brand'), dev.get('model'), dev.get('sys_descr'), dev.get('status', 'up'), dev.get('snmp_raw'), dev.get('is_poe'), dev.get('poe_data'), dev.get('cpu_load'), dev.get('mem_load'), safe_int(dev.get('has_sensor', 0), 0), dev.get('ssh_user'), dev.get('ssh_pass'), dev.get('ssh_secret'), dev.get('cli_type'), dev['ip']))
            else:
                cursor.execute('''INSERT INTO devices (ip, name, level, community, location, visible, type, brand, model, sys_descr, status, snmp_raw, is_poe, poe_data, cpu_load, mem_load, has_sensor, ssh_user, ssh_pass, ssh_secret, cli_type) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''', 
                       (dev['ip'], dev.get('name'), safe_int(dev.get('level')), dev.get('community'), dev.get('location'), safe_int(dev.get('visible', 1), 1), dev.get('type'), dev.get('brand'), dev.get('model'), dev.get('sys_descr'), dev.get('status', 'up'), dev.get('snmp_raw') or '{}', safe_int(dev.get('is_poe', 0), 0), dev.get('poe_data') or '{}', dev.get('cpu_load', 0.0), dev.get('mem_load', 0.0), safe_int(dev.get('has_sensor', 0), 0), dev.get('ssh_user', ''), dev.get('ssh_pass', ''), dev.get('ssh_secret', ''), dev.get('cli_type', '')))
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
    只在記憶體中精確修改 CPU/RAM 數值，完全不碰硬碟、不重新解算 JSON！
    """
    if not updates: return
    lookup = {ip: (cpu, mem) for cpu, mem, ip in updates}
    with _CACHE_LOCK:
        for dev in _DEVICE_CACHE:
            if dev['ip'] in lookup:
                cpu, mem = lookup[dev['ip']]
                dev['cpu_load'] = cpu
                dev['mem_load'] = mem

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
