import re
import platform
import subprocess
import threading
import logging
import time

# ==========================================
# 📝 日誌系統 (Logging) - 徹底移除檔案寫入
# ==========================================
# 💡 將 Flask 原生的 werkzeug 日誌強制關閉，避免黑視窗雜亂
werkzeug_log = logging.getLogger('werkzeug')
werkzeug_log.setLevel(logging.ERROR)

def log_info(msg):
    """
    🟢 終極全自動日誌攔截器 (純終端機輸出與資料庫寫入)
    """
    import re
    import sqlite3
    
    # 💡 引擎正名轉換：在印出與存檔前，先替換掉舊名稱
    msg = msg.replace("[終極引擎]", "【效能流量輪詢】")
    msg = msg.replace("[背景引擎]", "【自動拓樸搜尋】")
    msg = msg.replace("[快取引擎]", "【記憶體快取】")
    msg = msg.replace("[", "【").replace("]", "】")
    
    now_str = time.strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{now_str}] {msg}")

    try:
        conn_cfg = sqlite3.connect('config.db', timeout=5.0)
        cur = conn_cfg.execute("SELECT key, value FROM system_settings WHERE key LIKE 'audit_%'")
        policies = {r[0]: r[1] for r in cur.fetchall()}
        conn_cfg.close()

        username = "SystemEngine"
        action = "系統核心事件"
        target = "背景守護行程"
        result = "SUCCESS"
        
        if any(x in msg for x in ["⚠️", "🔴", "失敗", "錯誤", "異常", "拒絕", "404", "500"]):
            result = "FAILED"

        match = re.search(r'【(.*?)】', msg)
        if match: action = match.group(1)

        if "【HTTP】" in msg:
            action = "HTTP 請求"
            parts = msg.split('|')
            if len(parts) >= 3:
                username = parts[1].strip()
                target = parts[2].strip().replace('"', '')
            
            if "/api/ping" in msg:
                action = "主動網路探測"
                if policies.get('audit_net_scan', '1') == '0': return
            elif "GET " in msg and policies.get('audit_ui_view', '0') == '0':
                return
        else:
            if action in ["多核心並行輪詢", "記憶體快取", "效能流量輪詢", "自動拓樸搜尋", "紀錄生命週期"]:
                if policies.get('audit_engine_bg', '1') == '0': return
            
            if action in ["LLDP探索", "網段探索", "單機掃描"]:
                if policies.get('audit_net_scan', '1') == '0': return

        conn = sqlite3.connect('audit_hot.db', timeout=10.0)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("INSERT INTO audit_logs (username, action, target, result, details) VALUES (?, ?, ?, ?, ?)", (username, action, target, result, msg))
        conn.commit()
        conn.close()
    except Exception as e:
        pass

# ==========================================
# 🔒 全域掃描鎖 (防止多個背景掃描打架)
# ==========================================
SCAN_LOCK = threading.Lock()
current_active_scan = {"name": None}

def try_acquire_scan(name):
    with SCAN_LOCK:
        if current_active_scan["name"] is not None:
            return False, current_active_scan["name"]
        current_active_scan["name"] = name
        return True, name

def release_scan():
    with SCAN_LOCK:
        current_active_scan["name"] = None

# ==========================================
# 🛠️ 基礎工具函數
# ==========================================
def clean_str(val):
    if not val: return ""
    return str(val).replace('"', '').replace('\n', ' ').replace('\r', ' ').strip()

def is_valid_ipv4(ip_str): 
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", str(ip_str)) is not None

def safe_int(val, default=3):
    try: return int(val) if val is not None and str(val).strip() != '' else default
    except (ValueError, TypeError): return default

def check_ping(ip):
    if not is_valid_ipv4(ip): return False
    try:
        is_windows = platform.system().lower() == 'windows'
        param = '-n' if is_windows else '-c'
        result = subprocess.run(['ping', param, '1', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1.5)
        if result.returncode != 0: return False
        out_text = result.stdout.decode('cp950' if is_windows else 'utf-8', errors='ignore')
        if "無法連線" in out_text or "unreachable" in out_text or "逾時" in out_text or "timed out" in out_text: return False
        if is_windows and "TTL=" not in out_text: return False
        return True
    except: return False

def parse_snmp_val(val_obj):
    try:
        if hasattr(val_obj, 'asOctets'):
            octets = val_obj.asOctets()
            if not octets: return ""
            if all(32 <= b <= 126 or b in (9, 10, 13) for b in octets): return octets.decode('ascii', errors='ignore').strip()
            return ':'.join(f'{b:02X}' for b in octets)
    except: pass
    return str(val_obj).strip()

def extract_brand_model(descr):
    if not descr: return "Unknown", ""
    brand = "Unknown"; d_lower = descr.lower()
    if "ruckus" in d_lower or "ironware" in d_lower: brand = "Ruckus"
    elif "aruba" in d_lower: brand = "Aruba"
    elif "palo alto" in d_lower: brand = "Palo Alto"
    elif "forti" in d_lower: brand = "Fortinet"
    elif "routeros" in d_lower or "mikrotik" in d_lower: brand = "MikroTik"
    elif "d-link" in d_lower or "dgs" in d_lower: brand = "D-Link"
    elif "cisco" in d_lower: brand = "Cisco"
    elif "hp" in d_lower or "procurve" in d_lower: brand = "HP"
    elif "qnap" in d_lower or "qsw" in d_lower: brand = "QNAP"
    elif "dell" in d_lower: brand = "Dell"
    m = re.search(r'(CRS\d+[A-Za-z0-9\+\-]+|CX\d{4}[A-Za-z0-9\-]*|ICX\s?\d{4}[A-Za-z0-9\-]*|DGS-\d+[A-Za-z0-9\-]*|QSW-[A-Za-z0-9\-]+|FortiGate-\d+[A-Za-z0-9]*|WS-C\d+[A-Za-z0-9\-]*|C\d{4}[A-Za-z0-9\-]+|[XN]\d{4}[A-Za-z0-9\-]*|PA-\d+[A-Za-z0-9\-]*)', descr, re.IGNORECASE)
    return brand, m.group(1).strip() if m else (descr[:50] + "..." if len(descr) > 50 else descr)
    
import requests

# ==========================================
# 📱 ntfy 推播發送引擎 (完全解耦動態資料庫版)
# ==========================================
def send_ntfy_alert(title, message, priority="default", tags="", source="系統排程", ip_addr="localhost"):
    import requests
    
    # 💡 匯入寫入日誌與讀取系統設定的函式
    try:
        from database import write_audit_log, get_system_setting
    except ImportError:
        write_audit_log = None
        get_system_setting = None

    # 1. 🔍 動態讀取開關與伺服器網址
    # 💡 [安全防禦修正] 程式碼內部完全去識別化，回退值不留任何實體環境軌跡
    ntfy_enabled = "0"
    url = "http://localhost:8080/your_topic" 
    
    if get_system_setting:
        ntfy_enabled = get_system_setting('ntfy_enabled', '0')
        url = get_system_setting('ntfy_url', url).strip()
    
    # 2. 🛑 智慧守門員：如果不是手動點擊的「測試」任務，且後台把開關關閉（0），則直接優雅退場
    #    如果是預設的 localhost 佔位符，也直接攔截，避免對無效網址發送無效連線
    if source != "測試" and ntfy_enabled != "1":
        return False
    if not url or url == "http://localhost:8080/your_topic":
        return False

    # 針對 headers 裡的 Title 進行 utf-8 強制編碼
    headers = {
        "Title": title.encode('utf-8'),
        "Priority": priority,
        "Tags": tags
    }
    
    try:
        # 發送推播 (強制直連不繞 Proxy，超時限制由 3 秒微調為 4 秒防止複雜網絡掉包)
        response = requests.post(url, data=message.encode('utf-8'), headers=headers, timeout=4, proxies={"http": None, "https": None})
        
        if response.status_code == 200:
            print(f"✅ 告警推播成功！主題: {title} (發送至: {url} | 來源: {source})")
            
            # 嚴格對齊 database.py 的五大欄位
            if write_audit_log:
                write_audit_log(
                    username=f"{source} ({ip_addr})", 
                    action="推播通知", 
                    target="系統告警", 
                    result="SUCCESS", 
                    details=f"[{title}] {message}"
                )
            return True
        else:
            raise requests.exceptions.RequestException(f"HTTP Status {response.status_code}")
            
    except Exception as e:
        print(f"⚠️ [Ntfy 推播失敗] 無法連線至指定的自建推播主機 ({url}): {e}")
        
        if write_audit_log:
            write_audit_log(
                username=f"{source} ({ip_addr})", 
                action="推播通知", 
                target="系統告警", 
                result="FAILED", 
                details=f"發送失敗 (目標 {url}): {e}"
            )
        return False
        
