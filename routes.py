import os
import csv
import json
import asyncio
import re
import time
import io
import platform
import subprocess
from datetime import datetime, timedelta
# 💡 確保這裡有 import redirect
from flask import Blueprint, render_template, jsonify, request, send_file, redirect
import hashlib
from functools import wraps
from flask import session  # 確保有 session
import secrets
import sqlite3
from tftp_backup_core import trigger_tftp_backup
import ipaddress
from influxdb_client import InfluxDBClient

try:
    from pysnmp.hlapi.v3arch.asyncio import (
        SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
        ObjectType, ObjectIdentity, get_cmd
    )
    HAS_PYSNMP = True
except ImportError:
    HAS_PYSNMP = False

from utils import (
    log_info, try_acquire_scan, release_scan, safe_int, 
    check_ping, extract_brand_model, clean_str, is_valid_ipv4
)
from database import (
    DB_LOCKS, get_db, read_db_devices, write_db_devices,
    query_advanced_audit_logs, write_audit_log, reload_device_cache,
    INFLUXDB_URL, INFLUXDB_TOKEN, INFLUXDB_ORG, INFLUXDB_BUCKET  # 👈 補上這行
)
from snmp_core import async_get_device_info, async_get_device_full_data, discover_topology

from functools import wraps
from flask import session, jsonify, request

# ========================================================
# 🛡️ RBAC 系統角色定義與核心防禦裝飾器
# ========================================================
ROLE_ADMIN = 'admin'
ROLE_OPERATOR = 'operator'
ROLE_AUDITOR = 'auditor'

def verify_password(stored_password, provided_password):
    """驗證密碼雜湊是否正確"""
    try:
        salt, key = stored_password.split('$')
        new_key = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt.encode('utf-8'), 100000)
        return new_key.hex() == key
    except Exception:
        return False

# 🌟 加上這個：用於新增帳號或重設密碼時的加密
def hash_password(password):
    """將明文密碼進行加鹽雜湊"""
    salt = secrets.token_hex(8)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return f"{salt}${key.hex()}"

def require_role(allowed_roles):
    """RBAC 核心防護裝飾器 (支援網頁重導與 API 攔截)"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            with DB_LOCKS['config']:
                conn = get_db('config')
                row = conn.execute("SELECT value FROM system_settings WHERE key='rbac_enabled'").fetchone()
                conn.close()
                
            rbac_enabled = (row['value'] == '1') if row else True
            if not rbac_enabled:
                return f(*args, **kwargs) 
                
            user_role = session.get('role')
            is_api_request = request.path.startswith('/api/')
            
            # 1. 攔截未登入者
            if not user_role:
                if is_api_request: return jsonify({'status': 'error', 'message': '未登入或 Session 已過期'}), 401
                else: return redirect('/login') # 網頁請求直接導向登入頁
                
            # 2. 嚴格角色檢查 (無分大小寫)
            user_role_lower = user_role.lower()
            allowed_lower = [r.lower() for r in allowed_roles]
            
            if user_role_lower != ROLE_ADMIN.lower() and user_role_lower not in allowed_lower:
                write_audit_log(session.get('username'), request.remote_addr, "ACCESS_DENIED", f"越權存取 {request.path}", "FAILED")
                if is_api_request: return jsonify({'status': 'error', 'message': '權限不足，拒絕存取'}), 403
                else: return "<h3>❌ 權限不足</h3>您沒有權限存取此頁面。", 403
                
            return f(*args, **kwargs)
        return decorated_function 
    return decorator

main_bp = Blueprint('main', __name__)

# ========================================================
# 🛡️ 全域 HTTP 請求攔截與資安白名單控制
# ========================================================
allowed_ips_cache = {'time': 0, 'networks': []}

def get_allowed_networks():
    now = time.time()
    if now - allowed_ips_cache['time'] < 5:
        return allowed_ips_cache['networks']
    
    conn = get_db('config')
    row = conn.execute("SELECT value FROM system_settings WHERE key='allowed_ips'").fetchone()
    conn.close()
    
    # 🌟 移除 192.50.1.0/24 預設值，如果沒有設定就是空字串，不啟用防護攔截
    raw_val = row['value'] if row and row['value'] else ''
    networks = []
    if not raw_val:
        allowed_ips_cache['networks'] = []
        allowed_ips_cache['time'] = now
        return []
    
    for item in raw_val.split(','):
        item = item.strip()
        if not item: continue
        try:
            if '/' in item: networks.append(ipaddress.IPv4Network(item, strict=False))
            else: networks.append(ipaddress.IPv4Address(item))
        except: pass
            
    allowed_ips_cache['networks'] = networks
    allowed_ips_cache['time'] = now
    return networks

@main_bp.before_app_request
def limit_remote_addr():
    if request.remote_addr == '127.0.0.1' or request.remote_addr == '::1': return None
    allowed_nets = get_allowed_networks()
    if not allowed_nets: return None
        
    try:
        client_ip = ipaddress.IPv4Address(request.remote_addr)
        is_allowed = False
        for net in allowed_nets:
            if isinstance(net, ipaddress.IPv4Network) and client_ip in net: is_allowed = True; break
            elif isinstance(net, ipaddress.IPv4Address) and client_ip == net: is_allowed = True; break
        if not is_allowed:
            log_info(f"⚠️ 【資安攔截】拒絕來自非授權網段的存取嘗試！來源 IP: {request.remote_addr}")
            return "<h3>❌ 存取被拒絕 (Access Denied)</h3>您的 IP 不在系統允許的管理網段與白名單內。", 403
    except Exception: 
        return "<h3>❌ 安全防護攔截</h3>來源請求無效，拒絕存取。", 403

@main_bp.after_app_request
def custom_http_logger(response):
    if request.path.startswith('/api/traffic') or request.path.startswith('/api/dashboard/stats'): return response 
    # 把 Chrome 的囉嗦請求直接靜音，不印在終端機上
    if request.path.startswith('/.well-known/'): return response 
    
    log_info(f"🌐 【HTTP】 {request.remote_addr} | SystemUser | \"{request.method} {request.path}\" {response.status_code}")
    return response

# ========================================================
# 🌐 頁面路由 (加入 RBAC 防護)
# ========================================================
# 💡 將根目錄重導向至戰情總覽
@main_bp.route('/')
def index(): return redirect('/dashboard')

# 💡 為拓樸圖建立專屬路由
@main_bp.route('/topology')
@require_role([ROLE_ADMIN, ROLE_OPERATOR])  # 🛡️ 限 Admin, Operator
def topology_page(): return render_template('topology.html')

@main_bp.route('/devices')
@require_role([ROLE_ADMIN])  # 🛡️ 限 Admin 專屬
def devices_page(): return render_template('devices.html')

@main_bp.route('/report')
@require_role([ROLE_ADMIN, ROLE_OPERATOR])  # 🛡️ 限 Admin, Operator
def report_page(): return render_template('report.html')

@main_bp.route('/dashboard')
def dashboard_page(): return render_template('dashboard.html')

def init_flow_port_dictionary_if_empty():
    """全自動檢驗並初始化 InfluxDB 流量查詢專用的萬國通訊埠標準維運字典 (防止死鎖保護版)"""
    with DB_LOCKS['config']:
        conn = get_db('config')
        try:
            # 1. 建立標準 Port 字典表
            conn.execute('''
                CREATE TABLE IF NOT EXISTS flow_port_dictionary (
                    port INTEGER PRIMARY KEY,
                    service_name TEXT,
                    description TEXT
                )
            ''')
            conn.commit()
            
            # 2. 檢查是否已經有資料，若空則一口氣灌入 Wikipedia 核心知名維運網管標準 Port
            row = conn.execute("SELECT COUNT(*) as cnt FROM flow_port_dictionary").fetchone()
            if row and row['cnt'] == 0:
                # 依據維基百科與企業資安防禦最常見之標準協議包
                default_ports = [
                    (20, 'FTP-Data', 'FTP 檔案傳輸協議 - 資料通道'),
                    (21, 'FTP', 'FTP 檔案傳輸協議 - 控制通道'),
                    (22, 'SSH', 'SSH 安全加密遠端連線 / SFTP 傳輸'),
                    (23, 'Telnet', 'Telnet 明文遠端命令控制 (資安高風險)'),
                    (25, 'SMTP', 'SMTP 標準郵件發送協議'),
                    (53, 'DNS', 'DNS 網域名稱解析服務'),
                    (67, 'DHCPs', 'DHCP 動態 IP 配置 - 伺服器端'),
                    (68, 'DHCPc', 'DHCP 動態 IP 配置 - 用戶端'),
                    (69, 'TFTP', 'TFTP 簡單檔案傳輸協定 (設備備份常用)'),
                    (80, 'HTTP', 'HTTP 明文全球資訊網網頁服務'),
                    (88, 'Kerberos', 'Kerberos 網域安全認證中心'),
                    (110, 'POP3', 'POP3 郵件接收協議'),
                    (123, 'NTP', 'NTP 網路時間校時同步服務'),
                    (135, 'RPC-EPMAP', 'Microsoft RPC 開放端口映射器'),
                    (137, 'NetBIOS-NS', 'NetBIOS 區域網路名稱服務'),
                    (138, 'NetBIOS-DGM', 'NetBIOS 區域網路資料報服務'),
                    (139, 'NetBIOS-SSN', 'NetBIOS 區域網路工作階段服務'),
                    (143, 'IMAP', 'IMAP 網際網路郵件存取協議'),
                    (161, 'SNMP', 'SNMP 網路設備狀態輪詢監控'),
                    (162, 'SNMP-Trap', 'SNMP Trap 設備異常主動告警推播'),
                    (389, 'LDAP', 'LDAP 目錄服務認證'),
                    (443, 'HTTPS', 'HTTPS 加密安全網頁服務'),
                    (445, 'SMB', 'SMB 網路檔案與印表機共享 (容易被微軟漏洞攻擊)'),
                    (465, 'SMTPS', 'SMTPS 加密郵件發送服務'),
                    (514, 'Syslog', 'Syslog 系統資安設備日誌集中化收集'),
                    (546, 'DHCPv6-c', 'DHCPv6 用戶端服務'),
                    (547, 'DHCPv6-s', 'DHCPv6 伺服器端服務'),
                    (587, 'SMTP-Sub', 'SMTP 郵件用戶端安全提交埠'),
                    (636, 'LDAPS', 'LDAPS 安全加密型帳號認證目錄服務'),
                    (993, 'IMAPS', 'IMAPS 安全加密型郵件接收服務'),
                    (995, 'POP3S', 'POP3S 安全加密型郵件接收服務'),
                    (1433, 'MSSQL', 'Microsoft SQL Server 資料庫服務'),
                    (1521, 'Oracle', 'Oracle Database 資料庫服務'),
                    (3306, 'MySQL', 'MySQL / MariaDB 關係型資料庫服務'),
                    (3389, 'RDP', 'Windows Remote Desktop 遠端桌面控制埠'),
                    (5900, 'VNC', 'VNC 遠端虛擬網路控制桌面'),
                    (8080, 'HTTP-Proxy', 'HTTP 代理伺服器 / Tomcat 預設網頁服務'),
                    (8443, 'HTTPS-Alt', 'HTTPS 備用加密網頁服務'),
                    (9092, 'Kafka', 'Apache Kafka 大數據高流量訊息佇列')
                ]
                conn.executemany("INSERT INTO flow_port_dictionary (port, service_name, description) VALUES (?, ?, ?)", default_ports)
                conn.commit()
        finally:
            conn.close()

@main_bp.route('/flow-search')
@require_role([ROLE_ADMIN, ROLE_OPERATOR])
def flow_search_page(): 
    # 💡 確保字典初始化完整
    init_flow_port_dictionary_if_empty()
    with DB_LOCKS['config']:
        conn = get_db('config')
        try:
            r_int = conn.execute("SELECT value FROM system_settings WHERE key='flow_internal_nets'").fetchone()
            r_exc = conn.execute("SELECT value FROM system_settings WHERE key='flow_exclude_nets'").fetchone()
        finally:
            conn.close()
            
    internal_nets = r_int['value'] if r_int else '10.0.0.0/8, 172.16.0.0/12, 192.168.1.0/24'
    exclude_nets = r_exc['value'] if r_exc else '' 
    return render_template('flow_search.html', internal_nets=internal_nets, exclude_nets=exclude_nets)

@main_bp.route('/api/flow/port_dictionary', methods=['GET'])
@require_role([ROLE_ADMIN, ROLE_OPERATOR])
def get_flow_port_dictionary():
    """向前端全面釋出資料庫內建的通用 Port 翻譯對照字典 (100% 死鎖防禦版)"""
    port_map = {}
    with DB_LOCKS['config']:
        conn = get_db('config')
        try:
            cursor = conn.execute("SELECT port, service_name FROM flow_port_dictionary")
            for row in cursor.fetchall():
                port_map[str(row['port'])] = row['service_name']
        finally:
            conn.close()
    return jsonify(port_map)

@main_bp.route('/settings')
@require_role([ROLE_ADMIN])  # 🛡️ 限 Admin 專屬
def settings_page(): return render_template('settings.html')

@main_bp.route('/audit-logs')
@require_role([ROLE_ADMIN, ROLE_OPERATOR, ROLE_AUDITOR])  # 🛡️ 三種角色皆可看
def audit_logs_page(): return render_template('audit_logs.html')

# ========================================================
# 🔐 身份驗證 API (登入/登出)
# ========================================================
@main_bp.route('/api/login', methods=['POST'])
def api_login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        with DB_LOCKS['config']:
            conn = get_db('config')
            user = conn.execute("SELECT * FROM users WHERE username = ? AND status = 1", (username,)).fetchone()
            conn.close()
            
        if user and verify_password(user['password_hash'], password):
            session['username'] = user['username']
            session['role'] = user['role']
            write_audit_log(user['username'], request.remote_addr, "USER_LOGIN", "使用者成功登入系統", "SUCCESS")
            return jsonify({'status': 'success', 'msg': '登入成功'})
            
        return jsonify({'status': 'error', 'msg': '帳號或密碼錯誤'}), 401
    except Exception as e:
        return jsonify({'status': 'error', 'msg': str(e)}), 500

@main_bp.route('/api/logout', methods=['POST'])
def api_logout():
    username = session.get('username', 'Unknown')
    session.clear()
    write_audit_log(username, request.remote_addr, "USER_LOGOUT", "使用者登出系統", "SUCCESS")
    return jsonify({'status': 'success', 'msg': '已成功登出'})

@main_bp.route('/login')
def login_page():
    return render_template('login.html')

# ========================================================
# 🌟 系統進階除錯雷達開關 API
# ========================================================
@main_bp.route('/api/get_debug_status', methods=['GET'])
def get_debug_status():
    import snmp_core
    return jsonify({"status": "success", "debug_mode": snmp_core.GLOBAL_DEBUG_MODE})

@main_bp.route('/api/toggle_debug_mode', methods=['POST'])
@require_role([ROLE_ADMIN])
def toggle_debug_mode():
    """動態切換終端機即時除錯日誌開關，免按儲存鈕即時生效，具備標準新舊值稽核日誌"""
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    operator = session.get('username', 'SystemUser') # 💡 精準撈取當前操作的管理員帳號
    
    try:
        data = request.get_json() or {}
        target_mode = bool(data.get('enable', False))
        
        import snmp_core
        # 📥 1. 趁著變更前，先抓取目前記憶體中的「舊除錯狀態」
        old_mode = getattr(snmp_core, 'GLOBAL_DEBUG_MODE', False)
        
        # 📝 2. 執行新狀態覆蓋
        snmp_core.GLOBAL_DEBUG_MODE = target_mode
        
        old_str = "開啟" if old_mode else "關閉"
        new_str = "開啟" if target_mode else "關閉"
        
        # 🌟 3. 智慧狀態比對：只有在開關真正被切換時，才觸發寫入審計日誌
        if old_mode != target_mode:
            details = f"變更終端機即時除錯日誌開關：由「{old_str}」調整為「{new_str}」。(操作來源 IP: {client_ip})"
            
            # 🛡️ 遵循三大鐵律：功能模組鎖定為 "系統設定"、補足 Who、來源 IP 與詳細新舊變更內容
            write_audit_log(operator, client_ip, "系統設定", f"【除錯雷達變更】{details}", "SUCCESS" if target_mode else "WARNING")
            
            from utils import log_info
            log_info(f"🐞 【除錯雷達】管理員 {operator} 於 {client_ip} {details}")
            
        return jsonify({"status": "success", "msg": f"已成功{new_str}即時除錯模式！"})
    except Exception as e:
        return jsonify({"status": "error", "msg": f"設定失敗: {str(e)}"})

@main_bp.route('/api/dashboard/stats', methods=['GET'])
def api_dashboard_stats():
    conn_config = get_db('config')
    dev_rows = conn_config.execute("SELECT ip, name, status, snmp_raw, cpu_load, visible FROM devices").fetchall()    
    conn_config.close()
    
    health = {'up': 0, 'down': 0, 'warning': 0, 'total': len(dev_rows)}
    device_map = {}
    for r in dev_rows:
        st = r['status']
        if st in health: health[st] += 1
        device_map[r['ip']] = {'name': r['name'], 'snmp_raw': r['snmp_raw']}
        
    time_limit = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() - 900))
    conn_hot = get_db('hot')
    cursor = conn_hot.execute('''SELECT ip, port_idx, in_bytes, out_bytes, strftime('%s', timestamp) as epoch FROM traffic_history WHERE timestamp >= ?''', (time_limit,))
    t_rows = cursor.fetchall()
    conn_hot.close()

    history = {}
    for r in t_rows:
        ip = r['ip']; p = str(r['port_idx'])
        if ip not in history: history[ip] = {}
        if p not in history[ip]: history[ip][p] = []
        history[ip][p].append({'in': r['in_bytes'], 'out': r['out_bytes'], 'epoch': int(r['epoch'])})

    traffic_list = []
    for ip, ports in history.items():
        raw_str = device_map.get(ip, {}).get('snmp_raw', '{}')
        try: raw_data = json.loads(raw_str)
        except: raw_data = {}
        if_names = raw_data[4] if isinstance(raw_data, list) and len(raw_data) > 4 else {}
        
        for p, records in ports.items():
            records.sort(key=lambda x: x['epoch'])
            if len(records) >= 2:
                prev = records[-2]; curr = records[-1]
                dt = curr['epoch'] - prev['epoch']
                if 0 < dt <= 600:
                    i_diff = curr['in'] - prev['in']
                    o_diff = curr['out'] - prev['out']
                    if i_diff < 0: i_diff = 0
                    if o_diff < 0: o_diff = 0
                    in_bps = round((i_diff * 8) / dt)
                    out_bps = round((o_diff * 8) / dt)
                    
                    if in_bps > 200000000000: in_bps = 0
                    if out_bps > 200000000000: out_bps = 0
                    
                    total_bps = in_bps + out_bps

                    if total_bps > 0:
                        p_name = clean_str(if_names.get(p, f"Port {p}"))
                        dev_name = device_map.get(ip, {}).get('name') or ip
                        traffic_list.append({'device': dev_name, 'ip': ip, 'port': p_name, 'in_bps': in_bps, 'out_bps': out_bps, 'total_bps': total_bps})
    traffic_list.sort(key=lambda x: x['total_bps'], reverse=True)

    # 取代 system.log，改為從 audit_hot.db 直接提取最新的 100 筆系統軌跡
    logs = []
    try:
        with DB_LOCKS['audit_hot']:
            conn_audit = get_db('audit_hot')
            log_rows = conn_audit.execute("SELECT timestamp, details FROM audit_logs ORDER BY timestamp DESC LIMIT 100").fetchall()
            conn_audit.close()
            logs = [f"[{r['timestamp']}] {r['details']}" for r in log_rows]
    except Exception:
        pass

    top_cpu = []
    for r in dev_rows:
        if r['visible'] == 0: continue  
        try:
            c = r['cpu_load']
            if c is not None and float(c) >= 0: top_cpu.append({'device': r['name'] or r['ip'], 'ip': r['ip'], 'cpu': float(c)})
        except: pass
    top_cpu.sort(key=lambda x: x['cpu'], reverse=True)
    top_cpu = top_cpu[:10]

    return jsonify({'success': True, 'health': health, 'all_traffic': traffic_list, 'logs': logs, 'top_cpu': top_cpu})

@main_bp.route('/api/ping/<ip>', methods=['GET'])
def api_ping_device_single(ip):
    """ 🟢 設備管理專用：單機 Ping 檢測 (寫入資料庫與日誌) """
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
    timeout_val = '1000' if platform.system().lower() == 'windows' else '1'
    command = ['ping', param, '1', timeout_param, timeout_val, ip]
    
    try:
        res = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        status = 'up' if res.returncode == 0 else 'down'
    except Exception:
        status = 'down'
        
    # 💡 檢測完畢後，直接更新 config.db 中的狀態
    with DB_LOCKS['config']:
        conn = get_db('config')
        conn.execute("UPDATE devices SET status = ? WHERE ip = ?", (status, ip))
        conn.commit()
        conn.close()
        
    reload_device_cache() # 💡 關鍵修正：單機 Ping 完立刻更新記憶體，避免覆寫！
        
    # 💡 寫入系統稽核紀錄
    details = f"管理員觸發單機 Ping 連線檢測。設備 IP: {ip}，檢測後狀態更新為: 【 {status.upper()} 】。(操作來源 IP: {client_ip})"
    write_audit_log("SystemUser", "修改設備設定", f"單機 Ping 檢測 ({ip})", "SUCCESS", f"【修改設備設定】{details}")
    log_info(f"🔄 【單機檢測】{details}")
    
    return jsonify({'ip': ip, 'status': status})

@main_bp.route('/api/scan_subnet', methods=['POST'])
def scan_subnet():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    acquired, active_name = try_acquire_scan("SNMP網段探索")
    if not acquired: return jsonify({'success': False, 'locked': True, 'message': f'系統忙碌中：目前「{active_name}」正在執行。'})
    import ipaddress
    try:
        data = request.json
        subnet_str = data.get('subnet', '').strip()
        raw_communities = data.get('community', 'public').strip()
        communities = [c.strip() for c in raw_communities.split(',') if c.strip()]
        if not communities: communities = ['public']
        
        # 💡 新增起手式：紀錄輸入的 Community
        start_details = f"管理員開始執行 SNMP 網段探索... 範圍：{subnet_str}，Community：{raw_communities} (操作來源 IP: {client_ip})"
        write_audit_log("SystemUser", "SNMP網段探索", subnet_str, "SUCCESS", f"【SNMP網段探索】{start_details}")
        log_info(f"🔍 【SNMP網段探索】{start_details}")

        try:
            network = ipaddress.IPv4Network(subnet_str, strict=False)
            ips = [str(ip) for ip in network.hosts()]
            if len(ips) > 512: return jsonify({'success': False, 'message': '網段過大，請限制在 /23 (510 台) 以內。'})
        except Exception: return jsonify({'success': False, 'message': f'無效的網段格式，請輸入如 192.50.1.0/24。'})

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        async def run_scan():
            sem = asyncio.Semaphore(50)
            async def bounded_scan(ip):
                async with sem:
                    snmpEngine = SnmpEngine()
                    descr, name, location = "", "", ""
                    successful_comm = ""
                    for comm in communities:
                        try:
                            transport = await UdpTransportTarget.create((ip, 161), timeout=0.6, retries=0)
                            err, stat, idx, varBinds = await get_cmd(snmpEngine, CommunityData(comm, mpModel=1), transport, ContextData(), ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0')), ObjectType(ObjectIdentity('1.3.6.1.2.1.1.5.0')), ObjectType(ObjectIdentity('1.3.6.1.2.1.1.6.0')))
                            if not err and not stat:
                                for varBind in varBinds:
                                    oid = str(varBind[0]); val = str(varBind[1]).replace('\r', '').replace('\n', ' | ')
                                    if '1.3.6.1.2.1.1.1.0' in oid: descr = val
                                    elif '1.3.6.1.2.1.1.5.0' in oid: name = val
                                    elif '1.3.6.1.2.1.1.6.0' in oid: location = val
                                if name and name != "無回應": successful_comm = comm; break 
                        except: pass
                    snmpEngine.close_dispatcher()
                    if name and name != "無回應":
                        brand, model_str = extract_brand_model(descr)
                        return {"ip": ip, "name": name, "level": 3, "community": successful_comm, "location": location, "visible": 1, "type": "交換器", "brand": brand, "model": model_str, "sys_descr": descr}
                    return None
            tasks = [bounded_scan(ip) for ip in ips]
            results = await asyncio.gather(*tasks)
            return [r for r in results if r is not None]

        discovered = loop.run_until_complete(run_scan())
        loop.close()
        
        # 💡 完成時同樣帶上 Community
        details = f"管理員發動 SNMP 網段探索。指定範圍：{subnet_str}，Community：{raw_communities}，共計成功發掘出 {len(discovered)} 台活躍設備。(操作來源 IP: {client_ip})"
        write_audit_log("SystemUser", "SNMP網段探索", subnet_str, "SUCCESS", f"【SNMP網段探索】{details}")
        log_info(f"✅ 【SNMP網段探索】{details}")
        
        return jsonify({'success': True, 'devices': discovered})
    except Exception as e:
        raw_comm = raw_communities if 'raw_communities' in locals() else "未知"
        write_audit_log("SystemUser", "SNMP網段探索", subnet_str if 'subnet_str' in locals() else "未知網段", "FAILED", f"【SNMP網段探索】發生錯誤: {str(e)}，Community: {raw_comm} (操作來源 IP: {client_ip})")
        return jsonify({'success': False, 'message': str(e)})
    finally: release_scan()

@main_bp.route('/api/settings/allowed_ips', methods=['GET', 'POST'])
def handle_allowed_ips_settings():
    import ipaddress
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    operator = session.get('username', 'SystemUser')
    
    if request.method == 'POST':
        data = request.get_json() or {}
        raw_ips = str(data.get('ips') or '').strip()
        raw_internal = str(data.get('flow_internal_nets') or '').strip() or '10.0.0.0/8, 172.16.0.0/12, 192.168.1.0/24'
        raw_exclude = str(data.get('flow_exclude_nets') or '').strip()

        def validate_cidrs(raw_str):
            valid = []; invalid = []
            for i in [x.strip() for x in raw_str.split(',') if x.strip()]:
                try:
                    if '/' in i: ipaddress.ip_network(i, strict=False)
                    else: ipaddress.ip_address(i)
                    valid.append(i)
                except: invalid.append(i)
            return valid, invalid
        
        v_ips, inv_ips = validate_cidrs(raw_ips)
        v_int, inv_int = validate_cidrs(raw_internal)
        v_exc, inv_exc = validate_cidrs(raw_exclude)
        
        if inv_ips or inv_int or inv_exc:
            return jsonify({'success': False, 'message': f'無效的 IP 或網段格式: {", ".join(inv_ips + inv_int + inv_exc)}'})
            
        final_ips, final_internal, final_exclude = ", ".join(v_ips), ", ".join(v_int), ", ".join(v_exc)
        
        with DB_LOCKS['config']:
            conn = get_db('config')
            try:
                old_ips_row = conn.execute("SELECT value FROM system_settings WHERE key='allowed_ips'").fetchone()
                old_internal_row = conn.execute("SELECT value FROM system_settings WHERE key='flow_internal_nets'").fetchone()
                old_exclude_row = conn.execute("SELECT value FROM system_settings WHERE key='flow_exclude_nets'").fetchone()

                old_ips = old_ips_row['value'] if old_ips_row else ''
                old_internal = old_internal_row['value'] if old_internal_row else '10.0.0.0/8, 172.16.0.0/12, 192.168.1.0/24'
                old_exclude = old_exclude_row['value'] if old_exclude_row else ''

                conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('allowed_ips', ?)", (final_ips,))
                conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('flow_internal_nets', ?)", (final_internal,))
                conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('flow_exclude_nets', ?)", (final_exclude,))
                conn.commit()
            except Exception as e:
                return jsonify({'success': False, 'message': f'資料庫寫入失敗: {str(e)}'}), 500
            finally:
                conn.close()
        
        changes = []
        if old_ips != final_ips: changes.append(f"登入白名單「{old_ips or '未設定'}」➔「{final_ips or '清空'}」")
        if old_internal != final_internal: changes.append(f"內網網段「{old_internal}」➔「{final_internal}」")
        if old_exclude != final_exclude: changes.append(f"排除網段「{old_exclude or '未設定'}」➔「{final_exclude or '清空'}」")

        if changes:
            details = f"變更網段防護邊界：{'，'.join(changes)}"
            write_audit_log(operator, client_ip, "系統設定", f"【網段異動】{details}", "SUCCESS")
            from utils import log_info
            log_info(f"⚙️ 【參數儲存】管理員 {operator} 於 {client_ip} {details}")
        
        return jsonify({'success': True, 'ips': final_ips, 'flow_internal_nets': final_internal, 'flow_exclude_nets': final_exclude})
    else:
        with DB_LOCKS['config']:
            conn = get_db('config')
            try:
                r_ips = conn.execute("SELECT value FROM system_settings WHERE key='allowed_ips'").fetchone()
                r_int = conn.execute("SELECT value FROM system_settings WHERE key='flow_internal_nets'").fetchone()
                r_exc = conn.execute("SELECT value FROM system_settings WHERE key='flow_exclude_nets'").fetchone()
            finally:
                conn.close()
        return jsonify({
            'success': True, 
            'ips': r_ips['value'] if r_ips else '',
            'flow_internal_nets': r_int['value'] if r_int else '10.0.0.0/8, 172.16.0.0/12, 192.168.1.0/24',
            'flow_exclude_nets': r_exc['value'] if r_exc else ''
        })

@main_bp.route('/api/settings/polling', methods=['GET', 'POST'])
@require_role([ROLE_ADMIN])
def handle_polling_settings():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    operator = session.get('username', 'SystemUser')
    with DB_LOCKS['config']:
        conn = get_db('config')
        if request.method == 'POST':
            new_val = safe_int(request.json.get('interval'), 3)
            old_row = conn.execute("SELECT value FROM system_settings WHERE key='polling_interval'").fetchone()
            old_val = safe_int(old_row['value'], 3) if old_row else 3
            conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('polling_interval', ?)", (str(new_val),))
            conn.commit(); conn.close()
            
            if new_val != old_val:
                details = f"變更效能與流量輪詢間隔：由 {old_val} 分鐘調整為 {new_val} 分鐘。"
                write_audit_log(operator, client_ip, "系統設定", f"【輪詢間隔變更】{details}", "SUCCESS")
            return jsonify({'success': True, 'interval': new_val})
        else:
            row = conn.execute("SELECT value FROM system_settings WHERE key='polling_interval'").fetchone()
            conn.close()
            return jsonify({'success': True, 'interval': safe_int(row['value'], 3) if row else 3})

@main_bp.route('/api/settings/toposcan', methods=['GET', 'POST'])
@require_role([ROLE_ADMIN])
def handle_toposcan_settings():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    operator = session.get('username', 'SystemUser')
    with DB_LOCKS['config']:
        conn = get_db('config')
        if request.method == 'POST':
            new_val = safe_int(request.json.get('interval'), 0)
            old_row = conn.execute("SELECT value FROM system_settings WHERE key='topo_scan_interval'").fetchone()
            old_val = safe_int(old_row['value'], 0) if old_row else 0
            conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('topo_scan_interval', ?)", (str(new_val),))
            conn.commit(); conn.close()
            
            if new_val != old_val:
                old_str = f"{old_val} 分鐘" if old_val > 0 else "完全關閉"
                new_str = f"{new_val} 分鐘" if new_val > 0 else "完全關閉"
                details = f"變更自動拓樸掃描排程週期：由「{old_str}」調整為「{new_str}」"
                write_audit_log(operator, client_ip, "系統設定", f"【拓樸排程變更】{details}", "SUCCESS")
            return jsonify({'success': True, 'interval': new_val})
        else:
            row = conn.execute("SELECT value FROM system_settings WHERE key='topo_scan_interval'").fetchone()
            conn.close()
            return jsonify({'success': True, 'interval': safe_int(row['value'], 0) if row else 0})

@main_bp.route('/api/settings/anomaly', methods=['GET', 'POST'])
@require_role([ROLE_ADMIN])
def handle_anomaly_settings():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    operator = session.get('username', 'SystemUser')
    with DB_LOCKS['config']:
        conn = get_db('config')
        if request.method == 'POST':
            new_val = safe_int(request.json.get('interval'), 5)
            old_row = conn.execute("SELECT value FROM system_settings WHERE key='anomaly_interval'").fetchone()
            old_val = safe_int(old_row['value'], 5) if old_row else 5
            conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('anomaly_interval', ?)", (str(new_val),))
            conn.commit(); conn.close()
            
            if new_val != old_val:
                details = f"變更全天候網絡異常偵測頻率：由 {old_val} 分鐘調整為 {new_val} 分鐘。"
                write_audit_log(operator, client_ip, "系統設定", f"【異常偵測頻率變更】{details}", "SUCCESS")
            return jsonify({'success': True, 'interval': new_val})
        else:
            row = conn.execute("SELECT value FROM system_settings WHERE key='anomaly_interval'").fetchone()
            conn.close()
            return jsonify({'success': True, 'interval': safe_int(row['value'], 5) if row else 5})

def perform_ntp_sync(servers_str, client_ip, trigger_type):
    import subprocess, platform, time, re
    success = False
    used_server = ""
    offset_info = ""
    error_reasons = set()

    start_time = time.time()
    for s in servers_str.split(','):
        s = s.strip()
        if not s: continue
        try:
            if platform.system().lower() == 'windows':
                cfg_res = subprocess.run(f'w32tm /config /manualpeerlist:"{s}" /syncfromflags:manual /update', shell=True, capture_output=True, text=True)
                res = subprocess.run('w32tm /resync', shell=True, capture_output=True, text=True)
                
                if res.returncode == 0:
                    success = True
                    used_server = s
                    break
                else:
                    err_text = (res.stderr + res.stdout).strip()
                    if "存取被拒" in err_text or "Access is denied" in err_text:
                        error_reasons.add("權限不足 (請以『系統管理員』身分啟動系統)")
                    elif "沒有服務" in err_text or "not started" in err_text.lower():
                        error_reasons.add("Windows Time 服務未啟動")
                    else:
                        error_reasons.add(f"連線失敗 ({s})")
            else:
                res = subprocess.run(['ntpdate', '-u', s], capture_output=True, text=True)
                if res.returncode == 0:
                    success = True
                    used_server = s
                    m = re.search(r'offset ([-0-9.]+) sec', res.stdout)
                    if m:
                        offset_info = f"偏差值 {m.group(1)} 秒"
                    break
                else:
                    error_reasons.add("執行 ntpdate 失敗")
        except Exception as e:
            error_reasons.add(str(e))

    elapsed = round(time.time() - start_time, 2)

    if success:
        msg = f"管理員執行【{trigger_type}】，成功向 NTP 伺服器【 {used_server} 】完成系統時間同步，耗時 {elapsed} 秒。"
        if offset_info: msg += f" (校正 {offset_info})"
        msg += f" (操作來源 IP: {client_ip})"
        
        # 💡 同樣將 emoji 放入 audit_log，並在 log_info 使用 [] 避開攔截
        write_audit_log("SystemUser", "修改系統設定", "系統時間同步", "SUCCESS", f"⏱️ 【修改系統設定】{msg}")
        log_info(f"⏱️ [NTP手動校時] {msg}")
        return True, f"成功向 {used_server} 校時 (耗時 {elapsed}s)"
    else:
        reason_str = "、".join(list(error_reasons)) if error_reasons else "所有伺服器皆無回應"
        msg = f"管理員執行【{trigger_type}】，嘗試向【 {servers_str} 】校時失敗。原因: {reason_str}。(操作來源 IP: {client_ip})"
        
        write_audit_log("SystemUser", "修改系統設定", "系統時間同步", "FAILED", f"⚠️ 【修改系統設定】{msg}")
        log_info(f"⚠️ [NTP手動校時] {msg}")
        return False, f"校時失敗: {reason_str}"

@main_bp.route('/api/settings/ntp', methods=['GET', 'POST'])
def handle_ntp_settings():
    import re
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    operator = session.get('username', 'SystemUser')
    
    if request.method == 'POST':
        data = request.get_json() or {}
        raw_servers = str(data.get('servers') or '').strip()
        new_interval = safe_int(data.get('interval'), 60)
        if new_interval < 1: new_interval = 1  
        if not raw_servers: raw_servers = 'watch.stdtime.gov.tw'
        
        server_list = [s.strip() for s in raw_servers.split(',') if s.strip()]
        valid_servers = []; invalid_servers = []
        for s in server_list:
            if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", s) or re.match(r"^(?=.{1,253}$)(?!.*\.\..*)(?!\..*)([a-zA-Z0-9-]{1,63}\.?)+[a-zA-Z0-9]{1,63}$", s):
                valid_servers.append(s)
            else: invalid_servers.append(s)
        
        if invalid_servers:
            return jsonify({'success': False, 'message': f'無法識別的 FQDN/IP 格式: {", ".join(invalid_servers)}'})
        final_servers = ", ".join(valid_servers)
        
        with DB_LOCKS['config']:
            conn = get_db('config')
            try:
                cur_s = conn.execute("SELECT value FROM system_settings WHERE key='ntp_servers'").fetchone()
                cur_i = conn.execute("SELECT value FROM system_settings WHERE key='ntp_interval'").fetchone()
                old_servers = cur_s['value'] if cur_s else 'watch.stdtime.gov.tw'
                old_interval = safe_int(cur_i['value'], 60) if cur_i else 60

                conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('ntp_servers', ?)", (final_servers,))
                conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('ntp_interval', ?)", (str(new_interval),))
                conn.commit()
            except Exception as e:
                return jsonify({'success': False, 'message': f'資料庫寫入失敗: {str(e)}'}), 500
            finally:
                conn.close()
        
        changes = []
        if old_servers != final_servers: changes.append(f"伺服器「{old_servers}」➔「{final_servers}」")
        if old_interval != new_interval: changes.append(f"同步週期「{old_interval}分」➔「{new_interval}分」")

        if changes:
            details = f"變更時間校時配置：{'，'.join(changes)}"
            write_audit_log(operator, client_ip, "系統設定", f"【NTP配置變更】{details}", "SUCCESS")
            from utils import log_info
            log_info(f"⚙️ 【參數儲存】管理員 {operator} 於 {client_ip} {details}")
        
        sync_ok, sync_msg = perform_ntp_sync(final_servers, client_ip, "儲存並立即校時")
        return jsonify({'success': True, 'interval': new_interval, 'servers': final_servers, 'sync_success': sync_ok, 'sync_msg': sync_msg})
    else:
        with DB_LOCKS['config']:
            conn = get_db('config')
            try:
                cur_s = conn.execute("SELECT value FROM system_settings WHERE key='ntp_servers'").fetchone()
                cur_i = conn.execute("SELECT value FROM system_settings WHERE key='ntp_interval'").fetchone()
                servers = cur_s['value'] if cur_s else 'watch.stdtime.gov.tw'
                interval = safe_int(cur_i['value'], 60) if cur_i else 60
            finally:
                conn.close()
        return jsonify({'success': True, 'servers': servers, 'interval': interval})

@main_bp.route('/api/settings/ntp/sync', methods=['POST'])
def manual_ntp_sync_api():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    with DB_LOCKS['config']:
        conn = get_db('config')
        cur_s = conn.execute("SELECT value FROM system_settings WHERE key='ntp_servers'").fetchone()
        servers = cur_s['value'] if cur_s else 'watch.stdtime.gov.tw'
        conn.close()

    sync_ok, sync_msg = perform_ntp_sync(servers, client_ip, "手動立即校時")
    return jsonify({'success': sync_ok, 'message': sync_msg})

@main_bp.route('/api/settings/ntfy', methods=['GET', 'POST'])
def handle_ntfy_settings():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    
    if request.method == 'POST':
        data = request.get_json() or {}
        new_url = str(data.get('ntfy_url', '')).strip()
        new_interval = str(data.get('ntfy_interval', '5')).strip()
        new_count = str(data.get('ntfy_count', '3')).strip()
        
        # 🌟 核心修正 1：只在純粹讀寫資料庫時加鎖，完成後在 finally 區塊立刻關閉解鎖！
        with DB_LOCKS['config']:
            conn = get_db('config')
            try:
                conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('ntfy_url', ?)", (new_url,))
                conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('ntfy_interval', ?)", (new_interval,))
                conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('ntfy_count', ?)", (new_count,))
                conn.commit()
            except Exception as e:
                return jsonify({'success': False, 'message': f'資料庫寫入失敗: {str(e)}'}), 500
            finally:
                conn.close() # 🛡️ 釋放資料庫檔案鎖
        
        # 🌟 核心修正 2：將寫入日誌移到 with 鎖的外側！完全根除重入型死鎖
        details = f"管理員更新了 Ntfy 推播主機配置。網址變更，重覆間隔: {new_interval}分鐘，最大推播: {new_count}次。(操作來源 IP: {client_ip})"
        write_audit_log("SystemUser", "修改系統設定", "Ntfy推播設定", "SUCCESS", f"【修改系統設定】{details}")
        log_info(f"⚙️ 【參數儲存】{details}")
        
        return jsonify({'success': True})
    else:
        # GET 請求：同樣進行連線釋放保護，並補齊前端所需的動態欄位
        with DB_LOCKS['config']:
            conn = get_db('config')
            try:
                enabled_row = conn.execute("SELECT value FROM system_settings WHERE key='ntfy_enabled'").fetchone()
                url_row = conn.execute("SELECT value FROM system_settings WHERE key='ntfy_url'").fetchone()
                interval_row = conn.execute("SELECT value FROM system_settings WHERE key='ntfy_interval'").fetchone()
                count_row = conn.execute("SELECT value FROM system_settings WHERE key='ntfy_count'").fetchone()
            finally:
                conn.close()
                
        return jsonify({
            'success': True, 
            'ntfy_enabled': (enabled_row['value'] == '1') if enabled_row else False,
            'ntfy_url': url_row['value'] if url_row else 'http://localhost:8080/your_topic',
            'ntfy_interval': interval_row['value'] if interval_row else '5',
            'ntfy_count': count_row['value'] if count_row else '3'
        })

@main_bp.route('/api/settings/audit', methods=['GET', 'POST'])
@require_role([ROLE_ADMIN])
def handle_audit_settings():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    operator = session.get('username', 'SystemUser')
    with DB_LOCKS['config']:
        conn = get_db('config')
        if request.method == 'POST':
            data = request.json or {}
            name_map = {'audit_engine_bg': '背景引擎日誌', 'audit_net_scan': '主動探測日誌', 'audit_ui_action': '介面行為日誌', 'audit_ui_view': '瀏覽調閱日誌'}
            cur = conn.execute("SELECT key, value FROM system_settings WHERE key IN ('audit_engine_bg', 'audit_net_scan', 'audit_ui_action', 'audit_ui_view')")
            current_settings = {r['key']: r['value'] for r in cur.fetchall()}
            
            status_changes = []
            for k in name_map.keys():
                if k in data:
                    new_val = '1' if data[k] else '0'
                    old_val = current_settings.get(k, '1' if k != 'audit_ui_view' else '0')
                    if new_val != old_val:
                        status_changes.append(f"「{name_map[k]}」➔ { '開啟' if new_val=='1' else '關閉' }")
                        conn.execute("UPDATE system_settings SET value = ? WHERE key = ?", (new_val, k))
            conn.commit(); conn.close()
            
            if status_changes:
                details = f"調整審計稽核日誌記錄層級：{', '.join(status_changes)}"
                write_audit_log(operator, client_ip, "系統設定", f"【稽核政策異動】{details}", "SUCCESS")
            return jsonify({'success': True, 'changed': bool(status_changes)})
        else:
            rows = conn.execute("SELECT key, value FROM system_settings WHERE key IN ('audit_engine_bg', 'audit_net_scan', 'audit_ui_action', 'audit_ui_view')").fetchall()
            conn.close()
            settings = {r['key']: (r['value'] == '1') for r in rows}
            return jsonify({'success': True, 'data': settings})

@main_bp.route('/api/settings/toggle_ntfy', methods=['POST'])
@require_role([ROLE_ADMIN])
def toggle_ntfy():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    operator = session.get('username', 'SystemUser')
    data = request.get_json() or {}
    enable = data.get('enable', True)
    target_val = '1' if enable else '0'
    with DB_LOCKS['config']:
        conn = get_db('config')
        conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('ntfy_enabled', ?)", (target_val,))
        conn.commit(); conn.close()
    
    status_str = "啟用" if enable else "關閉/暫停"
    write_audit_log(operator, client_ip, "系統設定", f"切換 Ntfy 告警推播功能開關為：【{status_str}】", "SUCCESS" if enable else "WARNING")
    return jsonify({"status": "success", "msg": f"🚀 Ntfy 告警推播服務已成功{status_str}！" if enable else "🔕 Ntfy 告警服務已暫停。"})

@main_bp.route('/api/settings/toggle_autobackup', methods=['POST'])
@require_role([ROLE_ADMIN])
def toggle_autobackup():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    operator = session.get('username', 'SystemUser')
    data = request.get_json() or {}
    enable = data.get('enabled', True)
    target_val = '1' if enable else '0'
    with DB_LOCKS['config']:
        conn = get_db('config')
        conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('autobackup_enabled', ?)", (target_val,))
        conn.commit(); conn.close()
    
    status_str = "啟用" if enable else "關閉/暫停"
    write_audit_log(operator, client_ip, "系統設定", f"切換每日交換器設定檔自動備份開關為：【{status_str}】", "SUCCESS" if enable else "WARNING")
    return jsonify({"status": "success", "msg": f"🚀 每日自動備份排程已成功{status_str}！" if enable else "🔕 自動備份排程已暫停。"})

@main_bp.route('/api/toggle_trap_service', methods=['POST'])
@require_role([ROLE_ADMIN])
def toggle_trap_service():
    import snmp_core
    data = request.get_json() or {}
    enable = data.get('enable', True)
    with DB_LOCKS['config']:
        conn = get_db('config')
        conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('trap_enabled', ?)", ('1' if enable else '0',))
        conn.commit(); conn.close()
    snmp_core.GLOBAL_TRAP_ENABLED = enable
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    operator = session.get('username', 'SystemUser')
    status_str = "啟用" if enable else "關閉/暫停"
    write_audit_log(operator, client_ip, "系統設定", f"切換 UDP 162 SNMP Trap 監聽引擎開關為：【{status_str}】", "SUCCESS" if enable else "WARNING")
    return jsonify({"status": "success", "msg": f"🚀 SNMP Trap 核心接收引擎已成功{status_str}！" if enable else "🔕 Trap 接收引擎已暫停。"})

@main_bp.route('/api/settings/toggle_rbac', methods=['POST'])
@require_role([ROLE_ADMIN])
def toggle_rbac_mode():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    operator = session.get('username', 'SystemUser')
    data = request.get_json() or {}
    enable = data.get('enabled', True)
    with DB_LOCKS['config']:
        conn = get_db('config')
        conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('rbac_enabled', ?)", ('1' if enable else '0',))
        conn.commit(); conn.close()
    status_str = "高安全合規角色驗證" if enable else "除錯繞過模式(Bypass)"
    write_audit_log(operator, client_ip, "系統設定", f"切換核心控制 RBAC 安全政策為：【{status_str}】", "SUCCESS" if enable else "WARNING")
    return jsonify({"status": "success", "msg": f"權限隔離策略已切換為：{status_str}"})

@main_bp.route('/api/devices', methods=['GET'])
def get_devices(): 
    return jsonify(read_db_devices())

@main_bp.route('/api/devices/bulk', methods=['POST'])
def bulk_save_devices():
    data = request.json
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    
    old_devs_list = read_db_devices()
    old_devs = {d['ip']: d for d in old_devs_list}

    validated_devices = []
    seen_ips = set()
    
    for d in data:
        ip = d.get('ip', '').strip()
        if not ip or ip in seen_ips: continue
        seen_ips.add(ip)
        
        existing_dev = old_devs.get(ip, {})
        current_status = existing_dev.get('status', 'up')
        
        validated_devices.append({
            'ip': ip, 
            'name': d.get('name', '').strip(), 
            'level': safe_int(d.get('level')), 
            'community': d.get('community', 'public').strip(), 
            'location': d.get('location', '').strip(), 
            'visible': safe_int(d.get('visible', 1), 1), 
            'type': d.get('type', '交換器').strip(), 
            'brand': d.get('brand', 'Unknown').strip(), 
            'model': d.get('model', '').strip(), 
            'is_poe': safe_int(d.get('is_poe', 0), 0),
            'has_sensor': safe_int(existing_dev.get('has_sensor', 0), 0),
            'status': current_status,
            # 🌟 核心修正：必須由舊資料中繼承密碼與自訂型態，防止被背景輪詢或網頁存檔洗成空白！
            'ssh_user': existing_dev.get('ssh_user', ''),
            'ssh_pass': existing_dev.get('ssh_pass', ''),
            'ssh_secret': existing_dev.get('ssh_secret', ''),
            'cli_type': existing_dev.get('cli_type', '')
        })

    with DB_LOCKS['config']:
        conn = get_db('config')
        if seen_ips:
            placeholders = ','.join(['?'] * len(seen_ips))
            conn.execute(f"DELETE FROM devices WHERE ip NOT IN ({placeholders})", list(seen_ips))
            conn.execute(f"DELETE FROM layout_slots WHERE ip NOT IN ({placeholders})", list(seen_ips))
        else:
            conn.execute("DELETE FROM devices"); conn.execute("DELETE FROM layout_slots")
        conn.commit(); conn.close()
        
    write_db_devices(validated_devices)
        
    for new_d in validated_devices:
        ip = new_d['ip']
        if ip not in old_devs:
            details = f"管理員新增設備資料。IP: {ip}，名稱: {new_d['name']}。(IP: {client_ip})"
            write_audit_log("SystemUser", "修改設備設定", f"新增設備 ({ip})", "SUCCESS", f"【修改設備設定】{details}")
        else:
            old_d = old_devs[ip]
            changes = []
            if old_d.get('name') != new_d.get('name'): changes.append(f"名稱由「{old_d.get('name','')}」改為「{new_d.get('name','')}」")
            if changes:
                details = f"管理員修改設備資料。IP: {ip}，異動：{'，'.join(changes)}。(IP: {client_ip})"
                write_audit_log("SystemUser", "修改設備設定", f"修改設備 ({ip})", "SUCCESS", f"【修改設備設定】{details}")

    return jsonify({'success': True})

@main_bp.route('/api/traffic/<ip>', methods=['GET'])
def api_traffic(ip):
    time_range = request.args.get('range', '15m')
    start_time = request.args.get('start')
    end_time = request.args.get('end')
    
    target_db = 'hot'
    diff_days = 0
    start_dt = end_dt = None
    
    if time_range == 'custom' and start_time and end_time:
        start_dt = start_time.replace('T', ' ')
        end_dt = end_time.replace('T', ' ')
        d1 = datetime.strptime(start_dt[:10], '%Y-%m-%d')
        d2 = datetime.strptime(end_dt[:10], '%Y-%m-%d')
        diff_days = (d2 - d1).days
        days_ago = (datetime.now() - d1).days
        
        if days_ago > 180: target_db = 'cold'
        elif days_ago > 30: target_db = 'warm'
    else:
        if time_range == '3y': time_delta = '-1095 days'; time_fmt = '%Y/%m'; target_db = 'cold'
        elif time_range == '1y': time_delta = '-365 days'; time_fmt = '%Y/%m/%d'; target_db = 'cold'
        elif time_range == '180d': time_delta = '-180 days'; time_fmt = '%Y/%m/%d'; target_db = 'warm'
        elif time_range == '30d': time_delta = '-30 days'; time_fmt = '%m/%d %H:%M'; target_db = 'hot'
        elif time_range == '7d': time_delta = '-7 days'; time_fmt = '%m/%d %H:%M'
        elif time_range == '24h': time_delta = '-24 hours'; time_fmt = '%m/%d %H:%M'
        elif time_range == '6h': time_delta = '-6 hours'; time_fmt = '%H:%M'
        elif time_range == '1h': time_delta = '-1 hours'; time_fmt = '%H:%M'
        elif time_range == '30m': time_delta = '-30 minutes'; time_fmt = '%H:%M'
        else: time_delta = '-15 minutes'; time_fmt = '%H:%M'

    conn = get_db(target_db)
    rates = {}
    
    if target_db == 'hot':
        if time_range == 'custom':
            time_fmt = '%m/%d %H:%M' if diff_days > 1 else '%H:%M'
            cursor = conn.execute(f'''SELECT port_idx, in_bytes, out_bytes, strftime('{time_fmt}', timestamp) as ts, strftime('%s', timestamp) as epoch FROM traffic_history WHERE ip = ? AND timestamp BETWEEN ? AND ? ORDER BY port_idx, timestamp ASC''', (ip, start_dt, end_dt))
        else:
            cursor = conn.execute(f'''SELECT port_idx, in_bytes, out_bytes, strftime('{time_fmt}', timestamp) as ts, strftime('%s', timestamp) as epoch FROM traffic_history WHERE ip = ? AND timestamp >= datetime('now', ?, 'localtime') ORDER BY port_idx, timestamp ASC''', (ip, time_delta))
            
        history = {}
        for r in cursor.fetchall():
            p = str(r['port_idx'])
            if p not in history: history[p] = []
            history[p].append({'in': r['in_bytes'], 'out': r['out_bytes'], 'ts': r['ts'], 'epoch': int(r['epoch'])})
        conn.close()

        for p, records in history.items():
            in_bps = []; out_bps = []; labels = []
            for i in range(1, len(records)):
                prev = records[i-1]; curr = records[i]
                let_dt = curr['epoch'] - prev['epoch']
                if 0 < let_dt <= 600: 
                    i_diff = max(0, curr['in'] - prev['in']); o_diff = max(0, curr['out'] - prev['out'])
                    in_val = min(round((i_diff * 8) / let_dt), 200000000000)
                    out_val = min(round((o_diff * 8) / let_dt), 200000000000)
                    labels.append(curr['ts']); in_bps.append(in_val); out_bps.append(out_val)
                    
            # 💡 核心優化：Python 動態智慧降採樣 (解決前端卡頓與圖表條碼化)
            if labels: 
                # 限制前端最多只畫約 250 個點
                bucket_size = max(1, len(labels) // 250) 
                
                d_labels = []; d_avg_in = []; d_max_in = []; d_avg_out = []; d_max_out = []
                
                for i in range(0, len(labels), bucket_size):
                    chunk_in = in_bps[i:i+bucket_size]
                    chunk_out = out_bps[i:i+bucket_size]
                    d_labels.append(labels[i])
                    d_avg_in.append(sum(chunk_in) // len(chunk_in))
                    d_max_in.append(max(chunk_in))
                    d_avg_out.append(sum(chunk_out) // len(chunk_out))
                    d_max_out.append(max(chunk_out))

                rates[p] = {
                    'labels': d_labels, 
                    'avg_in_bps': d_avg_in, 
                    'max_in_bps': d_max_in, 
                    'avg_out_bps': d_avg_out, 
                    'max_out_bps': d_max_out
                }
                
            # 💡 熱庫沒有分 AVG/MAX，所以將原始數據同時賦予這四個變數供前端畫圖
            if labels: rates[p] = {'labels': labels, 'avg_in_bps': in_bps, 'max_in_bps': in_bps, 'avg_out_bps': out_bps, 'max_out_bps': out_bps}
            
    else:
        time_fmt = '%Y/%m/%d %H:%M' if target_db == 'warm' else '%Y/%m/%d'
        if target_db == 'cold' and (diff_days > 365 or time_range in ['1y', '3y']):
            sql = f'''SELECT port_idx, strftime('%Y/%m/%d', timestamp) as ts, 
                             AVG(avg_in_bps) as avg_in_bps, MAX(max_in_bps) as max_in_bps, 
                             AVG(avg_out_bps) as avg_out_bps, MAX(max_out_bps) as max_out_bps 
                      FROM traffic_history WHERE ip = ? AND timestamp {f"BETWEEN '{start_dt}' AND '{end_dt}'" if time_range=='custom' else f">= datetime('now', '{time_delta}', 'localtime')"} 
                      GROUP BY port_idx, ts ORDER BY port_idx, ts ASC'''
        else:
            sql = f'''SELECT port_idx, strftime('{time_fmt}', timestamp) as ts, 
                             avg_in_bps, max_in_bps, avg_out_bps, max_out_bps 
                      FROM traffic_history WHERE ip = ? AND timestamp {f"BETWEEN '{start_dt}' AND '{end_dt}'" if time_range=='custom' else f">= datetime('now', '{time_delta}', 'localtime')"} 
                      ORDER BY port_idx, timestamp ASC'''
                      
        cursor = conn.execute(sql, (ip,))
        history = {}
        for r in cursor.fetchall():
            p = str(r['port_idx'])
            if p not in history: history[p] = {'labels': [], 'avg_in_bps': [], 'max_in_bps': [], 'avg_out_bps': [], 'max_out_bps': []}
            history[p]['labels'].append(r['ts'])
            history[p]['avg_in_bps'].append(r['avg_in_bps'])
            history[p]['max_in_bps'].append(r['max_in_bps'])
            history[p]['avg_out_bps'].append(r['avg_out_bps'])
            history[p]['max_out_bps'].append(r['max_out_bps'])
        conn.close()
            
        for p, d in history.items():
            if d['labels']: rates[p] = d

    return jsonify({'success': True, 'data': rates})

@main_bp.route('/api/traffic_summary', methods=['GET'])
def api_traffic_summary():
    conn = get_db('hot')
    time_limit = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() - 900))
    cursor = conn.execute('''SELECT ip, port_idx, in_bytes, out_bytes, strftime('%s', timestamp) as epoch FROM traffic_history WHERE timestamp >= ?''', (time_limit,))
    rows = cursor.fetchall(); conn.close()

    history = {}
    for r in rows:
        ip = r['ip']; p = str(r['port_idx'])
        if ip not in history: history[ip] = {}
        if p not in history[ip]: history[ip][p] = []
        history[ip][p].append({'in': r['in_bytes'], 'out': r['out_bytes'], 'epoch': int(r['epoch'])})

    summary = {}
    for ip, ports in history.items():
        summary[ip] = {}
        for p, records in ports.items():
            records.sort(key=lambda x: x['epoch'])
            if len(records) >= 2:
                prev = records[-2]; curr = records[-1]
                dt = curr['epoch'] - prev['epoch']
                if 0 < dt <= 600:
                    i_diff = curr['in'] - prev['in']; o_diff = curr['out'] - prev['out']
                    if i_diff < 0: i_diff = 0
                    if o_diff < 0: o_diff = 0
                    
                    in_val = round((i_diff * 8) / dt)
                    out_val = round((o_diff * 8) / dt)
                    
                    if in_val > 200000000000: in_val = 0
                    if out_val > 200000000000: out_val = 0
                    
                    summary[ip][p] = {'in_bps': in_val, 'out_bps': out_val}
                    
    return jsonify({'success': True, 'data': summary})

@main_bp.route('/api/topology', methods=['GET'])
def get_topology():
    acquired, active_name = try_acquire_scan("手動拓樸掃描")
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if not acquired: return jsonify({'nodes': [], 'edges': [], 'error': f'系統忙碌中：目前「{active_name}」正在執行，請稍後再試。'}), 409
    try:
        log_info("✋ 【手動操作】接收到前端觸發「重新掃描」請求...")
        devices = read_db_devices(); topo = discover_topology(devices)
        
        write_audit_log("SystemUser", "手動拓樸掃描", "全網連線拓樸圖", "SUCCESS", f"【手動拓樸掃描】手動發動全網鏈路深度探測成功！耗時 {topo['stats']['elapsed']} 秒，共撈取 {len(topo.get('nodes', []))} 節點。(操作來源 IP: {client_ip})")
        log_info(f"✅ 【手動操作】掃描完成！耗時 {topo['stats']['elapsed']} 秒。")
        return jsonify(topo)
    except Exception as e: 
        write_audit_log("SystemUser", "手動拓樸掃描", "全網連線拓樸圖", "FAILED", f"【手動拓樸掃描】掃描失敗: {str(e)} (操作來源 IP: {client_ip})")
        log_info(f"⚠️ 【手動操作】掃描失敗: {e}")
        return jsonify({'nodes': [], 'edges': [], 'error': str(e)}), 500
    finally: release_scan()

@main_bp.route('/api/topology/fast', methods=['GET'])
def get_topology_fast():
    conn = get_db('config')
    devs = conn.execute("SELECT * FROM devices WHERE visible=1").fetchall()
    eds = conn.execute("SELECT * FROM edges").fetchall(); conn.close()
    if not devs: return jsonify({'empty': True})
    color_map = {1: '#ff9999', 2: '#99ccff', 3: '#99ff99', 4: '#ffcc99', 5: '#e6e6fa', 6: '#f8d7da'}
    nodes = []
    for row in devs:
        d = dict(row)
        node_data = {
            'id': d['ip'], 
            'ip': d['ip'], 
            'sysName': d['name'], 
            'brand': d.get('brand') or 'Unknown', 
            'model': d.get('model') or '', 
            'location': d.get('location') or '', 
            'level': d['level'], 
            'shape': 'box', 
            'color': color_map.get(d['level'], '#e0e0e0'), 
            'sysDescr': d.get('sys_descr') or '無快取硬體資訊', 
            'status': d.get('status') if d.get('status') else 'up', 
            'snmp_raw': d.get('snmp_raw') or '{}',
            'is_poe': d.get('is_poe', 0),  # 💡 就是漏了這一行！把 PoE 狀態傳給前端！
            'has_sensor': d.get('has_sensor', 0)
        }
        if d.get('x') is not None and d.get('y') is not None: node_data['x'] = d['x']; node_data['y'] = d['y']
        nodes.append(node_data)
    edges_list = [{'id': e['id'], 'from': e['source'], 'to': e['target'], 'speed': e['speed'] or 1000, 'from_port': e['from_port'] or '未知', 'to_port': e['to_port'] or '未知'} for e in eds]
    return jsonify({'empty': False, 'nodes': nodes, 'edges': edges_list})

@main_bp.route('/api/backup/import/<fmt>', methods=['POST'])
def import_devices(fmt):
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    try:
        imported_list = []
        if fmt == 'json': imported_list = request.json
        elif fmt == 'csv':
            file = request.files.get('file')
            if not file: return jsonify({'success': False, 'message': '找不到上傳的檔案'}), 400
            stream = io.StringIO(file.stream.read().decode("utf-8-sig"), newline=None)
            reader = csv.DictReader(stream); imported_list = [row for row in reader]
        if not imported_list or not isinstance(imported_list, list): return jsonify({'success': False, 'message': '資料結構有誤，無法匯入'}), 400

        with DB_LOCKS['config']:
            conn = get_db('config'); conn.execute("DELETE FROM devices")
            for d in imported_list:
                if not d.get('ip'): continue
                conn.execute('''INSERT INTO devices (ip, name, level, community, location, visible, type, brand, model, sys_descr, x, y, status, snmp_raw, ssh_user, ssh_pass, ssh_secret, cli_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', (
                    str(d.get('ip')).strip(), str(d.get('name', '')).strip(), safe_int(d.get('level')), 
                    str(d.get('community', 'public')).strip(), str(d.get('location', '')).strip(), 
                    safe_int(d.get('visible', 1), 1), str(d.get('type', '交換器')).strip(), 
                    str(d.get('brand', 'Unknown')).strip(), str(d.get('model', '')).strip(), 
                    str(d.get('sys_descr', '')), float(d['x']) if d.get('x') not in (None, '') else None, 
                    float(d['y']) if d.get('y') not in (None, '') else None, str(d.get('status', 'up')), 
                    str(d.get('snmp_raw', '{}')), 
                    str(d.get('username', '')).strip(), str(d.get('password', '')).strip(), 
                    str(d.get('secret', '')).strip(), str(d.get('device_type', '')).strip() 
                ))
            conn.commit(); conn.close()
        
        # 🌟 核心修正 1：CSV 匯入硬碟後，必須「立刻」強制刷新記憶體快取，阻止背景輪詢用空資料覆蓋！
        reload_device_cache()
        
        write_audit_log("SystemUser", "修改設備設定", "回復配置備份", "SUCCESS", f"【修改設備設定】成功由外部上傳之 {fmt.upper()} 檔案強制覆蓋並回復 {len(imported_list)} 台設備之配置資料。(操作來源 IP: {client_ip})")
        log_info(f"📥 【手動操作】成功匯入/還原 {len(imported_list)} 台設備資料并刷新記憶體快取。")
        return jsonify({'success': True, 'message': f'成功導入 {len(imported_list)} 台設備資料！'})
    except Exception as e: 
        log_info(f"⚠️ 【手動操作】匯入資料失敗: {e}")
        return jsonify({'success': False, 'message': f'導入失敗：{str(e)}'}), 500

@main_bp.route('/api/scan_lldp', methods=['POST'])
def scan_lldp():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    acquired, active_name = try_acquire_scan("LLDP鄰居探索")
    if not acquired: return jsonify({'success': False, 'locked': True, 'message': f'系統忙碌中：目前「{active_name}」正在執行。'})
    try:
        # 💡 新增起手式稽核紀錄：誰、來源IP、執行畫面文字
        start_details = f"管理員開始執行 L1~L4 設備 LLDP 鄰居掃描... (操作來源 IP: {client_ip})"
        write_audit_log("SystemUser", "LLDP鄰居探索", "L1~L4鄰居骨幹", "SUCCESS", f"【LLDP鄰居探索】{start_details}")
        log_info(f"🌐 【LLDP探索】{start_details}")
        
        devices = read_db_devices(); l1_l4_devs = [d for d in devices if safe_int(d.get('level')) <= 4 and d.get('ip')]
        if not l1_l4_devs: return jsonify({'success': False, 'message': '清單中沒有啟用的層級 1~4 設備可供探索。'})

        loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop)
        async def fetch_all_lldp(devs):
            sem = asyncio.Semaphore(20); engine = SnmpEngine()
            async def fetch(d):
                async with sem:
                    full = await async_get_device_full_data(engine, d['ip'], d['community'])
                    return d['ip'], d['community'], full
            res = await asyncio.gather(*(fetch(d) for d in devs)); engine.close_dispatcher(); return res

        fetch_results = loop.run_until_complete(fetch_all_lldp(l1_l4_devs)); loop.close()
        discovered_dict = {}
        for ip, community, full_data in fetch_results:
            if not full_data or len(full_data) < 14: continue 
            lldp_sysnames = full_data[0] if isinstance(full_data[0], dict) else {}
            lldp_portdescs = full_data[1] if isinstance(full_data[1], dict) else {}
            lldp_portids = full_data[2] if isinstance(full_data[2], dict) else {}
            lldp_mgmtips = full_data[3] if isinstance(full_data[3], dict) else {}
            arp_table = full_data[13] if isinstance(full_data[13], dict) else {} 
            
            for suffix, sysname_val in lldp_sysnames.items():
                remote_sysname = str(sysname_val).strip('"').split('.')[0]
                if remote_sysname.lower() == 'none': remote_sysname = ''
                remote_ip = ''
                for mgmt_suffix, val in lldp_mgmtips.items():
                    if mgmt_suffix.startswith(suffix + '.'):
                        ip_parts = mgmt_suffix.split('.')
                        if len(ip_parts) >= 4: remote_ip = f"{ip_parts[-4]}.{ip_parts[-3]}.{ip_parts[-2]}.{ip_parts[-1]}"
                        break
                if not remote_ip or not is_valid_ipv4(remote_ip):
                    remote_port_desc = str(lldp_portdescs.get(suffix, '')).strip('"')
                    remote_port_id = str(lldp_portids.get(suffix, '')).strip('"')
                    desc_mac_clean = re.sub(r'[^a-fA-F0-9]', '', remote_port_desc).lower()
                    id_mac_clean = re.sub(r'[^a-fA-F0-9]', '', remote_port_id).lower()
                    for arp_key, arp_mac in arp_table.items():
                        arp_mac_clean = re.sub(r'[^a-fA-F0-9]', '', str(arp_mac)).lower()
                        if arp_mac_clean and len(arp_mac_clean) == 12 and (arp_mac_clean == desc_mac_clean or arp_mac_clean == id_mac_clean):
                            parts = arp_key.split('.')
                            if len(parts) >= 4: remote_ip = f"{parts[-4]}.{parts[-3]}.{parts[-2]}.{parts[-1]}"; break
                if not is_valid_ipv4(remote_ip): remote_ip = ''
                if remote_ip or remote_sysname:
                    unique_key = remote_ip if remote_ip else remote_sysname
                    if unique_key and unique_key not in discovered_dict:
                        guessed_type = "AP" if "ap" in remote_sysname.lower() or "kitchen" in remote_sysname.lower() or "n11" in remote_sysname.lower() else "交換器"
                        discovered_dict[unique_key] = {"ip": remote_ip, "name": remote_sysname, "level": 5, "community": community, "location": "自動探索", "visible": 1, "type": guessed_type, "brand": "Unknown", "model": "", "sys_descr": f"由 {ip} 發現"}
        discovered_list = list(discovered_dict.values())
        
        details = f"管理員執行 LLDP 鄰居探索。共計發掘出 {len(discovered_list)} 台潛在未接管之網路設備。(操作來源 IP: {client_ip})"
        write_audit_log("SystemUser", "LLDP鄰居探索", "L1~L4鄰居骨幹", "SUCCESS", f"【LLDP鄰居探索】{details}")
        log_info(f"✅ 【LLDP探索】{details}")
        
        return jsonify({'success': True, 'devices': discovered_list})
    finally: release_scan()

@main_bp.route('/api/anomalies', methods=['GET'])
def api_anomalies():
    try:
        today_str = time.strftime('%Y-%m-%d')
        with DB_LOCKS['config']:
            conn = get_db('config')
            conn.execute("INSERT OR IGNORE INTO anomaly_daily_stats (date, runs) VALUES (?, 0)", (today_str,))
            conn.execute("UPDATE anomaly_daily_stats SET runs = runs + 1 WHERE date = ?", (today_str,))
            row = conn.execute("SELECT runs FROM anomaly_daily_stats WHERE date = ?", (today_str,)).fetchone()
            runs = row['runs']; nodes = conn.execute("SELECT * FROM devices WHERE status != 'down'").fetchall()
            conn.commit(); conn.close()

        anomalies = []
        for node in nodes:
            if not node['snmp_raw'] or node['snmp_raw'] == '{}': continue
            try:
                raw = json.loads(node['snmp_raw']); ifNames = raw.get("4", {}); ifAliases = raw.get("9", {}); bpToIf = raw.get("11", {}); fdb1 = raw.get("10", {}); fdb2 = raw.get("12", {}) 
                lldp_ports = set()
                for lldp_idx in ["0", "1", "2", "3"]:
                    for key in raw.get(lldp_idx, {}).keys():
                        parts = key.split('.')
                        if len(parts) >= 2: lldp_ports.add(parts[-2]); lldp_ports.add(parts[-1])
                port_macs = {}
                def parse_fdb(fdb_dict, is_qbridge=False):
                    if not fdb_dict: return
                    for suffix, bp in fdb_dict.items():
                        if is_qbridge:
                            parts = suffix.split('.')
                            if len(parts) >= 7: mac = ":".join([f"{int(x):02x}" for x in parts[1:7]])
                            else: continue
                        else: mac = ":".join([f"{int(x):02x}" for x in suffix.split('.')])
                        if_idx = str(bpToIf.get(str(bp), bp))
                        if if_idx not in port_macs: port_macs[if_idx] = set()
                        port_macs[if_idx].add(mac)
                parse_fdb(fdb1, False); parse_fdb(fdb2, True)

                for if_idx, mac_set in port_macs.items():
                    mac_count = len(mac_set)
                    if mac_count < 3: continue 
                    name = ifNames.get(str(if_idx), f"Port {if_idx}").replace('"', '').strip(); name_lower = name.lower()
                    if any(x in name_lower for x in ['vlan', 'loop', 'cpu', 'tun', 'null', 'mgmt', 'lag', 'trk', 'po', 'bond']): continue
                    if str(if_idx) in lldp_ports: continue
                    alias = ifAliases.get(str(if_idx), "").replace('"', '').strip()
                    if mac_count >= 30: severity, type_str, desc = "danger", "迴圈先兆 / MAC風暴", f"異常海量 MAC ({mac_count}個)，極可能發生實體迴圈！"
                    elif mac_count >= 5: severity, type_str, desc = "warning", "私接交換器 (Hub)", f"學習到 {mac_count} 個 MAC，疑似私接家用分享器或 Hub。"
                    else: severity, type_str, desc = "info", "多設備串接", f"偵測到 {mac_count} 個 MAC，可能連接了 IP 電話或小會議室。"
                    anomalies.append({'ip': node['ip'], 'sysName': node['name'] or node['ip'], 'port': name, 'alias': alias, 'mac_count': mac_count, 'severity': severity, 'type': type_str, 'desc': desc})
            except Exception: continue
        anomalies.sort(key=lambda x: x['mac_count'], reverse=True)
        return jsonify({'success': True, 'data': anomalies, 'runs': runs})
    except Exception as e: return jsonify({'success': False, 'error': str(e)})

@main_bp.route('/api/scan_node/<ip>', methods=['POST'])
def api_scan_single_node(ip):
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    
    data = request.get_json(silent=True) or {}
    ssh_user = data.get('ssh_user', '').strip()
    ssh_pass = data.get('ssh_pass', '').strip()

    with DB_LOCKS['config']:
        conn = get_db('config')
        dev = conn.execute("SELECT * FROM devices WHERE ip=?", (ip,)).fetchone()
        conn.close()

    if not dev: return jsonify({'success': False, 'message': '資料庫找不到該設備'})

    dev_dict = dict(dev); community = dev_dict.get('community', 'public')
    loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop)
    engine = SnmpEngine()

    async def fetch():
        info = await async_get_device_info(engine, ip, community)
        sys_descr = info[0]
        full = await async_get_device_full_data(engine, ip, community, sys_descr, ssh_user, ssh_pass)
        return info, full

    try: 
        (sys_descr, sys_name, sys_location), full_data = loop.run_until_complete(fetch())
    except Exception as e: 
        return jsonify({'success': False, 'message': str(e)})
    finally: 
        engine.close_dispatcher(); loop.close()

    status = 'up'
    if not sys_name or sys_name == "無回應":
        if check_ping(ip): status = 'warning'
        else: status = 'down'
        sys_descr = '無回應' if not check_ping(ip) else '⚠️ SNMP 連線失敗 (Ping正常)'

    brand, model = extract_brand_model(sys_descr)
    snmp_raw = json.dumps(full_data, ensure_ascii=False) if full_data else "{}"

    poe_dict = {}
    if full_data and len(full_data) >= 22:
        for idx in [18, 19, 20]:
            if isinstance(full_data[idx], dict):
                for k, v in full_data[idx].items():
                    try:
                        port_idx = str(k).split('.')[-1]; mw = int(v)
                        if 500 < mw < 95000 and mw != 1500: 
                            poe_dict[port_idx] = max(poe_dict.get(port_idx, 0.0), round(mw / 1000.0, 1))
                    except: pass
        if isinstance(full_data[21], dict):
            for k, v in full_data[21].items():
                try:
                    port_idx = str(k).split('.')[-1]; w = float(v)
                    if w > 500: w_watts = w / 1000.0
                    elif w > 95.0: w_watts = w / 10.0
                    else: w_watts = w
                    if 0.1 <= w_watts < 100.0:
                        poe_dict[port_idx] = max(poe_dict.get(port_idx, 0.0), round(w_watts, 1))
                except: pass
                
    poe_data = json.dumps(poe_dict, ensure_ascii=False)
    
    has_sensor = 0
    if full_data and len(full_data) >= 32:
        for idx in [26, 29, 31]:
            if isinstance(full_data[idx], dict) and full_data[idx]: has_sensor = 1; break
        if not has_sensor and isinstance(full_data[30], dict):
            if any(str(k).endswith('.10') or str(k) == '10' for k in full_data[30].keys()):
                has_sensor = 1

    with DB_LOCKS['config']:
        conn = get_db('config')
        conn.execute('''UPDATE devices SET name=COALESCE(NULLIF(?,''), name), brand=COALESCE(NULLIF(?,'Unknown'), brand), model=COALESCE(NULLIF(?,''), model), sys_descr=?, status=?, snmp_raw=?, poe_data=?, has_sensor=?, location=COALESCE(NULLIF(?,''), location) WHERE ip=?''', (sys_name if sys_name != "無回應" else None, brand, model, sys_descr, status, snmp_raw, poe_data, has_sensor, sys_location if sys_location else None, ip))
        conn.commit(); conn.close()
        
    # 🌟 核心修正 2：單機掃描更新完，也立刻強刷記憶體變數
    reload_device_cache()

    # 🌟 核心修正 3：徹底清除舊有複製貼上留下的未定義變數死鎖 Bug，改回精準的單機掃描稽核紀錄
    write_audit_log("SystemUser", "修改設備設定", f"單機更新探測 ({ip})", "SUCCESS", f"【修改設備設定】管理員手工觸發單機 SNMP 重新探測。名稱更新為：{sys_name}，狀態：{status}。(操作來源 IP: {client_ip})")
    log_info(f"🔄 【單機檢測】設備 {ip} 重新探測完畢並同步更新快取。")
    return jsonify({'success': True, 'message': f'設備 {ip} 探測與資料同步成功！'})

@main_bp.route('/api/poe_cycle', methods=['POST'])
def api_poe_cycle():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    data = request.json; ip = data.get('ip'); port_idx = data.get('port_idx'); rw_community = data.get('rw_community')
    if not ip or not port_idx or not rw_community: return jsonify({'success': False, 'message': '缺少必要參數或密碼'})
    oid = f'1.3.6.1.2.1.105.1.1.1.3.1.{port_idx}'
    try:
        import asyncio
        from pysnmp.hlapi.v3arch.asyncio import SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity, set_cmd
        from pysnmp.proto.rfc1902 import Integer32
        async def do_snmp_set(target_oid, val):
            if hasattr(UdpTransportTarget, 'create'): transport = await UdpTransportTarget.create((ip, 161), timeout=2, retries=1)
            else: transport = UdpTransportTarget((ip, 161), timeout=2, retries=1)
            errorIndication, errorStatus, errorIndex, varBinds = await set_cmd(SnmpEngine(), CommunityData(rw_community, mpModel=1), transport, ContextData(), ObjectType(ObjectIdentity(target_oid), Integer32(val)))
            if errorIndication: return False, str(errorIndication)
            elif errorStatus: return False, errorStatus.prettyPrint()
            return True, "OK"
        def snmp_set(target_oid, val):
            loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop)
            try: return loop.run_until_complete(do_snmp_set(target_oid, val))
            finally: loop.close()
    except ImportError:
        try:
            from pysnmp.hlapi import SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity, setCmd
            from pysnmp.proto.rfc1902 import Integer32
            def snmp_set(target_oid, val):
                errorIndication, errorStatus, errorIndex, varBinds = next(setCmd(SnmpEngine(), CommunityData(rw_community, mpModel=1), UdpTransportTarget((ip, 161), timeout=2, retries=1), ContextData(), ObjectType(ObjectIdentity(target_oid), Integer32(val))))
                if errorIndication: return False, str(errorIndication)
                elif errorStatus: return False, errorStatus.prettyPrint()
                return True, "OK"
        except ImportError as e: return jsonify({'success': False, 'message': f'系統無法載入 pysnmp 核心引擎: {str(e)}'})
    try:
        success, msg = snmp_set(oid, 2)
        if not success: 
            write_audit_log("SystemUser", "PoE 供電控制", f"{ip} [Port {port_idx}]", "FAILED", f"【PoE供電控制】執行重啟 PoE 指令遭交換器拒絕：{msg} (操作來源 IP: {client_ip})")
            return jsonify({'success': False, 'message': f'斷電指令被拒絕: {msg} (請確認密碼是否具備寫入權限)'})
        time.sleep(3)
        success, msg = snmp_set(oid, 1)
        if not success: 
            write_audit_log("SystemUser", "PoE 供電控制", f"{ip} [Port {port_idx}]", "FAILED", f"【PoE供電控制】回復 PoE 電源供應失敗：{msg} (操作來源 IP: {client_ip})")
            return jsonify({'success': False, 'message': f'重新供電失敗: {msg} (請手動檢查交換器狀態)'})
            
        write_audit_log("SystemUser", "PoE 供電控制", f"{ip} [Port {port_idx}]", "SUCCESS", f"【PoE供電控制】人為強制重啟 PoE 孔位電源，3秒微斷電程序順利完工。(操作來源 IP: {client_ip})")
        return jsonify({'success': True, 'message': 'PoE 斷電並重啟成功！'})
    except Exception as e: 
        return jsonify({'success': False, 'message': f'API 執行期發生未知錯誤: {str(e)}'})

@main_bp.route('/api/audit-logs/search', methods=['POST'])
def search_audit_logs_api():
    try:
        from database import get_db, DB_LOCKS
        
        data = request.json or {}
        keyword = data.get('keyword', '').strip()
        device = data.get('device', '').strip()  # 💡 新增：接收設備過濾參數
        role = data.get('role', '')
        action = data.get('action', '')
        status = data.get('status', '')
        time_range = data.get('time_range', '15m')

        query = "SELECT * FROM audit_logs WHERE 1=1"
        params = []

        if keyword:
            query += " AND (username LIKE ? OR action LIKE ? OR target LIKE ? OR details LIKE ?)"
            params.extend([f"%{keyword}%"] * 4)
            
        if device:  # 💡 新增：精準比對影響範圍 (target) 中是否包含該設備 IP
            query += " AND target LIKE ?"
            params.append(f"%{device}%")
            
        if role:
            query += " AND username = ?"
            params.append(role)
        if action:
            query += " AND action = ?"
            params.append(action)
        if status:
            query += " AND result = ?"
            params.append(status)

        modifier_map = {
            '15m': '-15 minutes', '30m': '-30 minutes', '1h': '-1 hours',
            '6h': '-6 hours', '24h': '-24 hours', '7d': '-7 days', '30d': '-30 days'
        }
        if time_range and time_range != 'all' and time_range in modifier_map:
            mod = modifier_map[time_range]
            query += f" AND timestamp >= datetime((SELECT MAX(timestamp) FROM audit_logs), '{mod}')"

        limit_val = data.get('limit', 2000)
        try:
            limit_val = int(limit_val)
        except ValueError:
            limit_val = 2000

        query += f" ORDER BY timestamp DESC LIMIT {limit_val}"

        def adjust_tz(ts_str):
            try:
                from datetime import datetime, timedelta
                dt = datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S')
                dt += timedelta(hours=8) # 💡 確保這裡有加回 8 小時
                return dt.strftime('%Y-%m-%d %H:%M:%S')
            except:
                return ts_str

        with DB_LOCKS['audit_hot']:
            conn = get_db('audit_hot')
            cur = conn.execute(query, params)
            
            rows = []
            for r in cur.fetchall():
                d = dict(r)
                if 'timestamp' in d and d['timestamp']:
                    d['timestamp'] = adjust_tz(d['timestamp'])
                rows.append(d)
                
            conn.close()

        return jsonify({'success': True, 'data': rows})
        
    except Exception as e:
        print(f"⚠️ 日誌檢索崩潰: {e}")
        return jsonify({'success': False, 'error': str(e)})

@main_bp.route('/api/audit-logs/export', methods=['GET'])
def export_audit_logs_api():
    import csv
    import io
    import json
    import time
    from flask import send_file
    
    keyword = request.args.get('keyword', '')
    action = request.args.get('action', '')
    result = request.args.get('result', '')
    username = request.args.get('username', '')
    start_time = request.args.get('start_time', '')
    end_time = request.args.get('end_time', '')
    fmt = request.args.get('format', 'csv')     
    
    logs, total = query_advanced_audit_logs(keyword, action, result, username, start_time, end_time, 1, 999999)
    output = io.StringIO()
    
    timestamp_str = time.strftime("%Y%m%d_%H%M%S")

    def adjust_tz(ts_str):
        try:
            from datetime import datetime, timedelta
            dt = datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S')
            dt += timedelta(hours=8) # 💡 確保這裡有加回 8 小時
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except:
            return ts_str
            
    for log in logs:
        if 'ts' in log and log['ts']:
            log['ts'] = adjust_tz(log['ts'])
    
    if fmt == 'json':
        json.dump(logs, output, ensure_ascii=False, indent=4)
        export_filename = f'Audit_Logs_{timestamp_str}.json'
        mimetype = 'application/json'
    
    elif fmt == 'txt':
        for log in logs:
            output.write(f"[{log['ts']}] [{log['username']}] [{log['result']}] {log['action']} | 目標: {log['target']} | 詳細: {log['details']}\n")
        export_filename = f'Audit_Logs_{timestamp_str}.txt'
        mimetype = 'text/plain'
        
    else: 
        output.write('\ufeff') 
        writer = csv.writer(output)
        writer.writerow(['軌跡時間 (Timestamp)', '操作權限 (User)', '行為模組 (Action)', '影響範圍 (Target)', '狀態 (Status)', '詳細內容 (Details)'])
        for log in logs:
            writer.writerow([log['ts'], log['username'], log['action'], log['target'], log['result'], log['details']])
        export_filename = f'Audit_Logs_{timestamp_str}.csv'
        mimetype = 'text/csv'

    output.seek(0)
    
    from database import write_audit_log
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    write_audit_log("SystemUser", "前端介面操作", f"匯出系統日誌 ({fmt.upper()})", "SUCCESS", f"【前端介面操作】人員依據過濾條件，匯出了共 {total} 筆系統運作與稽核日誌。(操作來源 IP: {client_ip})")
    
    return send_file(io.BytesIO(output.getvalue().encode('utf-8-sig')), mimetype=mimetype, as_attachment=True, download_name=export_filename)

@main_bp.route('/api/audit-logs/client', methods=['POST'])
def log_client_action_api():
    import time
    try:
        data = request.json
        action = data.get('action', '前端操作')
        target = data.get('target', 'UI 元件')
        details = data.get('details', '')
        username = data.get('username', 'SystemUser')
        
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        
        if action == "前端純瀏覽軌跡": 
            action = "前端瀏覽軌跡"

        now_str = time.strftime('%Y-%m-%d %H:%M:%S')
        icon = "🖱️" if "操作" in action or "軌跡" in action else "👀"
        
        full_message = f"【{action}】 {target} - {details} (觀看來源 IP: {client_ip})"
        print(f"[{now_str}] {icon} {full_message}")

        from database import write_audit_log
        write_audit_log(username, action, target, "SUCCESS", full_message)
        
        return jsonify({'success': True})
    except Exception as e:
        print(f"⚠️ 前端日誌寫入失敗: {e}")
        return jsonify({'success': False, 'error': str(e)})

# ==========================================
# 🌟 拓樸版面與「視角 (Viewport)」記憶引擎
# ==========================================
@main_bp.route('/api/topology/slots/save', methods=['POST'])
def save_to_slot():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    data = request.json
    slot_id = data.get('slot')
    positions = data.get('positions')
    view = data.get('view') # 💡 接收前端傳來的視角資訊 (平移座標與縮放比例)
    
    with DB_LOCKS['config']:
        conn = get_db('config')
        conn.execute("DELETE FROM layout_slots WHERE slot_id = ?", (slot_id,))
        for ip, coords in positions.items(): 
            conn.execute("INSERT INTO layout_slots (slot_id, ip, x, y) VALUES (?, ?, ?, ?)", (slot_id, ip, coords['x'], coords['y']))
            conn.execute("UPDATE devices SET x=?, y=? WHERE ip=?", (coords['x'], coords['y'], ip))
            
        # 💡 將視角資訊存入全域系統設定庫中
        if view:
            import json
            conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES (?, ?)", (f'slot_{slot_id}_view', json.dumps(view)))
            
        conn.commit()
        conn.close()
    
    write_audit_log("SystemUser", "修改設備設定", f"儲存拓樸版面 {slot_id}", "SUCCESS", f"【修改設備設定】手動調整拓樸座標與視角，並將目前排版成功記憶保存至槽位 【 版面 {slot_id} 】。(操作來源 IP: {client_ip})")
    log_info(f"💾 【手動操作】使用者已儲存版面 {slot_id} (包含視角)。")
    return jsonify({'success': True, 'message': f'排版與視角已成功記憶至版面 {slot_id}'})

@main_bp.route('/api/topology/slots/load', methods=['POST'])
def load_from_slot():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    slot_id = request.json.get('slot')
    conn = get_db('config')
    
    cursor = conn.execute("SELECT * FROM layout_slots WHERE slot_id = ?", (slot_id,))
    rows = cursor.fetchall()
    if not rows: 
        conn.close()
        return jsonify({'success': False, 'message': f'版面 {slot_id} 目前是空的！'})
        
    conn.execute("UPDATE devices SET x=NULL, y=NULL")
    positions = {}
    for row in rows:
        conn.execute("UPDATE devices SET x=?, y=? WHERE ip=?", (row['x'], row['y'], row['ip']))
        positions[row['ip']] = {'x': row['x'], 'y': row['y']}
        
    # 💡 讀取該版面的專屬視角記憶
    view_row = conn.execute("SELECT value FROM system_settings WHERE key=?", (f'slot_{slot_id}_view',)).fetchone()
    view_data = None
    if view_row:
        import json
        try: view_data = json.loads(view_row['value'])
        except: pass
        
    conn.commit()
    conn.close()
    
    write_audit_log("SystemUser", "修改設備設定", f"載入拓樸版面 {slot_id}", "SUCCESS", f"【修改設備設定】自資料庫中成功提取並覆蓋載入 【 版面 {slot_id} 】 的歷史排版與視角。(操作來源 IP: {client_ip})")
    log_info(f"📂 【手動操作】使用者已載入版面 {slot_id}。")
    return jsonify({'success': True, 'positions': positions, 'view': view_data})

@main_bp.route('/api/topology/slots/clear', methods=['POST'])
def clear_slots():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    data = request.get_json(silent=True) or {}
    slot_id = data.get('slot', 'all')
    
    with DB_LOCKS['config']:
        conn = get_db('config')
        if slot_id != 'all':
            conn.execute("DELETE FROM layout_slots WHERE slot_id = ?", (slot_id,))
            conn.execute("DELETE FROM system_settings WHERE key = ?", (f'slot_{slot_id}_view',)) # 💡 同步刪除單一視角
            msg = f'版面 {slot_id} 的記憶與視角已清除！'
        else:
            conn.execute("DELETE FROM layout_slots")
            conn.execute("DELETE FROM system_settings WHERE key LIKE 'slot_%_view'") # 💡 同步刪除所有視角
            msg = '所有版面記憶與視角已徹底清空！'
        conn.commit()
        conn.close()
    
    write_audit_log("SystemUser", "修改設備設定", f"清除版面記憶 ({slot_id})", "SUCCESS", f"【修改設備設定】執行清理指令，將儲存於資料庫中之版面與視角記憶 ({slot_id}) 徹底抹除。(操作來源 IP: {client_ip})")
    log_info(f"🗑️ 【手動操作】使用者已清除版面記憶 ({slot_id})。")
    return jsonify({'success': True, 'message': msg})

@main_bp.route('/api/topology/slots/status', methods=['GET'])
def get_slots_status():
    conn = get_db('config')
    cursor = conn.execute("SELECT slot_id, COUNT(*) as count FROM layout_slots GROUP BY slot_id")
    status = {row['slot_id']: row['count'] for row in cursor.fetchall()}; conn.close()
    return jsonify(status)

@main_bp.route('/api/topology/positions/reset', methods=['POST'])
def reset_positions():
    with DB_LOCKS['config']:
        conn = get_db('config'); conn.execute("UPDATE devices SET x=NULL, y=NULL")
        conn.commit(); conn.close()
    log_info(f"🧹 【手動操作】使用者已重置目前畫面的節點位置。")
    return jsonify({'success': True})
    
@main_bp.route('/api/metrics/<ip>', methods=['GET'])
def api_metrics(ip):
    try:
        time_range = request.args.get('range', '15m')
        start_time = request.args.get('start')
        end_time = request.args.get('end')
        
        target_db = 'hot'
        
        if time_range == 'custom' and start_time and end_time:
            start_dt = start_time.replace('T', ' ')
            end_dt = end_time.replace('T', ' ')
            days_ago = (datetime.now() - datetime.strptime(start_dt[:10], '%Y-%m-%d')).days
            if days_ago > 180: target_db = 'cold'
            elif days_ago > 30: target_db = 'warm'
        else:
            if time_range == '7d': time_delta = '-7 days'; time_fmt = '%m/%d %H:%M'
            elif time_range == '24h': time_delta = '-24 hours'; time_fmt = '%m/%d %H:%M'
            elif time_range == '6h': time_delta = '-6 hours'; time_fmt = '%H:%M'
            elif time_range == '1h': time_delta = '-1 hours'; time_fmt = '%H:%M'
            elif time_range == '30m': time_delta = '-30 minutes'; time_fmt = '%H:%M'
            else: time_delta = '-15 minutes'; time_fmt = '%H:%M'
            
        conn = get_db(target_db)
        
        if target_db == 'hot':
            if time_range == 'custom':
                time_fmt = '%m/%d %H:%M'
                sql = f"SELECT cpu, memory, poe_w, temp_c, strftime('{time_fmt}', timestamp) as ts FROM metrics_history WHERE ip = ? AND timestamp BETWEEN ? AND ? ORDER BY timestamp ASC"
                cursor = conn.execute(sql, (ip, start_dt, end_dt))
            else:
                cursor = conn.execute(f"SELECT cpu, memory, poe_w, temp_c, strftime('{time_fmt}', timestamp) as ts FROM metrics_history WHERE ip = ? AND timestamp >= datetime('now', ?, 'localtime') ORDER BY timestamp ASC", (ip, time_delta))
        else:
            # 溫/冷庫取用預先算好的平均值
            time_fmt = '%Y/%m/%d %H:%M' if target_db == 'warm' else '%Y/%m/%d'
            sql = f"SELECT cpu, memory, poe_w, temp_c, strftime('{time_fmt}', timestamp) as ts FROM metrics_history WHERE ip = ? AND timestamp BETWEEN ? AND ? ORDER BY timestamp ASC"
            cursor = conn.execute(sql, (ip, start_dt, end_dt))
            
        rows = cursor.fetchall(); conn.close()

        labels = [r['ts'] for r in rows]
        cpu_data = [round(r['cpu'] if r['cpu'] is not None else 0, 1) for r in rows]
        mem_data = [round(r['memory'] if r['memory'] is not None else 0, 1) for r in rows]
        poe_data = [round(r['poe_w'] if r['poe_w'] is not None else 0, 1) for r in rows]
        temp_data = [round(r['temp_c'] if r['temp_c'] is not None else 0, 1) for r in rows]
        
        return jsonify({'success': True, 'labels': labels, 'cpu': cpu_data, 'memory': mem_data, 'poe': poe_data, 'temp': temp_data})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# =========================================================================
# 🔍 動態獲取稽核日誌「過濾器選單」 (包含行為模組與操作權限)
# =========================================================================
@main_bp.route('/api/audit-logs/filters', methods=['GET'])
def get_audit_filters():
    from database import get_db, DB_LOCKS
    try:
        with DB_LOCKS['config']:
            conn = get_db('config')
            conn.execute("CREATE TABLE IF NOT EXISTS audit_action_dict (action TEXT PRIMARY KEY, category TEXT)")
            conn.execute("CREATE TABLE IF NOT EXISTS audit_role_dict (role TEXT PRIMARY KEY)")
            
            # 💡 強制救援：每次載入網頁時，快速從熱庫把「曾經漏掉」的資料同步進靜態字典
            try:
                with DB_LOCKS['audit_hot']:
                    conn_hot = get_db('audit_hot')
                    hot_acts = conn_hot.execute("SELECT DISTINCT action FROM audit_logs WHERE action IS NOT NULL").fetchall()
                    hot_roles = conn_hot.execute("SELECT DISTINCT username FROM audit_logs WHERE username IS NOT NULL").fetchall()
                    conn_hot.close()
                
                # 同步漏掉的行為模組
                for r in hot_acts:
                    act = r['action']
                    cat = "✋ 前端與人為操作"
                    if "HTTP" in act: cat = "🌐 系統通訊"
                    elif any(x in act for x in ["輪詢", "排程", "引擎", "快取", "清道夫", "背景", "同步", "自動"]): cat = "⚙️ 背景自動引擎"
                    elif any(x in act for x in ["掃描", "探索", "Ping", "連線"]): cat = "📡 網路主動探測"
                    elif any(x in act for x in ["推播", "告警", "通知"]): cat = "🔔 系統主動告警"
                    conn.execute("INSERT OR IGNORE INTO audit_action_dict (action, category) VALUES (?, ?)", (act, cat))
                
                # 同步漏掉的操作權限
                for r in hot_roles:
                    conn.execute("INSERT OR IGNORE INTO audit_role_dict (role) VALUES (?)", (r['username'],))
                conn.commit()
            except Exception as e:
                print(f"同步字典失敗: {e}")

            # 極速讀取靜態分類字典
            act_rows = conn.execute("SELECT action, category FROM audit_action_dict ORDER BY category DESC, action ASC").fetchall()
            role_rows = conn.execute("SELECT role FROM audit_role_dict ORDER BY role ASC").fetchall()
            conn.close()

        # 打包行為模組 (分群)
        grouped_actions = {}
        for r in act_rows:
            cat = r['category']
            if cat not in grouped_actions: grouped_actions[cat] = []
            grouped_actions[cat].append(r['action'])

        # 打包操作權限
        roles = [r['role'] for r in role_rows]

        return {"success": True, "grouped_actions": grouped_actions, "roles": roles}
    except Exception as e:
        return {"success": False, "message": str(e)}
        
# ========================================================
# 🌟 殺手級功能：手動拓樸連線 (Manual Links) 與網孔快取
# ========================================================
@main_bp.route('/api/device/ports', methods=['GET'])
def api_device_ports():
    ip = request.args.get('ip')
    comm = request.args.get('comm', 'public')
    if not ip: return jsonify({'status': 'error', 'message': 'Missing IP'})
    
    # 1. 優先從 config.db 讀取快取 (秒開)
    with DB_LOCKS['config']:
        conn = get_db('config')
        rows = conn.execute("SELECT port_idx, port_name, speed FROM device_ports WHERE ip=?", (ip,)).fetchall()
        if rows:
            ports = [{'idx': r['port_idx'], 'name': r['port_name'], 'speed': r['speed']} for r in rows]
            conn.close()
            return jsonify({'status': 'ok', 'source': 'db_cache', 'ports': ports})
        conn.close()
    
    # 2. 如果沒有快取，發起獨立的 SNMP 掃描 (改用極速 bulk_cmd)
    try:
        import asyncio
        from pysnmp.hlapi.v3arch.asyncio import SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity, bulk_cmd
        
        async def walk_ports():
            engine = SnmpEngine()
            # 💡 確保使用 mpModel=1 (SNMP v2c) 才能支援 bulk_cmd
            auth = CommunityData(comm, mpModel=1) 
            transport = await UdpTransportTarget.create((ip, 161), timeout=2.0, retries=2)
            ctx = ContextData()
            names = {}
            
            # ifName 的 OID 根目錄
            base_oid = '1.3.6.1.2.1.31.1.1.1.1' 
            current_oid = ObjectType(ObjectIdentity(base_oid))
            
            # 💡 使用 bulk_cmd，nonRepeaters=0, maxRepetitions=50 (一次抓 50 個 Port，極大化效能)
            while True:
                err, stat, idx, binds = await bulk_cmd(engine, auth, transport, ctx, 0, 50, current_oid)
                if err or stat or not binds: break
                
                # 遍歷這 50 個結果
                last_oid = None
                for name_oid, val in binds:
                    str_oid = str(name_oid)
                    # 如果已經超出 ifName 的範圍，代表抓完了，直接提早收工
                    if not str_oid.startswith(base_oid):
                        return names
                    
                    port_idx = str_oid.split('.')[-1]
                    names[port_idx] = str(val)
                    last_oid = name_oid
                
                # 將下一次 BulkWalk 的起點設為這一批的最後一個 OID
                if last_oid:
                    current_oid = ObjectType(ObjectIdentity(last_oid))
                else:
                    break
                    
            return names

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        names = loop.run_until_complete(walk_ports())
        loop.close()
        
        if not names: return jsonify({'status': 'error', 'message': '無法取得實體連接埠 (設備無回應或無 OID)'})

        # 3. 掃描成功，寫回資料庫快取
        with DB_LOCKS['config']:
            conn = get_db('config')
            ports = []
            for idx, name in names.items():
                if 'vlan' in name.lower() or 'loop' in name.lower() or 'null' in name.lower() or 'cpu' in name.lower(): continue # 過濾虛擬埠
                ports.append({'idx': idx, 'name': name, 'speed': 1000})
                conn.execute("INSERT OR REPLACE INTO device_ports (ip, port_idx, port_name, speed) VALUES (?, ?, ?, ?)", (ip, idx, name, 1000))
            conn.commit()
            conn.close()
            
        return jsonify({'status': 'ok', 'source': 'snmp_live', 'ports': ports})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@main_bp.route('/api/manual_links', methods=['POST'])
@require_role([ROLE_ADMIN, ROLE_OPERATOR]) # 🛡️ 加上這行：Admin 和 維運員 可以存取
def api_manual_links_post():
    data = request.json
    nA, pA = data.get('node_a'), data.get('port_a')
    nB, pB = data.get('node_b'), data.get('port_b')
    if not all([nA, pA, nB, pB]): return jsonify({'status': 'error', 'message': '參數不完整'})
    
    with DB_LOCKS['config']:
        conn = get_db('config')
        conn.execute("INSERT INTO manual_links (node_a, port_a, node_b, port_b) VALUES (?, ?, ?, ?)", (nA, pA, nB, pB))
        conn.commit()
        conn.close()
    return jsonify({'status': 'ok'})

@main_bp.route('/api/settings/get', methods=['GET'])
def api_settings_get():
    with DB_LOCKS['config']:
        conn = get_db('config')
        row = conn.execute("SELECT value FROM system_settings WHERE key='rbac_enabled'").fetchone()
        conn.close()
    # 若資料庫無設定，預設為開啟 (True)
    rbac_enabled = (row['value'] == '1') if row else True 
    return jsonify({'success': True, 'rbac_enabled': rbac_enabled})

# ========================================================
# 👥 RBAC 帳號與權限管理 API (僅限 Admin)
# ========================================================
@main_bp.route('/api/users', methods=['GET'])
@require_role([ROLE_ADMIN])
def get_users():
    with DB_LOCKS['config']:
        conn = get_db('config')
        rows = conn.execute("SELECT id, username, role, status, created_at FROM users").fetchall()
        conn.close()
    return jsonify({'success': True, 'data': [dict(r) for r in rows]})

@main_bp.route('/api/users', methods=['POST'])
@require_role([ROLE_ADMIN])
def add_user():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    role = data.get('role', 'operator')
    
    if not username or not password:
        return jsonify({'success': False, 'message': '帳號與密碼為必填欄位'})
        
    pwd_hash = hash_password(password)
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    operator = session.get('username', 'SystemUser')

    try:
        with DB_LOCKS['config']:
            conn = get_db('config')
            try:
                conn.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", (username, pwd_hash, role))
                conn.commit()
            finally:
                conn.close()
        
        # 🌟 修正：對齊標準參數 (操作者, 模組, 目標, 狀態, 詳細內容)
        details = f"建立新使用者帳號 [{username}]，指派權限角色為 [{role}]。(操作來源 IP: {client_ip})"
        write_audit_log(operator, "系統設定", "系統帳號與權限", "SUCCESS", f"【新增帳號】{details}")
        
        return jsonify({'success': True, 'message': f'成功建立帳號：{username}'})
    except Exception as e:
        if "UNIQUE" in str(e): return jsonify({'success': False, 'message': '該帳號名稱已存在，請更換名稱。'})
        return jsonify({'success': False, 'message': str(e)})

@main_bp.route('/api/users/<int:user_id>', methods=['PUT', 'DELETE'])
@require_role([ROLE_ADMIN])
def modify_user(user_id):
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    operator = session.get('username', 'SystemUser')
    
    with DB_LOCKS['config']:
        conn = get_db('config')
        try:
            target_user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
            if not target_user:
                return jsonify({'success': False, 'message': '找不到該使用者'})
            
            target_username = target_user['username']
            old_role = target_user['role']
            old_status = target_user['status']
            
            if target_username == 'admin' and operator != 'admin':
                return jsonify({'success': False, 'message': '預設 admin 帳號無法被其他人修改或刪除'})

            if request.method == 'DELETE':
                if target_username == 'admin':
                    return jsonify({'success': False, 'message': '系統預設 admin 帳號禁止刪除'})
                conn.execute("DELETE FROM users WHERE id=?", (user_id,))
                conn.commit()
                action_type = "DELETE"
                
            elif request.method == 'PUT':
                data = request.json
                action = data.get('action')
                
                if action == 'update_role':
                    if target_username == 'admin':
                        return jsonify({'success': False, 'message': 'admin 的角色無法變更'})
                    new_role = data.get('role')
                    conn.execute("UPDATE users SET role=? WHERE id=?", (new_role, user_id))
                    action_type = "ROLE"
                    
                elif action == 'update_status':
                    if target_username == 'admin':
                        return jsonify({'success': False, 'message': 'admin 帳號無法停用'})
                    new_status = int(data.get('status', 1))
                    conn.execute("UPDATE users SET status=? WHERE id=?", (new_status, user_id))
                    action_type = "STATUS"
                    
                elif action == 'reset_password':
                    old_pwd = data.get('old_password')
                    new_pwd = data.get('password')
                    
                    if not old_pwd or not new_pwd:
                        return jsonify({'success': False, 'message': '舊密碼與新密碼不可為空'})
                        
                    operator_record = conn.execute("SELECT password_hash FROM users WHERE username=?", (operator,)).fetchone()
                    
                    is_valid = False
                    if target_user and verify_password(target_user['password_hash'], old_pwd):
                        is_valid = True
                    elif operator_record and verify_password(operator_record['password_hash'], old_pwd):
                        is_valid = True
                        
                    if not is_valid:
                        return jsonify({'success': False, 'message': '舊密碼 (或管理員授權密碼) 驗證失敗，拒絕修改。'})
                        
                    conn.execute("UPDATE users SET password_hash=? WHERE id=?", (hash_password(new_pwd), user_id))
                    action_type = "PASSWORD"
            conn.commit()
        except Exception as e:
            return jsonify({'success': False, 'message': f'資料庫存取錯誤: {str(e)}'})
        finally:
            conn.close() 

    # 🌟 修正：對齊標準參數並精準分類行為標籤
    if request.method == 'DELETE':
        details = f"永久刪除使用者帳號 [{target_username}]。(操作來源 IP: {client_ip})"
        msg = f"帳號 [{target_username}] 已刪除"
        act_tag = "【刪除帳號】"
    else:
        if action_type == "ROLE":
            details = f"變更使用者 [{target_username}] 權限角色：由「{old_role}」改為「{new_role}」。(操作來源 IP: {client_ip})"
            msg = f"變更 [{target_username}] 角色為 {new_role}"
            act_tag = "【權限異動】"
        elif action_type == "STATUS":
            o_str = "啟用" if old_status == 1 else "停用"
            n_str = "啟用" if new_status == 1 else "停用"
            details = f"變更使用者 [{target_username}] 登入狀態：由「{o_str}」改為「{n_str}」。(操作來源 IP: {client_ip})"
            msg = f"變更 [{target_username}] 狀態為 {n_str}"
            act_tag = "【狀態異動】"
        elif action_type == "PASSWORD":
            details = f"重設使用者 [{target_username}] 的登入密碼。(操作來源 IP: {client_ip})"
            msg = f"重設 [{target_username}] 的密碼成功"
            act_tag = "【密碼重設】"
            
    write_audit_log(operator, "系統設定", "系統帳號與權限", "SUCCESS", f"{act_tag}{details}")
    
    return jsonify({'success': True, 'message': msg})
            
@main_bp.route('/api/device/<ip>/events', methods=['GET'])
@require_role([ROLE_ADMIN, ROLE_OPERATOR, ROLE_AUDITOR]) # 💡 加上標準 RBAC 裝飾器
def api_device_events(ip):
    """
    輕量級設備事件軌跡 API：
    專供前端拓樸圖右鍵面板使用，快速從熱庫撈取指定 IP 的最近 50 筆事件紀錄。
    """
    try:
        from database import get_db
        conn = get_db('audit_hot')
        # 透過 LIKE 語法，精準匹配目標欄位中包含該 IP 的紀錄
        cur = conn.execute(
            """
            SELECT timestamp, action, result, details 
            FROM audit_logs 
            WHERE target LIKE ? 
            ORDER BY timestamp DESC 
            LIMIT 50
            """, 
            (f'%{ip}%',)
        )
        rows = cur.fetchall()
        conn.close()
        
        events = []
        for r in rows:
            events.append({
                'timestamp': r['timestamp'],
                'action': r['action'],
                'result': r['result'],
                'details': r['details']
            })
            
        return jsonify({'success': True, 'events': events})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})
                
# ==========================================
# 🚀 設備設定檔 NCM 管理 API (TFTP 觸發與讀取)
# ==========================================
@main_bp.route('/api/device/backup_now', methods=['POST'])
@require_role([ROLE_ADMIN, ROLE_OPERATOR]) 
def api_backup_now():
    import os, csv
    try:
        from tftp_backup_core import trigger_tftp_backup
        
        data = request.json or {}
        ip = data.get('ip')
        if not ip: return jsonify({"status": "error", "message": "未提供 IP 位址"})

        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        operator = session.get('username', 'System')

        # 1. 先從資料庫抓取基礎資料
        with DB_LOCKS['config']:
            conn = get_db('config')
            dev_row = conn.execute("SELECT * FROM devices WHERE ip=?", (ip,)).fetchone()
            conn.close()

        if not dev_row: return jsonify({"status": "error", "message": "資料庫中找不到該設備！"})
        dev = dict(dev_row)
        
        # 🌟 新增防護：嚴格限制只有 Level 1~4 的交換器、防火牆與 AP控制器允許備份！
        level = safe_int(dev.get('level', 3))
        dev_type = str(dev.get('type', '')).strip()
        
        if level > 4 or dev_type not in ['交換器', '防火牆', 'AP控制器']:
            error_msg = f"此設備不符合自動備份條件。目前層級: L{level}，種類: {dev_type}。(僅限 Level 1~4 的防火牆、交換器與AP控制器)"
            try: write_audit_log(operator, "設備設定檔管理", f"拒絕備份 ({ip})", "FAILED", f"【設備設定檔管理】{error_msg} (操作來源 IP: {client_ip})")
            except: pass
            return jsonify({"status": "error", "message": "設備層級或種類不符，拒絕執行備份。"})
            
        username = dev.get('ssh_user', '').strip()
        # ... (下方保留原本的 username, password, cli_type 等邏輯不變) ...
        password = dev.get('ssh_pass', '').strip()
        secret = dev.get('ssh_secret', '').strip()
        cli_type = dev.get('cli_type', '').strip() 
        brand = str(dev.get('brand', 'Unknown')).lower()
        model = str(dev.get('model', '')).lower()
        sys_descr = str(dev.get('sys_descr', '')).lower()

        # 🌟 終極殺手鐧：直接強制讀取您編輯的 devices.csv 檔案！(完全比照 swcfgtotxt5 邏輯)
        csv_matched = False
        csv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'devices.csv')
        
        print(f"\n📢 [NCM 備份程序啟動] 目標 IP: {ip}")
        if os.path.exists(csv_path):
            try:
                with open(csv_path, mode='r', encoding='utf-8-sig') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        if row.get('ip', '').strip() == ip:
                            # 找到了！無情使用 CSV 的資料覆蓋！
                            username = row.get('username', '').strip()
                            password = row.get('password', '').strip()
                            secret = row.get('secret', '').strip()
                            cli_type = row.get('device_type', '').strip()
                            csv_matched = True
                            break
            except Exception as e:
                print(f"⚠️ [CSV 讀取失敗]: {e}")

        if csv_matched:
            print(f"✅ [強制覆寫] 成功從本機 devices.csv 讀取設定！指定型態為: {cli_type}")
        else:
            print(f"⚠️ [警告] 本機 devices.csv 找不到此 IP，退回系統自動判斷...")

        # 決定最終通道
        if cli_type:
            d_type = cli_type
        # (大約在第 560 行附近的自動判定漏斗)
        else:
            if 'ruckus' in brand: d_type = 'ruckus_fastiron'
            elif 'cisco' in brand: d_type = 'cisco_ios'
            elif 'cx' in model or 'aos-cx' in sys_descr: d_type = 'aruba_aoscx' 
            elif 'aruba' in brand or 'hp' in brand: d_type = 'aruba_os'
            elif 'palo' in brand or 'pan-os' in brand: d_type = 'paloalto_panos'
            # 🌟 新增這一行：讓系統具備 MikroTik 的自動防呆識別能力！
            elif 'mikrotik' in brand or 'routeros' in sys_descr: d_type = 'mikrotik_routeros'
            else: d_type = 'generic'

        print(f"🚀 [執行通道] 最終傳遞給 Netmiko 的驅動名稱為: {d_type}\n")

        # =========================================================================
        # 🛡️ 終極防護：引入防撞車重試機制 ＆ 舊型 D-Link 指令成功後直接安全退場
        # =========================================================================
        import random
        import time
        
        success = False
        max_retries = 3
        
        for attempt in range(1, max_retries + 1):
            if attempt > 1:
                # 🔄 若非首次嘗試，隨機微調退讓 2 ~ 5 秒，避開高併發連線撞車
                sleep_time = random.uniform(2.0, 5.0)
                print(f"⚠️ [防卡重試] 設備 {ip} 連線忙碌或遭彈開，隨機退讓 {sleep_time:.1f} 秒後進行第 {attempt} 次重試...")
                time.sleep(sleep_time)
            
            # 呼叫 TFTP 備份引擎
            success = trigger_tftp_backup(ip, username, password, secret, d_type)
            
            # 如果成功，立刻打破重試迴圈
            if success:
                break
                
            print(f"❌ [連線警報] 設備 {ip} 第 {attempt} 次連線嘗試失敗。")

        # 🌟 核心邏輯修正：如果底層回傳的是老舊 D-Link 機型 (is_old_dlink 成功發送指令)
        # 只要 trigger_tftp_backup 完成發送並回傳 True，我們就認定「前台指令發送完畢」！
        # 這樣就不會再讓程式誤闖底層的降級直讀流程，徹底根除 Pattern not detected 假失敗！
        # =========================================================================

        # 🌟 關鍵修正：強化稽核日誌，詳盡記錄「誰、IP來源、對誰做什麼事」
        dev_name = dev.get('name', '未命名')
        if success:
            details = f"管理員 {operator} 透過 Web 介面發動了設備設定檔備份。目標設備: [{dev_name}] ({ip})，使用驅動: {d_type}。(操作來源 IP: {client_ip})"
            try: write_audit_log(operator, "設備設定檔管理", f"發動備份 ({ip})", "SUCCESS", f"【設備設定檔管理】{details}")
            except: pass
            return jsonify({"status": "success", "message": "備份指令已成功送出！設定檔正透過 TFTP 傳回伺服器。"})
        else:
            details = f"管理員 {operator} 透過 Web 介面嘗試發動設定檔備份失敗。目標設備: [{dev_name}] ({ip})，使用驅動: {d_type}。(操作來源 IP: {client_ip})"
            try: write_audit_log(operator, "設備設定檔管理", f"發動備份 ({ip})", "FAILED", f"【設備設定檔管理】{details}")
            except: pass
            return jsonify({"status": "error", "message": "備份指令發送失敗，請確認終端機日誌。"})

    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        print(f"\n❌ [API 崩潰] /api/device/backup_now 發生例外錯誤:\n{error_trace}\n")
        return jsonify({"status": "error", "message": f"伺服器內部錯誤: {str(e)}"})

@main_bp.route('/api/device/get_config', methods=['GET'])
@require_role([ROLE_ADMIN, ROLE_OPERATOR, ROLE_AUDITOR])
def api_get_config():
    import sqlite3
    from utils import safe_int
    ip = request.args.get('ip')
    # 🌟 接收前端傳來的版本序號 (預設為 0 最新)
    idx = safe_int(request.args.get('index', 0), 0)
    
    try:
        with sqlite3.connect('bkpswcfg.db') as conn:
            # 🌟 1. 先抓出所有歷史時間，供前端動態選單使用 (最多3筆)
            cur_all = conn.execute("""
                SELECT datetime(backup_time, '+8 hours') as local_time 
                FROM config_history 
                WHERE ip = ? AND status = 'success' 
                ORDER BY backup_time DESC LIMIT 3
            """, (ip,))
            history_list = [r[0] for r in cur_all.fetchall()]

            # 🌟 2. 抓出使用者指定的「該筆」設定檔與時間
            cursor = conn.execute("""
                SELECT datetime(backup_time, '+8 hours') as local_time, config_text 
                FROM config_history 
                WHERE ip = ? AND status = 'success'
                ORDER BY backup_time DESC LIMIT 1 OFFSET ?
            """, (ip, idx))
            row = cursor.fetchone()
            
            if row:
                config_content = row[1]
                
                # 二進位檔防呆隱藏顯示
                if config_content and config_content.startswith("=== [SYSTEM_BINARY_CONFIG_BASE64] ==="):
                    config_content = (
                        "⚠️ [系統提示]\n"
                        "這是一份由 D-Link 設備匯出的二進位 (.bin) 設定檔。\n\n"
                        "檔案已安全轉碼並【100% 無損】保存在資料庫中。\n"
                        "(由於不是純文字格式，為避免畫面亂碼，此處不直接顯示內容。未來如需還原，可由系統底層匯出解碼。)"
                    )
                    
                return jsonify({
                    "status": "success", 
                    "backup_time": row[0], 
                    "config": config_content,
                    "history_list": history_list  # 回傳時間清單陣列
                })
            else:
                return jsonify({"status": "not_found", "message": "尚未找到該設備的歷史備份紀錄。"})
    except Exception as e:
        return jsonify({"status": "error", "message": f"資料庫讀取失敗: {str(e)}"})

@main_bp.route('/api/backup/export/<fmt>', methods=['GET'])
def export_devices(fmt):
    import io, csv, json
    from flask import send_file
    
    devices = read_db_devices()
    log_info(f"📤 【手動操作】執行匯出設備明細 ({fmt.upper()} 格式)")
    
    if fmt == 'json': 
        # 🌟 關鍵修改：將 JSON 資料轉為位元流，並透過 send_file 強制瀏覽器作為「附件(attachment)」下載！
        json_str = json.dumps(devices, ensure_ascii=False, indent=4)
        return send_file(
            io.BytesIO(json_str.encode('utf-8')), 
            mimetype='application/json', 
            as_attachment=True, 
            download_name='network_devices_backup.json'
        )
        
    elif fmt == 'csv':
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=['ip', 'name', 'level', 'community', 'location', 'visible', 'type', 'brand', 'model', 'sys_descr', 'x', 'y', 'status', 'username', 'password', 'secret', 'device_type'])
        writer.writeheader()
        for d in devices:
            d['username'] = d.get('ssh_user', '')
            d['password'] = d.get('ssh_pass', '')
            d['secret'] = d.get('ssh_secret', '')
            d['device_type'] = d.get('cli_type', '')
            clean_d = {k: v for k, v in d.items() if k in writer.fieldnames}
            writer.writerow(clean_d)
        output.seek(0)
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8-sig')), 
            mimetype='text/csv', 
            as_attachment=True, 
            download_name='network_devices_backup.csv'
        )
        
    return "不支援的格式", 400

@main_bp.route('/api/device/download_config', methods=['GET'])
def api_download_config():
    import sqlite3
    import base64
    from flask import Response, request
    from utils import safe_int
    
    ip = request.args.get('ip')
    # 🌟 接收前端傳入的歷史序號 index (0=最新, 1=次新, 2=最舊)，防呆預設為 0
    idx = safe_int(request.args.get('index', 0), 0)
    
    if not ip:
        return "Missing IP", 400
        
    try:
        with sqlite3.connect('bkpswcfg.db') as conn:
            # 🌟 利用 OFFSET 語法跳過指定筆數，精準抓取第 N 筆歷史備份！
            cursor = conn.execute("""
                SELECT config_text, backup_time 
                FROM config_history 
                WHERE ip = ? AND status = 'success' 
                ORDER BY backup_time DESC 
                LIMIT 1 OFFSET ?
            """, (ip, idx))
            row = cursor.fetchone()
            
            if row and row[0]:
                config_content = row[0]
                # 將備份時間轉換為安全的檔名格式 (例: 2026-06-07_14-20-00)
                backup_time_str = row[1].replace(":", "-").replace(" ", "_")
                
                # 🌟 智慧判斷：這是一般的純文字，還是封裝的二進位檔案？
                if config_content.startswith("=== [SYSTEM_BINARY_CONFIG_BASE64] ==="):
                    b64_str = config_content.replace("=== [SYSTEM_BINARY_CONFIG_BASE64] ===\n", "").strip()
                    raw_bytes = base64.b64decode(b64_str)
                    
                    return Response(
                        raw_bytes,
                        mimetype="application/octet-stream",
                        headers={"Content-disposition": f"attachment; filename={ip}_{backup_time_str}.bin"}
                    )
                else:
                    return Response(
                        config_content,
                        mimetype="text/plain",
                        headers={"Content-disposition": f"attachment; filename={ip}_{backup_time_str}.txt"}
                    )
            else:
                return f"找不到該設備指定的歷史備份檔案 (Index: {idx})", 404
    except Exception as e:
        return f"伺服器錯誤: {str(e)}", 500

# ========================================================
# 🔌 新增：UDP 162 SNMP Trap 服務主動防禦雷達控制項 API
# ========================================================
@main_bp.route('/api/get_trap_status', methods=['GET'])
def get_trap_status():
    """讓前端 UI 初始化時，讀取目前 Trap 服務是開啟還是關閉"""
    import snmp_core
    # 💡 透過傳遞 Blueprint 的標準 jsonify 回傳狀態
    return jsonify({"status": "success", "trap_enabled": getattr(snmp_core, 'GLOBAL_TRAP_ENABLED', True)})

@main_bp.route('/api/settings/autobackup', methods=['GET', 'POST'])
@require_role([ROLE_ADMIN])
def handle_autobackup_settings():
    from database import DB_LOCKS, get_db, write_audit_log
    from utils import log_info
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    
    if request.method == 'POST':
        data = request.get_json() or {}
        new_time = str(data.get('time', '02:00')).strip()
        new_scope = str(data.get('scope', 'all')).strip()
        
        # 🌟 核心修正 1：只在純粹寫入資料庫時加鎖，完成後在 finally 區塊立刻關閉釋放
        with DB_LOCKS['config']:
            conn = get_db('config')
            try:
                conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('autobackup_time', ?)", (new_time,))
                conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('autobackup_scope', ?)", (new_scope,))
                conn.commit()
            except Exception as e:
                return jsonify({'success': False, 'message': f'資料庫寫入失敗: {str(e)}'}), 500
            finally:
                conn.close() # 🛡️ 徹底釋放 config 鎖
                
        # 🌟 核心修正 2：將日誌紀錄完全移出 with 鎖的「外側」！
        scope_str = "僅顯示中設備" if new_scope == 'visible' else "全網L1~L4設備"
        details = f"管理員更新自動備份排程參數。執行時間設定為：{new_time}，備份範圍：{scope_str}。(操作來源 IP: {client_ip})"
        write_audit_log("SystemUser", "修改系統設定", "自動備份排程", "SUCCESS", f"【修改系統設定】{details}")
        log_info(f"⚙️ 【參數儲存】{details}")
        return jsonify({'success': True})
    else:
        # GET 請求：一併套用安全連線釋放
        with DB_LOCKS['config']:
            conn = get_db('config')
            try:
                en_row = conn.execute("SELECT value FROM system_settings WHERE key='autobackup_enabled'").fetchone()
                time_row = conn.execute("SELECT value FROM system_settings WHERE key='autobackup_time'").fetchone()
                scope_row = conn.execute("SELECT value FROM system_settings WHERE key='autobackup_scope'").fetchone()
            finally:
                conn.close()
                
            return jsonify({
                'success': True, 
                'enabled': (en_row['value'] == '1') if en_row else False,
                'time': time_row['value'] if time_row else '02:00',
                'scope': scope_row['value'] if scope_row else 'all'
            })

# ==========================================
# 📱 系統推播測試專用 API
# ==========================================
@main_bp.route('/api/test_push', methods=['POST'])
@require_role([ROLE_ADMIN])  # 🛡️ 補上資安防護：限制只有管理員可以觸發測試推播
def test_push_api():
    from utils import send_ntfy_alert
    try:
        # 💡 傳遞 source="測試" 特權代碼，告訴發送引擎這是人為手動測試，不受總開關關閉的限制
        send_ntfy_alert("🔔 測試推播成功", "這是一則來自 SNMP 網管系統的測試訊息，您的 ntfy 伺服器運作完美！", "high", "tada,sparkles", source="測試")
        # 💡 改用標準的 jsonify 回傳格式
        return jsonify({"status": "success", "message": "測試推播已發出！"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
        
# =========================================================================
# 📈 流量核心 API：從 InfluxDB 撈取最近 5 分鐘【內網全網段白名單】Top 10 排行
# =========================================================================
@main_bp.route('/api/flow/top5', methods=['GET'])
@require_role([ROLE_ADMIN, ROLE_OPERATOR])
def get_top5_flow():
    import ipaddress
    
    with DB_LOCKS['config']:
        conn = get_db('config')
        try:
            r_int = conn.execute("SELECT value FROM system_settings WHERE key='flow_internal_nets'").fetchone()
            r_exc = conn.execute("SELECT value FROM system_settings WHERE key='flow_exclude_nets'").fetchone()
        finally:
            conn.close()
    
    raw_int = r_int['value'] if r_int else '10.0.0.0/8, 172.16.0.0/12, 192.168.1.0/24'
    raw_exc = r_exc['value'] if r_exc else ''
    
    int_list = [x.strip() for x in raw_int.split(',') if x.strip()]
    exc_list = [x.strip() for x in raw_exc.split(',') if x.strip()]
    
    # === 在 get_top5_flow() 裡面 ===
    int_nets = []
    for c in int_list:
        try: int_nets.append(ipaddress.ip_network(c, strict=False))  # 🌟 支援 IPv6
        except: pass
        
    exc_nets = []
    for c in exc_list:
        try: exc_nets.append(ipaddress.ip_network(c, strict=False))  # 🌟 支援 IPv6
        except: pass

    def is_internal(ip_str):
        try:
            ip_obj = ipaddress.ip_address(ip_str)  # 🌟 支援 IPv6
            for exc in exc_nets:
                if ip_obj in exc: return False
            for inc in int_nets:
                if ip_obj in inc: return True
            return False
        except: return False

    client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG)
    query_api = client.query_api()

    flux_query = fr'''
    from(bucket: "{INFLUXDB_BUCKET}")
      |> range(start: -5m)
      |> filter(fn: (r) => r["_measurement"] == "netflow" or r["_measurement"] == "sflow")
      |> filter(fn: (r) => r["_field"] == "in_bytes" or r["_field"] == "bytes")
      |> filter(fn: (r) => exists r["src_ip"] and r["src_ip"] != "")
      |> group(columns: ["src_ip"])
      |> sum()
      |> group()
      |> sort(columns: ["_value"], desc: true)
      |> limit(n: 300)
    '''

    try:
        result = query_api.query(flux_query)
        top10_list = []
        for table in result:
            for record in table.records:
                device_ip = record.values.get("src_ip")
                if not device_ip or device_ip in ["Unknown", "None", "null"]: continue
                if is_internal(device_ip):
                    top10_list.append({"ip": device_ip, "traffic_mb": round(record.get_value() / (1024 * 1024), 2)})
                    if len(top10_list) >= 10: break
            if len(top10_list) >= 10: break
                
        client.close()
        return jsonify({"status": "success", "data": top10_list})
        
    except Exception as e:
        if client: client.close()
        error_str = str(e).lower()
        if "does not exist" in error_str or "no results" in error_str:
            return jsonify({"status": "success", "data": []})
        return jsonify({"status": "error", "message": str(e)}), 500 
 
# =========================================================================
# 💾 流量查詢記憶體快取池 (Memory Cache Engine)
# =========================================================================
FLOW_SEARCH_CACHE = {}  # 格式: { "cache_key": (cache_timestamp, json_data) }
CACHE_TTL_SECONDS = 15  # 快取存活時間：15秒

# =========================================================================
# 🔍 流量明細檢索 API：支援時間範圍、雙向 IP、Port 號複合式動態查詢 (快取與全自適應版)
# =========================================================================
@main_bp.route('/api/flow/search', methods=['POST'])
@require_role([ROLE_ADMIN, ROLE_OPERATOR])
def search_flow_details():
    data = request.get_json() or {}
    
    start_time = data.get('start_time', '-1h')
    end_time = "2030-01-01T00:00:00Z" 
    
    src_ip = data.get('src_ip', '').strip()
    dst_ip = data.get('dst_ip', '').strip()
    port_val = data.get('port', '').strip()
    
    cache_key = f"{start_time}_{src_ip}_{dst_ip}_{port_val}"
    now_ts = time.time()
    
    if cache_key in FLOW_SEARCH_CACHE:
        cache_time, cached_records = FLOW_SEARCH_CACHE[cache_key]
        if now_ts - cache_time < CACHE_TTL_SECONDS:
            return jsonify({"status": "success", "data": cached_records, "from_cache": True})

    client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG)
    query_api = client.query_api()

    flux_parts = [
        fr'from(bucket: "{INFLUXDB_BUCKET}")',
        fr'  |> range(start: {start_time}, stop: {end_time})',
        r'  |> filter(fn: (r) => r["_measurement"] == "netflow" or r["_measurement"] == "sflow")',
        r'  |> filter(fn: (r) => r["_field"] == "in_bytes" or r["_field"] == "bytes")',
        r'  |> filter(fn: (r) => exists r["src_ip"] and r["src_ip"] != "")'
    ]
    
    def build_flux_ip_filter(col_name, val):
        import ipaddress
        try:
            # 1. 嘗試解析為完整 IP (若成功則精確比對)
            ipaddress.ip_address(val)
            return fr'  |> filter(fn: (r) => r["{col_name}"] == "{val}")'
        except ValueError:
            # 2. 局部輸入智慧判斷 (正則表達式)
            if ':' in val:
                # IPv6 模糊搜尋：通常是前綴，例如 2001:288:1279
                safe_val = val.replace(':', r':')
                return fr'  |> filter(fn: (r) => r["{col_name}"] =~ /^{safe_val}/)'
            else:
                # IPv4 模糊搜尋：通常是後綴，例如 2.3 匹配結尾是 .2.3 的 IP
                safe_val = val.replace('.', r'\.')
                return fr'  |> filter(fn: (r) => r["{col_name}"] =~ /(^|\.){safe_val}$/)'

    if src_ip:
        flux_parts.append(build_flux_ip_filter("src_ip", src_ip))
    if dst_ip:
        flux_parts.append(build_flux_ip_filter("dst_ip", dst_ip))
    if port_val:
        flux_parts.append(fr'  |> filter(fn: (r) => r["src_port"] == "{port_val}" or r["dst_port"] == "{port_val}" or r["srcport"] == "{port_val}" or r["dstport"] == "{port_val}")')
        
    flux_parts.append(r'  |> sort(columns: ["_time"], desc: true)')
    flux_parts.append(r'  |> limit(n: 500)')
    
    flux_query = "\n".join(flux_parts)

    try:
        result = query_api.query(flux_query)
        records_list = []
        
        for table in result:
            for record in table.records:
                bytes_raw = record.get_value() or 0
                mb_size = round(float(bytes_raw) / (1024 * 1024), 3)
                
                src_p = record.values.get("src_port") or record.values.get("srcport") or "-"
                dst_p = record.values.get("dst_port") or record.values.get("dstport") or "-"
                prot = record.values.get("protocol") or record.values.get("proto") or "TCP/UDP"
                
                time_raw = record.get_time()
                time_str = "Unknown"
                if time_raw:
                    time_str = (time_raw + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')
                
                records_list.append({
                    "time": time_str,
                    "src_ip": record.values.get("src_ip", "-"),
                    "dst_ip": record.values.get("dst_ip", "-"),
                    "src_port": src_p,
                    "dst_port": dst_p,
                    "protocol": prot,
                    "traffic_mb": mb_size
                })
                
        client.close()
        
        # ==========================================================
        # 🌟 核心修復：強制進行全域時間降冪排序 (由最新到最舊)
        # ==========================================================
        records_list.sort(key=lambda x: x["time"], reverse=True)
        
        FLOW_SEARCH_CACHE[cache_key] = (now_ts, records_list)
        return jsonify({"status": "success", "data": records_list, "from_cache": False})
        
    except Exception as e:
        if client: client.close()
        error_str = str(e).lower()
        if "does not exist" in error_str or "no results" in error_str:
            return jsonify({"status": "success", "data": [], "from_cache": False})
        return jsonify({"status": "error", "message": str(e)}), 500

# =========================================================================
# 🩺 流量引擎健康檢查 API：偵測 InfluxDB 與 Telegraf 運行狀態
# =========================================================================
@main_bp.route('/api/flow/check_env', methods=['GET'])
@require_role([ROLE_ADMIN, ROLE_OPERATOR, ROLE_AUDITOR])
def check_flow_env():
    import platform
    import subprocess
    import urllib.request
    
    influx_ok = False
    telegraf_ok = False

    # 1. 檢查 InfluxDB (打它的 Health 端點最準確)
    try:
        # INFLUXDB_URL 通常是 "http://127.0.0.1:8086"
        health_url = f"{INFLUXDB_URL.rstrip('/')}/health"
        req = urllib.request.Request(health_url, method='GET')
        with urllib.request.urlopen(req, timeout=1.5) as res:
            if res.getcode() == 200:
                influx_ok = True
    except Exception:
        pass

    # 2. 檢查 Telegraf 行程 (Process) 是否存在
    try:
        sys_name = platform.system().lower()
        if sys_name == 'windows':
            # Windows 檢查 tasklist
            output = subprocess.run(['tasklist', '/FI', 'IMAGENAME eq telegraf.exe'], capture_output=True, text=True).stdout
            if 'telegraf.exe' in output.lower():
                telegraf_ok = True
        else:
            # Linux 檢查 ps
            output = subprocess.run(['ps', '-A'], capture_output=True, text=True).stdout
            if 'telegraf' in output.lower():
                telegraf_ok = True
    except Exception:
        pass

    return jsonify({
        "success": True,
        "influxdb_ok": influx_ok,
        "telegraf_ok": telegraf_ok
    })
        
# ==========================================
# 🌐 IP 來源、DNS 反解與內網 MAC 探測 API
# ==========================================
@main_bp.route('/api/tools/ip_lookup/<ip>', methods=['GET'])
@require_role([ROLE_ADMIN, ROLE_OPERATOR, ROLE_AUDITOR])
def ip_lookup(ip):
    import socket
    import urllib.request
    import urllib.parse
    import json
    import re
    import ipaddress
    import uuid
    import subprocess
    import platform
    
    # 💡 內建 Google 免費翻譯引擎 (只翻英文，保留原文字串)
    def translate_en_to_zh(text):
        if not text or text == '-': return text
        if any('\u4e00' <= char <= '\u9fa5' for char in text): return text
        try:
            url = f"https://translate.googleapis.com/translate_a/single?client=gtx&sl=en&tl=zh-TW&dt=t&q={urllib.parse.quote(text)}"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=1.5) as response:
                result = json.loads(response.read().decode('utf-8'))
                return result[0][0][0]  
        except Exception:
            return text 

    # 1. 執行 DNS 網域反解 (Reverse DNS Lookup)
    hostname = "無反解紀錄 (No PTR)"
    try:
        socket.setdefaulttimeout(1.5) 
        host_tuple = socket.gethostbyaddr(ip)
        hostname = host_tuple[0]
    except Exception:
        pass
        
    geo_info = {}
    mac_address = "無法解析 (無 ARP 快取)"
    is_internal = False
    
    # 2. 智慧核心：動態讀取系統設定中的「內網流量統計網段」
    internal_nets_str = '10.0.0.0/8, 172.16.0.0/12, 192.168.1.0/24'
    try:
        with DB_LOCKS['config']:
            conn = get_db('config')
            row = conn.execute("SELECT value FROM system_settings WHERE key='flow_internal_nets'").fetchone()
            if row and row['value']:
                internal_nets_str = row['value']
            conn.close()
    except Exception as e:
        pass

    internal_networks = []
    for net_str in internal_nets_str.split(','):
        net_str = net_str.strip()
        if not net_str: continue
        try: internal_networks.append(ipaddress.ip_network(net_str, strict=False)) # 🌟 支援 IPv6
        except: pass

    try:
        ip_obj = ipaddress.ip_address(ip) # 🌟 支援 IPv6
        for net in internal_networks:
            if ip_obj in net:
                is_internal = True
                break
    except: pass

    # 🌟 兜底防護與特殊協定位址 (智慧辨識 IPv6 與 Class D 群播)
    is_multicast_or_link_local = False
    if not is_internal:
        try:
            # 呼叫強大的 ipaddress，自動支援 IPv4 與 IPv6
            ip_obj = ipaddress.ip_address(ip)
            
            # is_multicast: 自動涵蓋 IPv4 (224.0.0.0/4) 與 IPv6 (ff00::/8)
            # is_link_local: 自動涵蓋 IPv4 (169.254.x.x) 與 IPv6 (fe80::/10)
            if ip_obj.is_private or ip_obj.is_multicast or ip_obj.is_link_local or ip_obj.is_loopback:
                is_internal = True
                
            # 特別標記群播與本地鏈路，避免後續進行無效的 ARP 實體網卡搜尋
            if ip_obj.is_multicast or ip_obj.is_link_local:
                is_multicast_or_link_local = True
        except:
            pass

    # 3. 分流處理：內網撈 MAC，外網撈 GeoIP
    if is_internal:
        target_ip = ip.strip()
        
        # 💡 若為群播或本地鏈路，直接賦予虛擬說明，跳過實體 ARP 查詢
        # (字串內包含「無法解析」，前端就會自動隱藏複製按鈕)
        if is_multicast_or_link_local:
            mac_address = "群播 / 本地鏈路虛擬位址 (無法解析實體 MAC)"
        else:
            try:
                with DB_LOCKS['config']:
                    conn = get_db('config')
                    devs = conn.execute("SELECT snmp_raw FROM devices WHERE snmp_raw IS NOT NULL AND snmp_raw != '{}'").fetchall()
                    conn.close()
                
                for dev in devs:
                    try:
                        raw = json.loads(dev['snmp_raw'])
                        arp_table = raw.get("13", {})     
                        arp_table_15 = raw.get("15", {})  
                        
                        def find_valid_mac(table):
                            if isinstance(table, dict):
                                for arp_key, mac_val in table.items():
                                    # 🌟 終極修復：與 modal_search 演算法對齊！利用 . 切割，精準取最後4節
                                    parts = str(arp_key).strip().split('.')
                                    if len(parts) >= 4 and ".".join(parts[-4:]) == target_ip:
                                        mac_clean = re.sub(r'[^a-fA-F0-9]', '', str(mac_val)).lower()
                                        if len(mac_clean) == 12:
                                            return ':'.join(mac_clean[i:i+2] for i in range(0, 12, 2)).upper()
                            return None

                        found_mac = find_valid_mac(arp_table) or find_valid_mac(arp_table_15)
                        
                        if found_mac:
                            mac_address = found_mac
                            break # 找到真正的 MAC 才跳出
                    except Exception:
                        continue 
                        
            except Exception as e:
                print(f"ARP 解析錯誤: {e}")

            # 🌟 終極備援：判斷是否為伺服器本機 IP，或是動用本機 ARP 廣播
            if mac_address == "無法解析 (無 ARP 快取)":
                try:
                    # 💡 獲取伺服器本機的所有 IPv4 位址
                    local_ips = [socket.gethostbyname(socket.gethostname())]
                    try:
                        _, _, ips = socket.gethostbyname_ex(socket.gethostname())
                        local_ips.extend(ips)
                    except: pass
                    
                    # 1. 檢查是否為伺服器自己 (本機作業系統不會有自己的 ARP 紀錄)
                    if target_ip in local_ips or target_ip == '127.0.0.1':
                        mac_num = hex(uuid.getnode()).replace('0x', '').upper().zfill(12)
                        mac_address = ':'.join(mac_num[i:i+2] for i in range(0, 12, 2)) + " (網管伺服器本機)"
                    
                    # 2. 若不是本機，強迫伺服器發出 Ping 與 ARP 廣播強行抓取
                    else:
                        subprocess.run(["ping", "-n", "1", "-w", "500", target_ip] if platform.system().lower() == 'windows' else ["ping", "-c", "1", "-W", "1", target_ip], stdout=subprocess.DEVNULL)
                        arp_res = subprocess.run(["arp", "-a", target_ip], capture_output=True, text=True)
                        match = re.search(r'([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})', arp_res.stdout)
                        if match:
                            mac_address = match.group(1).replace('-', ':').upper() + " (伺服器 ARP 快取)"
                except Exception as e: 
                    print(f"備援 MAC 解析失敗: {e}")

        geo_info = {
            "country_zh": "內部網路 (LAN)", "country_en": "Private Network", 
            "isp_zh": "內部設備", "isp_en": "Internal Device",
            "city_zh": "-", "city_en": "-"
        }
        
    else:
        # 外部 IP 查詢 (GeoIP + Google 即時翻譯雙列輸出)
        try:
            req = urllib.request.Request(
                f"http://ip-api.com/json/{ip}?lang=zh-TW", 
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            with urllib.request.urlopen(req, timeout=3.0) as response:
                data = json.loads(response.read().decode('utf-8'))
                if data.get("status") == "success":
                    raw_country = data.get("country", "")
                    raw_city = data.get("city", "")
                    raw_isp = data.get("isp", "")
                    raw_org = data.get("org", "")
                    
                    # 💡 將原文與 Google 翻譯結果「同時保留」傳給前端
                    geo_info = {
                        "country_en": raw_country,
                        "country_zh": "台灣" if raw_country == "Taiwan" else translate_en_to_zh(raw_country),
                        "city_en": raw_city,
                        "city_zh": translate_en_to_zh(raw_city),
                        "isp_en": raw_isp,
                        "isp_zh": translate_en_to_zh(raw_isp),
                        "org_en": raw_org,
                        "org_zh": translate_en_to_zh(raw_org)
                    }
                else:
                    geo_info = {"country_en": "Unknown", "country_zh": "未知的外部 IP", "city_en": "-", "city_zh": "-", "isp_en": "Unknown", "isp_zh": "Unknown", "org_en": "Unknown", "org_zh": "Unknown"}
        except Exception:
            geo_info = {"country_en": "Timeout", "country_zh": "查詢逾時或連線失敗", "city_en": "-", "city_zh": "-", "isp_en": "-", "isp_zh": "-", "org_en": "-", "org_zh": "-"}

    return jsonify({
        "success": True,
        "ip": ip,
        "hostname": hostname,
        "is_internal": is_internal,
        "mac_address": mac_address,
        "geo": geo_info
    })
    
# =========================================================================
# 💾 InfluxDB 大數據瘦身與降維任務初始化 API (Retention Policy & Downsampling)
# =========================================================================
@main_bp.route('/api/system/init_influx_tasks', methods=['POST'])
@require_role([ROLE_ADMIN])
def init_influx_tasks():
    from influxdb_client import InfluxDBClient
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    operator = session.get('username', 'SystemUser')
    
    try:
        client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG)
        
        # 1. 取得 Org ID
        org_api = client.organizations_api()
        orgs = org_api.find_organizations(org=INFLUXDB_ORG)
        if not orgs: return jsonify({'success': False, 'message': '找不到 InfluxDB 組織'})
        org_id = orgs[0].id
        
        # 2. 建立新的長期降維儲存 Bucket (若不存在)
        buckets_api = client.buckets_api()
        downsample_bucket_name = f"{INFLUXDB_BUCKET}_downsampled"
        existing_buckets = buckets_api.find_buckets().buckets
        
        target_bucket = next((b for b in existing_buckets if b.name == downsample_bucket_name), None)
        if not target_bucket:
            # 建立長期桶 (保留 365 天)
            buckets_api.create_bucket(bucket_name=downsample_bucket_name, org_id=org_id, retention_rules=[{"type": "expire", "everySeconds": 31536000}])
            
        # 3. 將原始 Bucket (netflow_db) 的保留期限縮短為 7 天 (604800 秒)，自動刪除舊資料釋放空間
        raw_bucket = next((b for b in existing_buckets if b.name == INFLUXDB_BUCKET), None)
        if raw_bucket:
            raw_bucket.retention_rules = [{"type": "expire", "everySeconds": 604800}]
            buckets_api.update_bucket(bucket=raw_bucket)

        # 4. 寫入 Flux Task 腳本：每小時自動把原始資料加總，寫入降維桶
        tasks_api = client.tasks_api()
        task_query = f'''
        option task = {{name: "Downsample_Hourly_Flow", every: 1h}}
        from(bucket: "{INFLUXDB_BUCKET}")
            |> range(start: -1h)
            |> filter(fn: (r) => r["_measurement"] == "netflow" or r["_measurement"] == "sflow")
            |> filter(fn: (r) => r["_field"] == "in_bytes" or r["_field"] == "bytes")
            |> group(columns: ["src_ip", "dst_ip", "protocol"])
            |> sum()
            |> to(bucket: "{downsample_bucket_name}")
        '''
        
        # 檢查是否已經有同名的 Task，若有則刪除重建
        tasks = tasks_api.find_tasks(org_id=org_id).tasks
        for t in tasks:
            if t.name == "Downsample_Hourly_Flow":
                tasks_api.delete_task(t.id)
                
        tasks_api.create_task(every="1h", name="Downsample_Hourly_Flow", org_id=org_id, flux=task_query)
        client.close()
        
        # 🌟 寫入稽核日誌
        details = f"啟動大數據降維與瘦身機制：建立 {downsample_bucket_name} (保留365天)，並將原始資料保留期縮減為 7 天。背景排程 Task 已生效。(操作來源 IP: {client_ip})"
        write_audit_log(operator, "系統設定", "InfluxDB資料庫瘦身", "SUCCESS", f"【修改系統設定】{details}")
        
        return jsonify({'success': True, 'message': 'InfluxDB 降維與瘦身任務已成功植入底層排程！'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'InfluxDB API 執行失敗: {str(e)}'})
        
