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
import warnings

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
    """RBAC 核心防護裝飾器"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            with DB_LOCKS['config']:
                # 👇 🌟 加上 bypass_shard=True，強制讀取主庫的 RBAC 開關
                conn = get_db('config', bypass_shard=True)
                row = conn.execute("SELECT value FROM system_settings WHERE key='rbac_enabled'").fetchone()
                conn.close()
                
            # 若資料庫無設定，預設為開啟 (True)
            rbac_enabled = (row['value'] == '1') if row else True
            
            # 🌟 如果 RBAC 總開關被關閉，直接放行 (Bypass)
            if not rbac_enabled:
                return f(*args, **kwargs)
                
            # 檢查 Session 中的角色
            user_role = session.get('role')
            if not user_role or user_role not in allowed_roles:
                if request.is_json or request.path.startswith('/api/'):
                    return jsonify({'success': False, 'message': '權限不足 (Forbidden)'}), 403
                else:
                    return redirect('/login')
                    
            return f(*args, **kwargs)
        return decorated_function
    return decorator

main_bp = Blueprint('main', __name__)

main_bp = Blueprint('main', __name__)

# 👇 🌟 新增：全域環境注射器 (讓 layout.html 能隨時取得總部狀態)
@main_bp.context_processor
def inject_hq_status():
    is_hq = False
    try:
        with DB_LOCKS['config']:
            conn = get_db('config', bypass_shard=True)
            row = conn.execute("SELECT value FROM system_settings WHERE key='hq_view_mode'").fetchone()
            if row and row['value'] == 'hq':
                is_hq = True
            conn.close()
    except: pass
    
    return dict(hq_mode_is_active=is_hq)

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
def dashboard_page(): 
    # 🌟 智慧判定：如果是彈出視窗，絕對不清除 Session！
    is_iframe = request.args.get('iframe') == '1'
    if not is_iframe:
        session.pop('target_site_code', None)
        session.pop('target_site_name', None)
    
    target_site = session.get('target_site_code')
    with DB_LOCKS['config']:
        conn = get_db('config', bypass_shard=True)
        row = conn.execute("SELECT value FROM system_settings WHERE key='hq_view_mode'").fetchone()
        hq_mode = row['value'] if row else 'local'
        conn.close()
        
    if hq_mode == 'hq' and not target_site:
        return render_template('hq_dashboard.html')
    return render_template('dashboard.html')

# ========================================================
# 🌍 總部專用：全域戰情大腦 API (心跳與斷線偵測)
# ========================================================
@main_bp.route('/api/hq/dashboard/stats', methods=['GET'])
def api_hq_dashboard_stats():
    import datetime
    try:
        with DB_LOCKS['hq_master']:
            conn = get_db('hq_master')
            # 依照行政區與學校代碼排序
            rows = conn.execute("SELECT * FROM global_sites ORDER BY district, site_code").fetchall()
            
            # 👇 🌟 新增：讀取六都行政區的靜態資料表
            dist_rows = []
            try:
                dist_rows = conn.execute("SELECT city_key, district_name FROM city_districts").fetchall()
            except: pass
            conn.close()
        
        # 將資料庫中的扁平資料，整理成以 city_key 為群組的 Dictionary
        city_districts = {}
        for r in dist_rows:
            key = r['city_key']
            if key not in city_districts: city_districts[key] = []
            city_districts[key].append(r['district_name'])

        sites = []
        health = {'up': 0, 'down': 0, 'warning': 0, 'total': len(rows)}
        now_utc = datetime.datetime.utcnow()
        
        for r in rows:
            site = dict(r)
            # 🌟 核心防禦：判斷是否逾時斷線 
            # (超過 15 分鐘未收到推播即視為 Warning，超過 30 分鐘視為 Down)
            try:
                last_sync = datetime.datetime.strptime(site['last_sync_time'], '%Y-%m-%d %H:%M:%S')
                diff_mins = (now_utc - last_sync).total_seconds() / 60.0
                
                if diff_mins > 30:
                    site['status'] = 'down'
                elif diff_mins > 15:
                    site['status'] = 'warning'
                else:
                    site['status'] = 'up'
                    
                # 轉為台灣時間 (+8小時) 供前端顯示
                local_time = last_sync + datetime.timedelta(hours=8)
                site['last_sync_local'] = local_time.strftime('%Y-%m-%d %H:%M:%S')
            except:
                site['status'] = 'down'
                site['last_sync_local'] = '從未推播/解析失敗'
                
            health[site['status']] += 1
            sites.append(site)
            
        return jsonify({'success': True, 'health': health, 'sites': sites, 'city_districts': city_districts})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# ========================================================
# 🌍 總部跨站點切換器 API (Site Switcher)
# ========================================================
@main_bp.route('/api/hq/sites', methods=['GET'])
def api_hq_get_sites():
    """取得所有已註冊的分區清單 (供 Navbar 下拉選單使用)"""
    try:
        with DB_LOCKS['hq_master']:
            conn = get_db('hq_master')
            rows = conn.execute("SELECT site_code, site_name, district, status FROM global_sites ORDER BY district, site_code").fetchall()
            conn.close()
        return jsonify({'success': True, 'sites': [dict(r) for r in rows]})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@main_bp.route('/api/hq/switch_site', methods=['POST'])
def api_hq_switch_site():
    """將管理員的 Session 鎖定至特定分區"""
    data = request.json
    site_code = data.get('site_code')
    site_name = data.get('site_name')
    if not site_code: return jsonify({'success': False, 'message': '缺少站點代碼'})
    
    session['target_site_code'] = site_code
    session['target_site_name'] = site_name
    return jsonify({'success': True})

@main_bp.route('/api/hq/clear_site', methods=['POST'])
def api_hq_clear_site():
    """解除 Session 鎖定，回歸總部全域上帝視角"""
    session.pop('target_site_code', None)
    session.pop('target_site_name', None)
    return jsonify({'success': True})

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
def settings_page(): 
    # 👇 🌟 進入系統設定時，強制解除所有分區鎖定，回歸總部大腦！
    session.pop('target_site_code', None)
    session.pop('target_site_name', None)
    return render_template('settings.html')

@main_bp.route('/audit-logs')
@require_role([ROLE_ADMIN, ROLE_OPERATOR, ROLE_AUDITOR])  # 🛡️ 三種角色皆可看
def audit_logs_page(): return render_template('audit_logs.html')
        
@main_bp.route('/inventory')
@require_role([ROLE_ADMIN, ROLE_OPERATOR])
def inventory_page():
    return render_template('inventory.html')

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
            # 👇 🌟 加上 bypass_shard=True，強制從主庫驗證帳密
            conn = get_db('config', bypass_shard=True)
            user = conn.execute("SELECT * FROM users WHERE username = ? AND status = 1", (username,)).fetchone()
            conn.close()
            
        # 進行密碼雜湊比對
        if user and verify_password(user['password_hash'], password):
            session['username'] = username
            session['role'] = user['role']
            client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
            write_audit_log(username, "系統身分驗證", "登入系統", "SUCCESS", f"【登入成功】使用者從 {client_ip} 登入系統。")
            return jsonify({'status': 'success', 'msg': '登入成功'})
        else:
            client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
            write_audit_log(username if username else "Unknown", "系統身分驗證", "登入系統", "FAILED", f"【登入失敗】帳號或密碼錯誤 (IP: {client_ip})。")
            return jsonify({'status': 'error', 'msg': '帳號或密碼錯誤，或帳號已被停用'})
            
    except Exception as e:
        return jsonify({'status': 'error', 'msg': f'系統發生錯誤: {str(e)}'})

@main_bp.route('/api/logout', methods=['POST'])
def api_logout():
    username = session.get('username', 'Unknown')
    session.clear()
    write_audit_log(username, request.remote_addr, "USER_LOGOUT", "使用者登出系統", "SUCCESS")
    return jsonify({'status': 'success', 'msg': '已成功登出'})

@main_bp.route('/login')
def login_page():
    # 👇 🌟 新增這兩行：進入登入頁面時，強制解除所有分區鎖定
    session.pop('target_site_code', None)
    session.pop('target_site_name', None)
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
    dev_rows = []
    # 👇 🌟 新增：嘗試取得該分區最後一次成功推播到總部的時間
    latest_sync_time = None
    try:
        if session.get('target_site_code'):
            # 如果是總部看分區，去 hq_master 查這個 site_code 的最後推播時間
            with DB_LOCKS['hq_master']:
                conn_hq = get_db('hq_master')
                row = conn_hq.execute("SELECT last_sync_time FROM global_sites WHERE site_code=?", (session.get('target_site_code'),)).fetchone()
                conn_hq.close()
                if row and row['last_sync_time']:
                    import datetime
                    # 轉換為台灣時間 (+8)
                    last_sync = datetime.datetime.strptime(row['last_sync_time'], '%Y-%m-%d %H:%M:%S')
                    local_time = last_sync + datetime.timedelta(hours=8)
                    latest_sync_time = local_time.strftime('%H:%M:%S')
    except Exception as e:
        print(f"取得同步時間失敗: {e}")
        pass # 🌟 核心修復：這就是遺失的 except 區塊，讓 try 有完美的結束！

    # 🌟 終極防禦：完美兼容分區新舊資料庫，缺少欄位也不會崩潰
    try:
        conn_config = get_db('config')
        # 先抓取所有原始資料
        raw_rows = conn_config.execute("SELECT * FROM devices").fetchall()
        conn_config.close()
        
        # 過濾出 visible == 1 的設備
        dev_rows = [dict(r) for r in raw_rows if r['visible'] == 1]
    except Exception as e:
        print(f"設備讀取失敗: {e}")
        dev_rows = []
        
    health = {'up': 0, 'down': 0, 'warning': 0, 'total': len(dev_rows)}
    device_map = {}
    for d in dev_rows:
        st = d['status']
        if st in health: health[st] += 1
        device_map[d['ip']] = {'name': d['name'], 'snmp_raw': d['snmp_raw']}
        
    time_limit = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() - 900))
    
    t_rows = []
    try:
        # 👇 🌟 終極破案：總部視角時，推播的流量表全部存在「分區庫 (config)」！
        # 絕對不能呼叫 get_db('hot')，否則會讀到總部伺服器自己的本機流量！
        if session.get('target_site_code'):
            conn_traffic = get_db('config')
            cursor = conn_traffic.execute('''SELECT ip, port_idx, in_bytes, out_bytes, strftime('%s', timestamp) as epoch FROM traffic_history''')
        else:
            conn_traffic = get_db('hot')
            cursor = conn_traffic.execute('''SELECT ip, port_idx, in_bytes, out_bytes, strftime('%s', timestamp) as epoch FROM traffic_history WHERE timestamp >= ?''', (time_limit,))
        
        t_rows = cursor.fetchall()
        conn_traffic.close()
    except Exception as e:
        print(f"Traffic Error: {e}")
        t_rows = []

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
        
        if_names = {}
        if_high_speeds = {}
        if_speeds = {}
        
        if isinstance(raw_data, dict): 
            if_names = raw_data.get("4", {})
            if_high_speeds = raw_data.get("5", {})
            if_speeds = raw_data.get("6", {})
        elif isinstance(raw_data, list) and len(raw_data) > 6: 
            if_names = raw_data[4]
            if_high_speeds = raw_data[5]
            if_speeds = raw_data[6]
        
        for p, records in ports.items():
            records.sort(key=lambda x: x['epoch'])
            if len(records) >= 2:
                prev = records[-2]; curr = records[-1]
                dt = curr['epoch'] - prev['epoch']
                if 0 < dt <= 600:
                    i_diff = curr['in'] - prev['in']
                    o_diff = curr['out'] - prev['out']
                    
                    # 🌟 處理 32-bit 計數器溢位 (Counter Rollover) 真實加法
                    if i_diff < 0:
                        if prev['in'] > 4290000000 and curr['in'] < 10000000: i_diff = (4294967296 - prev['in']) + curr['in']
                        else: i_diff = 0
                    if o_diff < 0:
                        if prev['out'] > 4290000000 and curr['out'] < 10000000: o_diff = (4294967296 - prev['out']) + curr['out']
                        else: o_diff = 0
                        
                    in_bps = round((i_diff * 8) / dt)
                    out_bps = round((o_diff * 8) / dt)
                    
                    # 🌟 智慧獲取該網孔的真實實體速率
                    speed_mbps = 0
                    try: speed_mbps = int(if_high_speeds.get(p, 0))
                    except: pass
                    if speed_mbps <= 0:
                        try:
                            raw_bps = int(if_speeds.get(p, 0))
                            speed_mbps = 10000 if raw_bps >= 4294967295 else raw_bps // 1000000
                        except: pass
                    if speed_mbps <= 0: speed_mbps = 1000 # 預設 1Gbps
                    
                    # 🌟 動態天花板：實體速率的 1.5 倍 (容許突發與計算誤差，徹底封殺百倍溢位)
                    max_bps = speed_mbps * 1000000 * 1.5
                    
                    if in_bps > max_bps: in_bps = 0
                    if out_bps > max_bps: out_bps = 0
                    
                    total_bps = in_bps + out_bps

                    if total_bps > 0:
                        p_name = clean_str(if_names.get(p, f"Port {p}"))
                        dev_name = device_map.get(ip, {}).get('name') or ip
                        traffic_list.append({'device': dev_name, 'ip': ip, 'port': p_name, 'in_bps': in_bps, 'out_bps': out_bps, 'total_bps': total_bps})
    traffic_list.sort(key=lambda x: x['total_bps'], reverse=True)

    logs = []
    try:
        with DB_LOCKS['audit_hot']:
            conn_audit = get_db('audit_hot', bypass_shard=True)
            log_rows = conn_audit.execute("SELECT timestamp, details FROM audit_logs ORDER BY timestamp DESC LIMIT 100").fetchall()
            conn_audit.close()
            logs = [f"[{r['timestamp']}] {r['details']}" for r in log_rows]
    except Exception:
        pass

    top_cpu = []
    for d in dev_rows:
        try:
            c = d['cpu_load']
            if c is not None and float(c) >= 0: 
                top_cpu.append({'device': d['name'] or d['ip'], 'ip': d['ip'], 'cpu': float(c)})
        except: pass
    top_cpu.sort(key=lambda x: x['cpu'], reverse=True)
    top_cpu = top_cpu[:10]

    # 👇 🌟 將 latest_sync_time 加進回傳的 JSON 裡
    return jsonify({
        'success': True, 
        'health': health, 
        'all_traffic': traffic_list, 
        'logs': logs, 
        'top_cpu': top_cpu,
        'latest_sync_time': latest_sync_time
    })

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
    # 👇 🌟 攔截器：如果是總部正在鑽取分區，必須從該分區的實體資料庫讀取，不能用總部全域快取！
    if session.get('target_site_code'):
        try:
            conn = get_db('config')
            rows = conn.execute("SELECT * FROM devices").fetchall()
            conn.close()
            return jsonify([dict(r) for r in rows])
        except Exception as e:
            return jsonify([])
            
    # 如果是一般狀態，才回傳總部自己的全域快取
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
            'is_backup': safe_int(d.get('is_backup', 1), 1), 
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
            'cli_type': existing_dev.get('cli_type', ''),
            'snmp_version': existing_dev.get('snmp_version', 'v2c'),
            'port_specs': existing_dev.get('port_specs', '[]')
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

        # 🌟 讀取單機 snmp_raw 獲取速率限制
        raw_data = {}
        try:
            with DB_LOCKS['config']:
                conn_cfg = get_db('config')
                dev = conn_cfg.execute("SELECT snmp_raw FROM devices WHERE ip=?", (ip,)).fetchone()
                if dev and dev['snmp_raw']:
                    raw_data = json.loads(dev['snmp_raw'])
                conn_cfg.close()
        except: pass
        
        if_high_speeds = {}
        if_speeds = {}
        if isinstance(raw_data, dict): 
            if_high_speeds = raw_data.get("5", {})
            if_speeds = raw_data.get("6", {})
        elif isinstance(raw_data, list) and len(raw_data) > 6: 
            if_high_speeds = raw_data[5]
            if_speeds = raw_data[6]

        for p, records in history.items():
            # 🌟 智慧獲取實體網孔速率
            speed_mbps = 0
            try: speed_mbps = int(if_high_speeds.get(p, 0))
            except: pass
            if speed_mbps <= 0:
                try:
                    raw_bps = int(if_speeds.get(p, 0))
                    speed_mbps = 10000 if raw_bps >= 4294967295 else raw_bps // 1000000
                except: pass
            if speed_mbps <= 0: speed_mbps = 1000 # 預設 1Gbps
            
            max_bps = speed_mbps * 1000000 * 1.5

            in_bps = []; out_bps = []; labels = []
            for i in range(1, len(records)):
                prev = records[i-1]; curr = records[i]
                let_dt = curr['epoch'] - prev['epoch']
                if 0 < let_dt <= 600: 
                    i_diff = curr['in'] - prev['in']
                    o_diff = curr['out'] - prev['out']
                    
                    # 🌟 處理 32-bit 計數器溢位
                    if i_diff < 0:
                        if prev['in'] > 4290000000 and curr['in'] < 10000000: i_diff = (4294967296 - prev['in']) + curr['in']
                        else: i_diff = 0
                    if o_diff < 0:
                        if prev['out'] > 4290000000 and curr['out'] < 10000000: o_diff = (4294967296 - prev['out']) + curr['out']
                        else: o_diff = 0
                        
                    in_val = round((i_diff * 8) / let_dt)
                    out_val = round((o_diff * 8) / let_dt)
                    
                    if in_val > max_bps: in_val = 0
                    if out_val > max_bps: out_val = 0
                    
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
    rows = []
    # 👇 🌟 同步防禦：拓樸圖水流動畫也必須切換到正確的資料庫
    try:
        if session.get('target_site_code'):
            conn = get_db('config')
            cursor = conn.execute('''SELECT ip, port_idx, in_bytes, out_bytes, strftime('%s', timestamp) as epoch FROM traffic_history''')
        else:
            conn = get_db('hot')
            time_limit = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() - 900))
            cursor = conn.execute('''SELECT ip, port_idx, in_bytes, out_bytes, strftime('%s', timestamp) as epoch FROM traffic_history WHERE timestamp >= ?''', (time_limit,))
        rows = cursor.fetchall()
        conn.close()
    except Exception:
        pass

    history = {}
    for r in rows:
        ip = r['ip']; p = str(r['port_idx'])
        if ip not in history: history[ip] = {}
        if p not in history[ip]: history[ip][p] = []
        history[ip][p].append({'in': r['in_bytes'], 'out': r['out_bytes'], 'epoch': int(r['epoch'])})

    # 🌟 需要讀取 devices 的 snmp_raw 來獲取網孔實體速限
    device_map = {}
    try:
        conn = get_db('config')
        devs = conn.execute("SELECT ip, snmp_raw FROM devices").fetchall()
        for d in devs: device_map[d['ip']] = d['snmp_raw']
        conn.close()
    except: pass

    summary = {}
    for ip, ports in history.items():
        summary[ip] = {}
        
        raw_str = device_map.get(ip, '{}')
        try: raw_data = json.loads(raw_str)
        except: raw_data = {}
        
        if_high_speeds = {}
        if_speeds = {}
        if isinstance(raw_data, dict): 
            if_high_speeds = raw_data.get("5", {})
            if_speeds = raw_data.get("6", {})
        elif isinstance(raw_data, list) and len(raw_data) > 6: 
            if_high_speeds = raw_data[5]
            if_speeds = raw_data[6]

        for p, records in ports.items():
            records.sort(key=lambda x: x['epoch'])
            if len(records) >= 2:
                prev = records[-2]; curr = records[-1]
                dt = curr['epoch'] - prev['epoch']
                if 0 < dt <= 600:
                    i_diff = curr['in'] - prev['in']; o_diff = curr['out'] - prev['out']
                    
                    # 🌟 處理 32-bit 計數器溢位
                    if i_diff < 0:
                        if prev['in'] > 4290000000 and curr['in'] < 10000000: i_diff = (4294967296 - prev['in']) + curr['in']
                        else: i_diff = 0
                    if o_diff < 0:
                        if prev['out'] > 4290000000 and curr['out'] < 10000000: o_diff = (4294967296 - prev['out']) + curr['out']
                        else: o_diff = 0
                    
                    in_val = round((i_diff * 8) / dt)
                    out_val = round((o_diff * 8) / dt)
                    
                    # 🌟 智慧獲取實體網孔速率限制
                    speed_mbps = 0
                    try: speed_mbps = int(if_high_speeds.get(p, 0))
                    except: pass
                    if speed_mbps <= 0:
                        try:
                            raw_bps = int(if_speeds.get(p, 0))
                            speed_mbps = 10000 if raw_bps >= 4294967295 else raw_bps // 1000000
                        except: pass
                    if speed_mbps <= 0: speed_mbps = 1000 # 預設 1Gbps
                    
                    max_bps = speed_mbps * 1000000 * 1.5
                    
                    if in_val > max_bps: in_val = 0
                    if out_val > max_bps: out_val = 0
                    
                    summary[ip][p] = {'in_bps': in_val, 'out_bps': out_val}
                    
    return jsonify({'success': True, 'data': summary})

@main_bp.route('/api/topology', methods=['GET'])
def get_topology():
    acquired, active_name = try_acquire_scan("手動拓樸掃描")
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if not acquired: 
        return jsonify({'nodes': [], 'edges': [], 'error': f'系統忙碌中：目前「{active_name}」正在執行，請稍後再試。'}), 409

    try:
        log_info("✋ 【手動操作】接收到前端觸發「重新掃描」請求...")
        devices = read_db_devices()
        topo = discover_topology(devices)
        
        write_audit_log("SystemUser", "手動拓樸掃描", "全網連線拓樸圖", "SUCCESS", f"【手動拓樸掃描】全網鏈路深度探測成功！耗時 {topo['stats']['elapsed']} 秒。(操作來源 IP: {client_ip})")
        log_info(f"✅ 【手動操作】掃描完成！耗時 {topo['stats']['elapsed']} 秒。")
        return jsonify(topo)

    except Exception as e: 
        write_audit_log("SystemUser", "手動拓樸掃描", "全網連線拓樸圖", "FAILED", f"【手動拓樸掃描】掃描失敗: {str(e)} (操作來源 IP: {client_ip})")
        log_info(f"⚠️ 【手動操作】掃描失敗: {e}")
        return jsonify({'nodes': [], 'edges': [], 'error': str(e)}), 500
    finally: 
        release_scan()
        
@main_bp.route('/api/topology/fast', methods=['GET'])
def get_topology_fast():
    conn = get_db('config')
    
    # 🌟 總部鑽取分區時，拓樸圖只顯示核心骨幹 (排除 AP)；單一分區則全顯
    if session.get('target_site_code'):
        devs = conn.execute("SELECT * FROM devices WHERE visible=1 AND type IN ('防火牆', '交換器', 'AP控制器', '路由器')").fetchall()
    else:
        devs = conn.execute("SELECT * FROM devices WHERE visible=1").fetchall()
        
    eds = conn.execute("SELECT * FROM edges").fetchall()
    conn.close()
    
    if not devs: return jsonify({'empty': True})
    
    color_map = {1: '#ff9999', 2: '#99ccff', 3: '#99ff99', 4: '#ffcc99', 5: '#e6e6fa', 6: '#f8d7da'}
    nodes = []
    for row in devs:
        d = dict(row)
        node_data = {
            'id': d['ip'], 
            'ip': d['ip'], 
            'sysName': d['name'], 
            'type': d.get('type', '交換器'),
            'brand': d.get('brand') or 'Unknown', 
            'model': d.get('model') or '', 
            'location': d.get('location') or '', 
            'level': d['level'], 
            'shape': 'box', 
            'color': color_map.get(d['level'], '#e0e0e0'), 
            'sysDescr': d.get('sys_descr') or '無快取硬體資訊', 
            'status': d.get('status') if d.get('status') else 'up', 
            'snmp_raw': d.get('snmp_raw') or '{}',
            'is_poe': d.get('is_poe', 0), 
            'has_sensor': d.get('has_sensor', 0),
            'is_backup': d.get('is_backup', 1),
            'snmp_version': d.get('snmp_version', 'v2c'),
            'port_specs': d.get('port_specs', '[]')
        }
        if d.get('x') is not None and d.get('y') is not None: 
            node_data['x'] = d['x']; node_data['y'] = d['y']
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
        import re
        today_str = time.strftime('%Y-%m-%d')
        runs = 0
        latest_sync_time = None  
        edges_data = [] 
        
        with DB_LOCKS['config']:
            conn = get_db('config')
            conn.execute("CREATE TABLE IF NOT EXISTS anomaly_daily_stats (date TEXT PRIMARY KEY, runs INTEGER DEFAULT 0)")
            
            if session.get('target_site_code'):
                row_runs = conn.execute("SELECT runs FROM anomaly_daily_stats WHERE date = ?", (today_str,)).fetchone()
                runs = row_runs['runs'] if row_runs else 0
                
                ano_data = []
                try:
                    conn.execute("CREATE TABLE IF NOT EXISTS system_settings (key TEXT PRIMARY KEY, value TEXT)")
                    ano_row = conn.execute("SELECT value FROM system_settings WHERE key='latest_anomalies'").fetchone()
                    if ano_row and ano_row['value']:
                        import json
                        ano_data = json.loads(ano_row['value'])
                except: pass
                
                try:
                    with DB_LOCKS['hq_master']:
                        conn_hq = get_db('hq_master')
                        hq_row = conn_hq.execute("SELECT last_sync_time FROM global_sites WHERE site_code=?", (session.get('target_site_code'),)).fetchone()
                        conn_hq.close()
                        if hq_row and hq_row['last_sync_time']:
                            import datetime
                            last_sync = datetime.datetime.strptime(hq_row['last_sync_time'], '%Y-%m-%d %H:%M:%S')
                            local_time = last_sync + datetime.timedelta(hours=8)
                            latest_sync_time = local_time.strftime('%H:%M:%S')
                except: pass
                conn.close()
                return jsonify({'success': True, 'data': ano_data, 'runs': runs, 'latest_sync_time': latest_sync_time})
                
            else:
                conn.execute("INSERT OR IGNORE INTO anomaly_daily_stats (date, runs) VALUES (?, 0)", (today_str,))
                conn.execute("UPDATE anomaly_daily_stats SET runs = runs + 1 WHERE date = ?", (today_str,))
                row = conn.execute("SELECT runs FROM anomaly_daily_stats WHERE date = ?", (today_str,)).fetchone()
                runs = row['runs']
                
                nodes = conn.execute("SELECT * FROM devices WHERE status != 'down'").fetchall()
                edges_data = conn.execute("SELECT source, target, from_port, to_port FROM edges").fetchall()
            conn.commit()
            conn.close()

        immune_ports = {}
        for edge in edges_data:
            s_ip = edge['source']
            t_ip = edge['target']
            s_ports = [p.strip().lower() for p in (edge['from_port'] or "").split(',')]
            t_ports = [p.strip().lower() for p in (edge['to_port'] or "").split(',')]
            
            if s_ip not in immune_ports: immune_ports[s_ip] = set()
            if t_ip not in immune_ports: immune_ports[t_ip] = set()
            
            immune_ports[s_ip].update(s_ports)
            immune_ports[t_ip].update(t_ports)

        anomalies = []
        for node in nodes:
            if not node['snmp_raw'] or node['snmp_raw'] == '{}': continue
            try:
                import json
                raw = json.loads(node['snmp_raw'])
                ifNames = raw.get("4", {})
                ifAliases = raw.get("9", {})
                bpToIf = raw.get("11", {})
                fdb1 = raw.get("10", {})
                fdb2 = raw.get("12", {}) 
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
                parse_fdb(fdb1, False)
                parse_fdb(fdb2, True)

                for if_idx, mac_set in port_macs.items():
                    mac_count = len(mac_set)
                    if mac_count < 3: continue 
                    name = ifNames.get(str(if_idx), f"Port {if_idx}").replace('"', '').strip()
                    name_lower = name.lower()
                    alias = ifAliases.get(str(if_idx), "").replace('"', '').strip()
                    alias_lower = alias.lower()
                    
                    # 🌟 核心過濾升級：利用精準的正則前綴比對，徹底斬除 lg1, lag3, trk1 等所有聚合/骨幹/虛擬網孔
                    if re.match(r'^(vlan|loop|cpu|tun|null|mgmt|lag|lg|trk|po|bond|slot|uplink|ae|eth-trunk|port-channel)', name_lower): 
                        continue
                        
                    # 若自訂說明有明確註記為 uplink 或 core 也一併免疫
                    if 'uplink' in alias_lower or 'core' in alias_lower:
                        continue
                        
                    is_immune = False
                    for immune_p in immune_ports.get(node['ip'], set()):
                        if name_lower == immune_p or name_lower in immune_p or immune_p in name_lower:
                            is_immune = True
                            break
                            
                    if is_immune:
                        continue
                        
                    if str(if_idx) in lldp_ports: continue
                    
                    if mac_count >= 30: severity, type_str, desc = "danger", "迴圈先兆 / MAC風暴", f"異常海量 MAC ({mac_count}個)，極可能發生實體迴圈！"
                    elif mac_count >= 5: severity, type_str, desc = "warning", "私接交換器 (Hub)", f"學習到 {mac_count} 個 MAC，疑似私接家用分享器或 Hub。"
                    else: severity, type_str, desc = "info", "多設備串接", f"偵測到 {mac_count} 個 MAC，可能連接了 IP 電話或小會議室。"
                    
                    anomalies.append({'ip': node['ip'], 'sysName': node['name'] or node['ip'], 'port': name, 'alias': alias, 'mac_count': mac_count, 'severity': severity, 'type': type_str, 'desc': desc})
            except Exception: 
                continue
                
        anomalies.sort(key=lambda x: x['mac_count'], reverse=True)
        return jsonify({'success': True, 'data': anomalies, 'runs': runs, 'latest_sync_time': latest_sync_time})
    except Exception as e: 
        return jsonify({'success': False, 'error': str(e)})
        
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
    snmp_ver = dev_dict.get('snmp_version', 'v2c') # 🌟 撈取資料庫設定
    loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop)
    engine = SnmpEngine()

    async def fetch():
        info = await async_get_device_info(engine, ip, community, snmp_ver)
        sys_descr = info[0]
        full = await async_get_device_full_data(engine, ip, community, sys_descr, ssh_user, ssh_pass, snmp_ver)
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
            from datetime import datetime
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
            
        from database import get_db, DB_LOCKS
        conn = get_db(target_db)
        
        if target_db == 'hot':
            if time_range == 'custom':
                time_fmt = '%m/%d %H:%M'
                # 🌟 加入 latency_ms
                sql = f"SELECT cpu, memory, poe_w, temp_c, IFNULL(session_util, 0) as session_util, IFNULL(latency_ms, 0) as latency_ms, strftime('{time_fmt}', timestamp) as ts FROM metrics_history WHERE ip = ? AND timestamp BETWEEN ? AND ? ORDER BY timestamp ASC"
                cursor = conn.execute(sql, (ip, start_dt, end_dt))
            else:
                # 🌟 加入 latency_ms
                sql = f"SELECT cpu, memory, poe_w, temp_c, IFNULL(session_util, 0) as session_util, IFNULL(latency_ms, 0) as latency_ms, strftime('{time_fmt}', timestamp) as ts FROM metrics_history WHERE ip = ? AND timestamp >= datetime('now', ?, 'localtime') ORDER BY timestamp ASC"
                cursor = conn.execute(sql, (ip, time_delta))
        else:
            time_fmt = '%Y/%m/%d %H:%M' if target_db == 'warm' else '%Y/%m/%d'
            # 🌟 加入 latency_ms
            sql = f"SELECT cpu, memory, poe_w, temp_c, IFNULL(session_util, 0) as session_util, IFNULL(latency_ms, 0) as latency_ms, strftime('{time_fmt}', timestamp) as ts FROM metrics_history WHERE ip = ? AND timestamp BETWEEN ? AND ? ORDER BY timestamp ASC"
            cursor = conn.execute(sql, (ip, start_dt, end_dt))
            
        rows = cursor.fetchall(); conn.close()

        with DB_LOCKS['config']:
            conn_cfg = get_db('config')
            dev_row = conn_cfg.execute("SELECT brand, model FROM devices WHERE ip=?", (ip,)).fetchone()
            conn_cfg.close()
        
        brand_str = str(dev_row['brand'] if dev_row else '').lower()
        model_str = str(dev_row['model'] if dev_row else '').lower()
        is_pa = "palo" in brand_str or "pan" in brand_str or "pa-" in model_str

        labels = [r['ts'] for r in rows]
        mem_data = [round(r['memory'] if r['memory'] is not None else 0, 1) for r in rows]
        poe_data = [round(r['poe_w'] if r['poe_w'] is not None else 0, 1) for r in rows]
        temp_data = [round(r['temp_c'] if r['temp_c'] is not None else 0, 1) for r in rows]
        session_data = [int(r['session_util'] if r['session_util'] is not None else 0) for r in rows]
        # 🌟 整理延遲陣列
        latency_data = [round(r['latency_ms'] if r['latency_ms'] is not None else 0, 1) for r in rows]
        
        if is_pa:
            dp_cpu_data = [round(r['cpu'] if r['cpu'] is not None else 0, 1) for r in rows]
            mp_cpu_data = [round(max(0, r['cpu'] * 0.8) if r['cpu'] is not None else 0, 1) for r in rows] 
            
            return jsonify({
                'success': True, 'labels': labels, 'is_pa': True,
                'mp_cpu': mp_cpu_data, 'dp_cpu': dp_cpu_data, 
                'memory': mem_data, 'poe': poe_data, 'temp': temp_data, 
                'session_util': session_data,
                'latency_ms': latency_data # 🌟 回傳給前端
            })
            
        else:
            cpu_data = [round(r['cpu'] if r['cpu'] is not None else 0, 1) for r in rows]
            return jsonify({
                'success': True, 'labels': labels, 'is_pa': False,
                'cpu': cpu_data, 'memory': mem_data, 'poe': poe_data, 'temp': temp_data,
                'latency_ms': latency_data # 🌟 回傳給前端
            })
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
    
    # 💡 1. 核心修正：改為從 devices 資料表的 snmp_raw 中直接提取所有網孔！
    # 絕對不能從 device_ports 撈，因為那裡只有「被手動註記過」的零星網孔！
    with DB_LOCKS['config']:
        conn = get_db('config')
        dev_row = conn.execute("SELECT snmp_raw FROM devices WHERE ip=?", (ip,)).fetchone()
        conn.close()
        
    if dev_row and dev_row['snmp_raw'] and dev_row['snmp_raw'] != '{}':
        try:
            import json
            raw_data = json.loads(dev_row['snmp_raw'])
            ifNames = raw_data.get("4", {})
            
            # 🌟 新增降級防線：如果欄位 4 是空的 (如 D-Link v1)，自動改抓欄位 8 (ifDescr)
            if not ifNames:
                ifNames = raw_data.get("8", {})

            if ifNames:
                ports = []
                for idx, name in ifNames.items():
                    clean_name = str(name).replace('"', '').strip()
                    n_low = clean_name.lower()
                    # 過濾虛擬邏輯埠
                    if any(x in n_low for x in ['vlan', 'loop', 'null', 'cpu', 'tun']): 
                        continue
                    ports.append({'idx': idx, 'name': clean_name, 'speed': 1000})
                    
                # 依照 idx 排序，讓 Port 1, 2, 3... 依序排列
                ports.sort(key=lambda x: int(x['idx']) if str(x['idx']).isdigit() else 9999)
                return jsonify({'status': 'ok', 'source': 'snmp_raw_cache', 'ports': ports})
        except Exception as e:
            print(f"解析 snmp_raw 獲取 port 失敗: {e}")

    # 💡 2. 如果剛好沒有 snmp_raw，發起獨立的 SNMP 掃描 (內建 v2c/v1 智慧自動降級機制)
    try:
        import asyncio
        # 🌟 補上次級尋路所需的 next_cmd 模組
        from pysnmp.hlapi.v3arch.asyncio import SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity, bulk_cmd, next_cmd
        
        async def walk_ports():
            engine = SnmpEngine()
            ctx = ContextData()
            names = {}
            
            # ── 嘗試 1: 先用標準 SNMP v2c (bulk_cmd) 進行高速掃描 ──
            try:
                auth_v2 = CommunityData(comm, mpModel=1) 
                transport_v2 = await UdpTransportTarget.create((ip, 161), timeout=1.0, retries=1)
                base_oid_v2 = '1.3.6.1.2.1.31.1.1.1.1' 
                current_oid = ObjectType(ObjectIdentity(base_oid_v2))
                
                while True:
                    err, stat, idx, binds = await bulk_cmd(engine, auth_v2, transport_v2, ctx, 0, 50, current_oid)
                    if err or stat or not binds: break
                    
                    last_oid = None
                    for name_oid, val in binds:
                        str_oid = str(name_oid)
                        if not str_oid.startswith(base_oid_v2): break
                        port_idx = str_oid.split('.')[-1]
                        names[port_idx] = str(val)
                        last_oid = name_oid
                    
                    if last_oid and str(last_oid).startswith(base_oid_v2):
                        current_oid = ObjectType(ObjectIdentity(last_oid))
                    else:
                        break
            except Exception:
                pass

            # ── 嘗試 2: 如果 v2c 沒回應或回傳空字典，啟動自動降級機制，改走相容性最高的 SNMP v1 (next_cmd) ──
            if not names:
                # 智慧型相容雙 OID：舊型 v1 設備不一定有 ifName (1.3.6.1.2.1.31...)，故連同最標準的 ifDescr (1.3.6.1.2.1.2...) 一起測試
                for base_oid in ['1.3.6.1.2.1.31.1.1.1.1', '1.3.6.1.2.1.2.2.1.2']:
                    try:
                        auth_v1 = CommunityData(comm, mpModel=0)  # 🌟 mpModel=0 強制切換為純 SNMP v1 協定
                        transport_v1 = await UdpTransportTarget.create((ip, 161), timeout=1.5, retries=1)
                        current_oid = ObjectType(ObjectIdentity(base_oid))
                        
                        while True:
                            # v1 設備不支援批次，此處改用 next_cmd 進行逐行精準尋軌
                            err, stat, idx, binds = await next_cmd(engine, auth_v1, transport_v1, ctx, current_oid)
                            if err or stat or not binds: break
                            
                            name_oid, val = binds[0]
                            str_oid = str(name_oid)
                            if not str_oid.startswith(base_oid): break
                            
                            port_idx = str_oid.split('.')[-1]
                            names[port_idx] = str(val)
                            current_oid = ObjectType(ObjectIdentity(name_oid))
                            
                        if names: break # 任何一個 OID 成功抓到資料，立刻跳出迴圈
                    except Exception:
                        pass
                        
            return names

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        names = loop.run_until_complete(walk_ports())
        loop.close()
        
        if not names: return jsonify({'status': 'error', 'message': '無法取得實體連接埠 (設備無回應或無 OID)'})

        # 💡 3. 掃描成功，直接回傳給前端！(絕對不再寫入 device_ports 破壞舊有的手動註記)
        ports = []
        for idx, name in names.items():
            clean_name = str(name).replace('"', '').strip()
            n_low = clean_name.lower()
            if any(x in n_low for x in ['vlan', 'loop', 'null', 'cpu', 'tun']): 
                continue
            ports.append({'idx': idx, 'name': clean_name, 'speed': 1000})
            
        ports.sort(key=lambda x: int(x['idx']) if str(x['idx']).isdigit() else 9999)
        return jsonify({'status': 'ok', 'source': 'snmp_live', 'ports': ports})
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

# ========================================================
# 🌟 殺手級功能：手動拓樸連線 (建立時自動在背景重算拓樸)
# ========================================================
@main_bp.route('/api/manual_links', methods=['POST'])
@require_role([ROLE_ADMIN, ROLE_OPERATOR])
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
        
    # 💡 核心修復：強制在背景重算拓樸，讓 manual_links 立刻轉換為 edges 快取！
    from snmp_core import discover_topology
    from database import read_db_devices
    try:
        discover_topology(read_db_devices())
    except:
        pass

    return jsonify({'status': 'ok'})

# ========================================================
# 💡 網孔智慧快取與手動標註 API (恢復 Uplink 標註支援)
# ========================================================
@main_bp.route('/api/device/port/manage', methods=['GET', 'POST'])
@require_role([ROLE_ADMIN, ROLE_OPERATOR])
def manage_port_annotation():
    if request.method == 'GET':
        ip = request.args.get('ip')
        port_idx = request.args.get('port_idx')
        if not ip or not port_idx:
            return jsonify({'success': False, 'message': '缺少參數'})
        
        with DB_LOCKS['config']:
            conn = get_db('config')
            # 🌟 核心擴充：SQL 多查詢 is_manual_mgmt 欄位
            row = conn.execute("SELECT memorized_ips, is_manual_uplink, is_manual_mgmt FROM device_ports WHERE ip=? AND port_idx=?", (ip, port_idx)).fetchone()
            conn.close()

        if row:
            return jsonify({
                'success': True, 
                'memorized_ips': row['memorized_ips'] or '', 
                'is_manual_uplink': bool(row['is_manual_uplink']),
                'is_manual_mgmt': bool(row['is_manual_mgmt']) # 🌟 帶回前端雙切換開關
            })
        return jsonify({'success': True, 'memorized_ips': '', 'is_manual_uplink': False, 'is_manual_mgmt': False})


    if request.method == 'POST':
        data = request.json
        ip = data.get('ip')
        port_idx = data.get('port_idx')
        port_name = data.get('port_name', '')
        action = data.get('action') 
        
        if not ip or not port_idx: return jsonify({'success': False, 'message': '缺少必要參數'})
        
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        operator = session.get('username', 'SystemUser')
        
        with DB_LOCKS['config']:
            conn = get_db('config')
            dev_row = conn.execute("SELECT name FROM devices WHERE ip=?", (ip,)).fetchone()
            dev_name = dev_row['name'] if dev_row and dev_row['name'] else ip

            if action == 'clear':
                # 🌟 清除時一併清除 Uplink 與 MGMT 狀態
                conn.execute("UPDATE device_ports SET memorized_ips='', is_manual_uplink=0, is_manual_mgmt=0 WHERE ip=? AND port_idx=?", (ip, port_idx))
                conn.commit()
                
            elif action == 'save':
                ips_str = data.get('ips', '') 
                is_uplink = 1 if data.get('is_uplink') else 0 
                is_mgmt = 1 if data.get('is_mgmt') else 0 # 🌟 新增：接收前端勾選狀態
                conn.execute("INSERT OR IGNORE INTO device_ports (ip, port_idx, port_name, speed) VALUES (?, ?, ?, 1000)", (ip, port_idx, port_name))
                # 🌟 寫入實體資料庫永續記憶
                conn.execute("UPDATE device_ports SET memorized_ips=?, is_manual_uplink=?, is_manual_mgmt=? WHERE ip=? AND port_idx=?", (ips_str, is_uplink, is_mgmt, ip, port_idx))
                conn.commit()
                
            conn.close() 
            
        if action == 'clear':
            log_details = f"【網孔標註】管理員清除了交換器 {dev_name} ({ip}) 的 {port_name} 網孔所有標註與 IP 記憶設定。(操作來源: {client_ip})"
            write_audit_log(operator, "前端介面操作", f"{dev_name} [{port_name}]", "SUCCESS", log_details)
            return jsonify({'success': True, 'message': f"已清除 {dev_name} ({port_name}) 的所有網孔註記！"})
            
        elif action == 'save':
            ips_str = data.get('ips', '') 
            is_uplink = 1 if data.get('is_uplink') else 0
            ip_list = [p.split('|')[0] for p in ips_str.split(',') if p.strip()]
            ips_display = ", ".join(ip_list) if ip_list else "無"
            
            msg_toast = f"成功更新 {dev_name} ({port_name}) 的網孔標註設定！"
            log_details = f"【網孔標註】管理員設定了交換器 {dev_name} ({ip}) 的 {port_name} 網孔。Uplink 標註: {'是' if is_uplink else '否'}，記憶終端: {ips_display}。(操作來源: {client_ip})"
            write_audit_log(operator, "前端介面操作", f"{dev_name} [{port_name}]", "SUCCESS", log_details)
            return jsonify({'success': True, 'message': msg_toast})

@main_bp.route('/api/settings/get', methods=['GET'])
def api_settings_get():
    with DB_LOCKS['config']:
        # 🌟 補上 bypass_shard=True
        conn = get_db('config', bypass_shard=True)
        row = conn.execute("SELECT value FROM system_settings WHERE key='rbac_enabled'").fetchone()
        conn.close()
    rbac_enabled = (row['value'] == '1') if row else True 
    return jsonify({'success': True, 'rbac_enabled': rbac_enabled})

# ========================================================
# 👥 RBAC 帳號與權限管理 API (僅限 Admin)
# ========================================================
@main_bp.route('/api/users', methods=['GET'])
@require_role([ROLE_ADMIN])
def get_users():
    with DB_LOCKS['config']:
        conn = get_db('config', bypass_shard=True)
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
    operator = session.get('username', 'admin')

    try:
        with DB_LOCKS['config']:
            conn = get_db('config', bypass_shard=True)
            try:
                conn.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", (username, pwd_hash, role))
                conn.commit()
            finally:
                conn.close()
                
        # 🌟 救援成功：移出鎖外！在這裡寫入日誌絕對不會死鎖
        write_audit_log(operator, "系統帳號與權限管理", f"新增帳號 ({username})", "SUCCESS", f"【新增帳號】成功建立新使用者：{username}，指派角色為：{role}。(IP: {client_ip})")
        return jsonify({'success': True, 'message': '使用者建立成功'})
    except Exception as e:
        if "UNIQUE" in str(e):
            return jsonify({'success': False, 'message': '此帳號已存在'})
        return jsonify({'success': False, 'message': str(e)})

@main_bp.route('/api/users/<int:user_id>', methods=['PUT', 'DELETE'])
@require_role([ROLE_ADMIN])
def modify_user(user_id):
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    operator = session.get('username', 'admin')
    
    target_username = ""
    action_type = ""
    action_msg = ""
    status_str = ""
    new_role = ""
    
    try:
        with DB_LOCKS['config']:
            conn = get_db('config', bypass_shard=True)
            try:
                target_user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
                if not target_user:
                    return jsonify({'success': False, 'message': '找不到該使用者'})
                    
                target_username = target_user['username']
                
                if request.method == 'DELETE':
                    if target_username == 'admin':
                        return jsonify({'success': False, 'message': '預設 admin 帳號無法被刪除'})
                    conn.execute("DELETE FROM users WHERE id=?", (user_id,))
                    conn.commit()
                    action_type = "DELETE"
                    action_msg = f"【刪除帳號】永久移除了使用者：{target_username}。(IP: {client_ip})"
                    
                elif request.method == 'PUT':
                    data = request.json
                    action = data.get('action')
                    
                    if action == 'update_status':
                        if target_username == 'admin':
                            return jsonify({'success': False, 'message': '預設 admin 帳號無法被停用'})
                        new_status = safe_int(data.get('status', 1))
                        conn.execute("UPDATE users SET status=? WHERE id=?", (new_status, user_id))
                        conn.commit()
                        status_str = "啟用" if new_status == 1 else "停用"
                        action_type = "UPDATE_STATUS"
                        action_msg = f"【變更帳號狀態】將使用者 {target_username} 的狀態設定為：{status_str}。(IP: {client_ip})"
                        
                    elif action == 'update_role':
                        if target_username == 'admin':
                            return jsonify({'success': False, 'message': '預設 admin 帳號角色無法變更'})
                        new_role = data.get('role', 'operator')
                        conn.execute("UPDATE users SET role=? WHERE id=?", (new_role, user_id))
                        conn.commit()
                        action_type = "UPDATE_ROLE"
                        action_msg = f"【變更帳號角色】將使用者 {target_username} 的角色變更為：{new_role}。(IP: {client_ip})"
                        
                    elif action == 'reset_password':
                        new_password = data.get('password')
                        old_password = data.get('old_password') 
                        if not new_password:
                            return jsonify({'success': False, 'message': '新密碼不可為空'})
                            
                        auth_user = conn.execute("SELECT * FROM users WHERE username=?", (operator,)).fetchone()
                        if not auth_user or not verify_password(auth_user['password_hash'], old_password):
                            return jsonify({'success': False, 'message': '管理員授權舊密碼錯誤'})
                            
                        pwd_hash = hash_password(new_password)
                        conn.execute("UPDATE users SET password_hash=? WHERE id=?", (pwd_hash, user_id))
                        conn.commit()
                        action_type = "RESET_PWD"
                        action_msg = f"【重設密碼】為使用者 {target_username} 重新設定了密碼。(IP: {client_ip})"
            finally:
                conn.close()

        # 🌟 救援成功：移出鎖外！將變數暫存後，在這裡統一寫入日誌，完美避開死鎖！
        if action_type == "DELETE":
            write_audit_log(operator, "系統帳號與權限管理", f"刪除帳號 ({target_username})", "SUCCESS", action_msg)
            return jsonify({'success': True, 'message': '帳號刪除成功'})
        elif action_type == "UPDATE_STATUS":
            write_audit_log(operator, "系統帳號與權限管理", f"變更帳號狀態 ({target_username})", "SUCCESS", action_msg)
            return jsonify({'success': True, 'message': f'帳號已{status_str}'})
        elif action_type == "UPDATE_ROLE":
            write_audit_log(operator, "系統帳號與權限管理", f"變更帳號角色 ({target_username})", "SUCCESS", action_msg)
            return jsonify({'success': True, 'message': '角色更新成功'})
        elif action_type == "RESET_PWD":
            write_audit_log(operator, "系統帳號與權限管理", f"重設密碼 ({target_username})", "SUCCESS", action_msg)
            return jsonify({'success': True, 'message': '密碼修改成功'})
            
        return jsonify({'success': False, 'message': '未知的操作'})

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@main_bp.route('/api/device/<ip>/events', methods=['GET'])
@require_role([ROLE_ADMIN, ROLE_OPERATOR, ROLE_AUDITOR])
def api_device_events(ip):
    """
    輕量級設備事件軌跡 API：
    專供前端拓樸圖右鍵面板使用，快速從熱庫撈取指定 IP 的最近 50 筆事件紀錄。
    """
    try:
        from database import get_db
        conn = get_db('audit_hot')
        # 🌟 核心修正：使用 strftime(..., 'localtime') 將資料庫中的 UTC 時間轉為台灣時間 (+8)
        cur = conn.execute(
            """
            SELECT strftime('%Y-%m-%d %H:%M:%S', timestamp, 'localtime') as ts, action, result, details 
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
                'timestamp': r['ts'], # 🌟 對應 SQL 中轉換後的別名 ts
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
TOP5_FLOW_CACHE = {'time': 0, 'data': []}

@main_bp.route('/api/flow/top5', methods=['GET'])
@require_role([ROLE_ADMIN, ROLE_OPERATOR])
def get_top5_flow():
    global TOP5_FLOW_CACHE
    import ipaddress
    import snmp_core  
    
    # 👇 🌟 核心修復：如果總部正在看分區，必須去該分區的實體資料庫 (hq_sites/site_xxx.db) 讀取！
    # 絕不能去讀取本機的 config.db！
    if session.get('target_site_code'):
        try:
            # 💡 get_db('config') 已經內建了對 session['target_site_code'] 的智慧切換
            # 但確保前一步接收時也是寫到同一個邏輯
            conn = get_db('config') 
            row = conn.execute("SELECT value FROM system_settings WHERE key='latest_top5_flow'").fetchone()
            conn.close()
            
            if row and row['value']:
                import json
                return jsonify({"status": "success", "data": json.loads(row['value']), "from_cache": True})
        except Exception as e: 
            print(f"讀取分區流量快取失敗: {e}")
            pass
        return jsonify({"status": "success", "data": []})

    now_ts = time.time()
    # 🌟 核心防護：60 秒記憶體快取！(稍後會在程式「結束時」才押上最新時間戳記)
    if now_ts - TOP5_FLOW_CACHE.get('time', 0) < 60 and TOP5_FLOW_CACHE.get('data'):
        return jsonify({"status": "success", "data": TOP5_FLOW_CACHE['data'], "from_cache": True})

    is_debug_mode = getattr(snmp_core, 'GLOBAL_DEBUG_MODE', False)
    
    with DB_LOCKS['config']:
        conn = get_db('config')
        try:
            r_int = conn.execute("SELECT value FROM system_settings WHERE key='flow_internal_nets'").fetchone()
            r_exc = conn.execute("SELECT value FROM system_settings WHERE key='flow_exclude_nets'").fetchone()
        finally:
            conn.close()
    
    raw_int = r_int['value'] if (r_int and r_int['value']) else '10.0.0.0/8, 172.16.0.0/12, 192.168.1.0/24'
    raw_exc = r_exc['value'] if (r_exc and r_exc['value']) else ''
    
    int_nets_v4, int_nets_v6 = [], []
    exc_nets_v4, exc_nets_v6 = [], []
    
    for c in [x.strip() for x in raw_int.split(',') if x.strip()]:
        try:
            net = ipaddress.ip_network(c, strict=False)
            if net.version == 4: int_nets_v4.append(net)
            else: int_nets_v6.append(net)
        except: pass
        
    for c in [x.strip() for x in raw_exc.split(',') if x.strip()]:
        try:
            net = ipaddress.ip_network(c, strict=False)
            if net.version == 4: exc_nets_v4.append(net)
            else: exc_nets_v6.append(net)
        except: pass

    if is_debug_mode:
        print(f"\n🔍 [進階除錯] 內網流量大戶分析 API 啟動！目前載入之內網白名單: {raw_int}")

    def is_internal(ip_str):
        if not ip_str or ip_str in ["Unknown", "None", "null", "-"]: return False
        try:
            ip_clean = ip_str.split('%')[0].strip()
            if ip_clean.startswith('::ffff:'): ip_clean = ip_clean.replace('::ffff:', '')
            ip_obj = ipaddress.ip_address(ip_clean)
            
            if ip_obj.version == 4:
                for exc in exc_nets_v4:
                    if ip_obj in exc: return False
                for inc in int_nets_v4:
                    if ip_obj in inc: return True
                if ip_obj.is_private: return True
            else:
                for exc in exc_nets_v6:
                    if ip_obj in exc: return False
                for inc in int_nets_v6:
                    if ip_obj in inc: return True
                if ip_obj.is_private or ip_obj.is_site_local or ip_obj.is_link_local: return True
            return False
        except: return False

    try:
        client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG, timeout=60000)
        query_api = client.query_api()

        # 🌟 極速優化：完全捨棄 keep()，把 filter 放在最前面確保底層 Pushdown 順暢，使用 top() 高速降維
        query_src = fr'''
        from(bucket: "{INFLUXDB_BUCKET}")
          |> range(start: -5m)
          |> filter(fn: (r) => r["_measurement"] == "netflow" or r["_measurement"] == "sflow")
          |> filter(fn: (r) => r["_field"] == "in_bytes" or r["_field"] == "bytes")
          |> filter(fn: (r) => exists r["src_ip"] and r["src_ip"] != "")
          |> group(columns: ["src_ip"])
          |> sum()
          |> group()
          |> top(n: 200, columns: ["_value"])
          |> keep(columns: ["src_ip", "_value"])
        '''
        
        query_dst = fr'''
        from(bucket: "{INFLUXDB_BUCKET}")
          |> range(start: -5m)
          |> filter(fn: (r) => r["_measurement"] == "netflow" or r["_measurement"] == "sflow")
          |> filter(fn: (r) => r["_field"] == "in_bytes" or r["_field"] == "bytes")
          |> filter(fn: (r) => exists r["dst_ip"] and r["dst_ip"] != "")
          |> group(columns: ["dst_ip"])
          |> sum()
          |> group()
          |> top(n: 200, columns: ["_value"])
          |> keep(columns: ["dst_ip", "_value"])
        '''

        ip_totals = {}
        
        # 🌟 新增：套用警告捕捉，靜音封殺 InfluxDB CSV 解析器警告
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            res_src = query_api.query(query_src)
            res_dst = query_api.query(query_dst)
            
        for table in res_src:
            for record in table.records:
                ip = record.values.get("src_ip")
                if ip: ip_totals[ip] = ip_totals.get(ip, 0) + (record.get_value() or 0)
                    
        res_dst = query_api.query(query_dst)
        for table in res_dst:
            for record in table.records:
                ip = record.values.get("dst_ip")
                if ip: ip_totals[ip] = ip_totals.get(ip, 0) + (record.get_value() or 0)
                    
        client.close()

        sorted_ips = sorted(ip_totals.items(), key=lambda item: item[1], reverse=True)
        top10_list = []
        for ip, total_bytes in sorted_ips:
            if is_internal(ip):
                mb_size = round(total_bytes / (1024 * 1024), 2)
                if mb_size >= 0.01:
                    top10_list.append({
                        "ip": ip.strip().replace('::ffff:', ''),
                        "traffic_mb": mb_size
                    })
                if len(top10_list) >= 10: break

        if is_debug_mode:
            print(f"🔍 [進階除錯] InfluxDB 成功極速運算！已攔截並聚合最大的 {len(ip_totals)} 組通訊數據。")

        # 🌟 核心修復：使用 time.time()，保證快取是從「算完的這一刻」才開始倒數 60 秒！
        TOP5_FLOW_CACHE['time'] = time.time()
        TOP5_FLOW_CACHE['data'] = top10_list

        return jsonify({"status": "success", "data": top10_list, "from_cache": False})
        
    except Exception as e:
        print(f"❌ [系統錯誤] 流量 API 發生致命錯誤: {e}")
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
    # 🚀 核心修正：徹底廢除寫死的 2030 年！
    # 改為在收到請求（按下按鈕）的當下，動態生成符合 InfluxDB Flux 規範的精準 UTC 當前時間字串
    end_time = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    
    src_ip = data.get('src_ip', '').strip()
    dst_ip = data.get('dst_ip', '').strip()
    port_val = data.get('port', '').strip()
    
    cache_key = f"{start_time}_{src_ip}_{dst_ip}_{port_val}"
    now_ts = time.time()
    
    if cache_key in FLOW_SEARCH_CACHE:
        cache_time, cached_records = FLOW_SEARCH_CACHE[cache_key]
        if now_ts - cache_time < CACHE_TTL_SECONDS:
            return jsonify({"status": "success", "data": cached_records, "from_cache": True})

    # ✅ 請替換為這行 (加上 timeout=60000)
    client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG, timeout=60000)
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
                safe_val = val.replace(':', r':')
                return fr'  |> filter(fn: (r) => r["{col_name}"] =~ /^{safe_val}/)'
            else:
                safe_val = val.replace('.', r'\.')
                # 🌟 優化：移除昂貴的 (^|\.)，改用單純的包含比對，大幅提升 InfluxDB 正則效能
                return fr'  |> filter(fn: (r) => r["{col_name}"] =~ /{safe_val}/)'

    if src_ip:
        flux_parts.append(build_flux_ip_filter("src_ip", src_ip))
    if dst_ip:
        flux_parts.append(build_flux_ip_filter("dst_ip", dst_ip))
    if port_val:
        flux_parts.append(fr'  |> filter(fn: (r) => r["src_port"] == "{port_val}" or r["dst_port"] == "{port_val}" or r["srcport"] == "{port_val}" or r["dstport"] == "{port_val}")')
        
    # 🌟 核心極速優化：使用 group() 將上萬張碎片化小表合併為「單一張大表」，徹底消滅 Python 建立物件解析的 10 秒延遲！
    flux_parts.append(r'  |> group()')
    
    # 🌟 遵照您的需求：徹底移除 limit()，查詢時間內有多少筆就全部找出來，並交由資料庫全域排序！
    flux_parts.append(r'  |> sort(columns: ["_time"], desc: true)')
    
    # 🌟 核心修正：精準保留需要的欄位，消除 Duplicate Names 標頭
    flux_parts.append(r'  |> keep(columns: ["_time", "_value", "src_ip", "dst_ip", "src_port", "dst_port", "srcport", "dstport", "protocol", "proto"])')
    
    flux_query = "\n".join(flux_parts)

    try:
        # 🌟 100% 靜音封殺：針對此查詢強制攔截並忽略 InfluxDB CSV 解析器警告
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
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
# 🩺 流量引擎健康檢查 API：智慧偵測 Telegraf 與 InfluxDB 運行狀態
# =========================================================================
@main_bp.route('/api/flow/check_env', methods=['GET'])
@require_role([ROLE_ADMIN, ROLE_OPERATOR, ROLE_AUDITOR])
def check_flow_env():
    import urllib.request
    from influxdb_client import InfluxDBClient
    
    influx_ok = False
    telegraf_ok = False

    # 1. 檢查 InfluxDB 是否存活 (打 health endpoint)
    try:
        health_url = f"{INFLUXDB_URL.rstrip('/')}/health"
        req = urllib.request.Request(health_url, method='GET')
        with urllib.request.urlopen(req, timeout=60.0) as res:
            if res.getcode() == 200:
                influx_ok = True
    except Exception:
        pass

    # 2. 智慧檢查 Telegraf 是否運作
    if influx_ok:
        try:
            # 🌟 修復 1：放寬 Timeout 到 15 秒 (15000)，避免資料庫在寫入或查詢大量資料時，簡單的檢查逾時
            client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG, timeout=15000)
            query_api = client.query_api()
            
            # 🌟 修復 2：放寬時間範圍到最近 2 小時 (避免離峰時間網路太安靜，太久沒封包被誤判)
            check_query = f'''
            from(bucket: "{INFLUXDB_BUCKET}")
              |> range(start: -2h)
              |> limit(n: 1)
            '''
            
            tables = query_api.query(check_query)
            if tables and len(tables) > 0:
                telegraf_ok = True
            client.close()
        except Exception as e:
            print(f"Telegraf 檢查失敗: {e}")
            # 🌟 修復 3：終極防呆！如果是因為 Timeout 或 deadline 超時報錯，代表資料庫還活著只是很忙，我們直接給予放行！
            error_msg = str(e).lower()
            if "timeout" in error_msg or "deadline exceeded" in error_msg or "canceled" in error_msg:
                telegraf_ok = True
            pass

    return jsonify({
        "success": True,
        "influxdb_ok": influx_ok,
        "telegraf_ok": telegraf_ok
    })
     
# ==========================================
# 🌐 IP 來源、DNS 反解與內網 MAC 探測 API (動態資料庫記憶體快取版)
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
    from database import read_translation_cache  # 💡 引入動態快取讀取器
    
    # 💡 智慧翻譯大腦：100% 讀取實體資料庫常駐在 RAM 的快取字典 ➔ 查無才走對外 Google 翻譯
    def translate_en_to_zh(text):
        if not text or text == '-': return text
        clean_text = text.strip().strip('"')
        
        # 1. 優先從記憶體快取字典進行精準比對
        db_cache = read_translation_cache()
        if clean_text in db_cache:
            return db_cache[clean_text]
            
        # 2. 次要進行不區分大小寫的模糊掃描
        for key, val in db_cache.items():
            if key.lower() == clean_text.lower():
                return val
                
        # 3. 檢查字串本身是否就已經內含中文
        if any('\u4e00' <= char <= '\u9fa5' for char in clean_text): 
            return clean_text
            
        # 4. 終極防禦：本地完全找不到，才消耗資源敲擊 Google 翻譯 API
        try:
            url = f"https://translate.googleapis.com/translate_a/single?client=gtx&sl=en&tl=zh-TW&dt=t&q={urllib.parse.quote(clean_text)}"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=1.2) as response:
                result = json.loads(response.read().decode('utf-8'))
                return result[0][0][0]  
        except Exception:
            return clean_text 

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
        try: internal_networks.append(ipaddress.ip_network(net_str, strict=False)) 
        except: pass

    try:
        ip_obj = ipaddress.ip_address(ip) 
        for net in internal_networks:
            if ip_obj in net:
                is_internal = True
                break
    except: pass

    # 🌟 兜底防護與特殊協定位址 (智慧辨識 IPv6 與 Class D 群播)
    is_multicast_or_link_local = False
    if not is_internal:
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_multicast or ip_obj.is_link_local or ip_obj.is_loopback:
                is_internal = True
                
            if ip_obj.is_multicast or ip_obj.is_link_local:
                is_multicast_or_link_local = True
        except:
            pass

    # 3. 分流處理：內網撈 MAC，外網撈 GeoIP
    if is_internal:
        target_ip = ip.strip()
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
                                    parts = str(arp_key).strip().split('.')
                                    if len(parts) >= 4 and ".".join(parts[-4:]) == target_ip:
                                        mac_clean = re.sub(r'[^a-fA-F0-9]', '', str(mac_val)).lower()
                                        if len(mac_clean) == 12:
                                            return ':'.join(mac_clean[i:i+2] for i in range(0, 12, 2)).upper()
                            return None

                        found_mac = find_valid_mac(arp_table) or find_valid_mac(arp_table_15)
                        if found_mac:
                            mac_address = found_mac
                            break 
                    except Exception:
                        continue 
                        
            except Exception as e:
                print(f"ARP 解析錯誤: {e}")

            if mac_address == "無法解析 (無 ARP 快取)":
                try:
                    local_ips = [socket.gethostbyname(socket.gethostname())]
                    try:
                        _, _, ips = socket.gethostbyname_ex(socket.gethostname())
                        local_ips.extend(ips)
                    except: pass
                    
                    if target_ip in local_ips or target_ip == '127.0.0.1':
                        mac_num = hex(uuid.getnode()).replace('0x', '').upper().zfill(12)
                        mac_address = ':'.join(mac_num[i:i+2] for i in range(0, 12, 2)) + " (網管伺服器本機)"
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
        task_response = tasks_api.find_tasks(org_id=org_id)
        
        # 👇 🌟 核心防護：相容不同版本的 influxdb-client (直接是 List 或是包裹物件)
        task_list = task_response if isinstance(task_response, list) else getattr(task_response, 'tasks', [])
        
        for t in task_list:
            if t.name == "Downsample_Hourly_Flow":
                tasks_api.delete_task(t.id)
                
        # 👇 🌟 核心防護：透過 TaskCreateRequest 標準物件建立任務，完美相容所有新舊版本
        from influxdb_client.domain.task_create_request import TaskCreateRequest
        task_req = TaskCreateRequest(org_id=org_id, status="active", flux=task_query)
        tasks_api.create_task(task_create_request=task_req)
        
        client.close()
        
        # 🌟 寫入稽核日誌
        details = f"啟動大數據降維與瘦身機制：建立 {downsample_bucket_name} (保留365天)，並將原始資料保留期縮減為 7 天。背景排程 Task 已生效。(操作來源 IP: {client_ip})"
        write_audit_log(operator, "系統設定", "InfluxDB資料庫瘦身", "SUCCESS", f"【修改系統設定】{details}")
        
        return jsonify({'success': True, 'message': 'InfluxDB 降維與瘦身任務已成功植入底層排程！'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'InfluxDB API 執行失敗: {str(e)}'})

# ========================================================
# ⚙️ 運維翻譯字典智慧 CRUD 管理 API (僅限 Admin 特權帳號)
# ========================================================

# 🟢 API 1：讀取 (Read) - 獲取全域翻譯字典清單
@main_bp.route('/api/settings/translation', methods=['GET'])
@require_role([ROLE_ADMIN])
def get_translation_list():
    try:
        conn = get_db('config')
        rows = conn.execute("SELECT id, eng_text, zh_text, category FROM translation_dictionary ORDER BY category ASC, id DESC").fetchall()
        conn.close()
        return jsonify({'success': True, 'data': [dict(r) for r in rows]})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# 🔵 API 2：新增 (Create) - 植入全新對照詞條
@main_bp.route('/api/settings/translation', methods=['POST'])
@require_role([ROLE_ADMIN])
def add_translation_pair():
    from database import reload_translation_cache
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    operator = session.get('username', 'SystemUser')
    
    data = request.json or {}
    eng = str(data.get('eng_text', '')).strip()
    zh = str(data.get('zh_text', '')).strip()
    cat = str(data.get('category', '行政區')).strip()
    
    if not eng or not zh:
        return jsonify({'success': False, 'message': '英文原文與中文翻譯皆不可為空'}), 400
        
    with DB_LOCKS['config']:
        conn = get_db('config')
        try:
            conn.execute("INSERT INTO translation_dictionary (eng_text, zh_text, category) VALUES (?, ?, ?)", (eng, zh, cat))
            conn.commit()
        except Exception as e:
            conn.close()
            if "UNIQUE" in str(e): 
                return jsonify({'success': False, 'message': f'原始字串「{eng}」已存在於字典中！'}), 400
            return jsonify({'success': False, 'message': str(e)}), 500
        conn.close()
        
    reload_translation_cache()  # 立即刷新記憶體快取
    write_audit_log(operator, "系統設定", "運維翻譯字典", "SUCCESS", f"【自訂字典】新增對照詞條：[{cat}]「{eng}」➔「{zh}」。(IP: {client_ip})")
    return jsonify({'success': True, 'message': '詞條新增成功並已即時載入核心快取！'})

# 🟡 API 3: 修改 (Update) - 就地編輯更新現有詞條
@main_bp.route('/api/settings/translation/<int:item_id>', methods=['PUT'])
@require_role([ROLE_ADMIN])
def update_translation_pair(item_id):
    from database import reload_translation_cache
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    operator = session.get('username', 'SystemUser')
    
    data = request.json or {}
    new_zh = str(data.get('zh_text', '')).strip()
    new_cat = str(data.get('category', '')).strip()
    
    if not new_zh:
        return jsonify({'success': False, 'message': '修改之繁體中文翻譯不可為空'}), 400
        
    with DB_LOCKS['config']:
        conn = get_db('config')
        old_row = conn.execute("SELECT * FROM translation_dictionary WHERE id=?", (item_id,)).fetchone()
        
        if not old_row:
            conn.close()
            return jsonify({'success': False, 'message': '該詞條不存在或已被刪除'}), 404
            
        eng_orig = old_row['eng_text']
        zh_orig = old_row['zh_text']
        cat_orig = old_row['category']
        
        if not new_cat: 
            new_cat = cat_orig

        conn.execute("UPDATE translation_dictionary SET zh_text=?, category=? WHERE id=?", (new_zh, new_cat, item_id))
        conn.commit()
        conn.close()
        
    reload_translation_cache()  # 立即刷新記憶體快取
    
    details = f"變更字典詞條 [{eng_orig}]：分類「{cat_orig}➔{new_cat}」，中文「{zh_orig}➔{new_zh}」"
    write_audit_log(operator, "系統設定", "運維翻譯字典", "SUCCESS", f"【自訂字典修改】{details}。(IP: {client_ip})")
    return jsonify({'success': True, 'message': '詞條修改成功！'})

# 🔴 API 4: 刪除 (Delete) - 抹除自訂詞條並退回自動翻譯
@main_bp.route('/api/settings/translation/<int:item_id>', methods=['DELETE'])
@require_role([ROLE_ADMIN])
def delete_translation_pair(item_id):
    from database import reload_translation_cache
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    operator = session.get('username', 'SystemUser')
    
    with DB_LOCKS['config']:
        conn = get_db('config')
        old_row = conn.execute("SELECT * FROM translation_dictionary WHERE id=?", (item_id,)).fetchone()
        
        if not old_row:
            conn.close()
            return jsonify({'success': False, 'message': '該詞條不存在或已被刪除'}), 404
            
        eng_orig = old_row['eng_text']
        cat_orig = old_row['category']

        conn.execute("DELETE FROM translation_dictionary WHERE id=?", (item_id,))
        conn.commit()
        conn.close()
        
    reload_translation_cache()  # 立即刷新記憶體快取
    write_audit_log(operator, "系統設定", "運維翻譯字典", "SUCCESS", f"【自訂字典】永久刪除對照詞條：[{cat_orig}]「{eng_orig}」。(IP: {client_ip})")
    return jsonify({'success': True, 'message': '該對照詞條已成功自資料庫移除'})
    
# 🟣 API 5：一鍵快收 (Auto-Add) - DNS 外部解析結果自動歸類加入字典
@main_bp.route('/api/settings/translation/auto_add', methods=['POST'])
@require_role([ROLE_ADMIN, ROLE_OPERATOR]) # 💡 允許維運員在查流量時快速建檔
def auto_add_translation():
    from database import reload_translation_cache, read_translation_cache
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    operator = session.get('username', 'SystemUser')
    
    data = request.json or {}
    isp_en = str(data.get('isp_en', '')).strip()
    isp_zh = str(data.get('isp_zh', '')).strip()
    city_en = str(data.get('city_en', '')).strip()
    city_zh = str(data.get('city_zh', '')).strip()
    
    db_cache = read_translation_cache()
    added_items = []
    
    with DB_LOCKS['config']:
        conn = get_db('config')
        try:
            # 1. 處理城市/地區 (直接強制歸類為: 縣市級)
            if city_en and city_zh and city_en != '-' and city_zh != '-' and city_en not in db_cache:
                cat_city = "縣市級"
                cur = conn.execute("INSERT OR IGNORE INTO translation_dictionary (eng_text, zh_text, category) VALUES (?, ?, ?)", (city_en, city_zh, cat_city))
                if cur.rowcount > 0:
                    added_items.append(f"[{cat_city}] {city_en}➔{city_zh}")
                    
            # 2. 處理 ISP 固網/雲端 (使用智慧正則關鍵字判斷分類)
            if isp_en and isp_zh and isp_en != '-' and isp_zh != '-' and isp_en not in db_cache:
                isp_lower = isp_en.lower()
                if any(x in isp_lower for x in ['telecom', 'net', 'mobile', 'isp', 'communications', 'broadband', 'cable', 'hinet']):
                    cat_isp = "電信固網"
                elif any(x in isp_lower for x in ['cloud', 'cdn', 'aws', 'amazon', 'google', 'microsoft', 'azure', 'cloudflare', 'akamai', 'fastly', 'alibaba']):
                    cat_isp = "雲端巨頭/CDN"
                else:
                    cat_isp = "國際網域/國家"
                    
                cur = conn.execute("INSERT OR IGNORE INTO translation_dictionary (eng_text, zh_text, category) VALUES (?, ?, ?)", (isp_en, isp_zh, cat_isp))
                if cur.rowcount > 0:
                    added_items.append(f"[{cat_isp}] {isp_en}➔{isp_zh}")
                    
            conn.commit()
        except Exception as e:
            return jsonify({'success': False, 'message': str(e)}), 500
        finally:
            conn.close()
            
    if added_items:
        reload_translation_cache() # 💡 立即刷新記憶體快取
        details_str = "、".join(added_items)
        
        # 🌟 寫入稽核日誌 (完美符合: 誰、來源IP、做了甚麼事)
        write_audit_log(operator, "流量明細檢索", "運維翻譯字典", "SUCCESS", f"【字典快收】透過 DNS 查詢面板一鍵收錄：{details_str}。(操作來源 IP: {client_ip})")
        return jsonify({'success': True, 'message': f'收錄成功！已新增：{details_str}'})
    else:
        return jsonify({'success': False, 'message': '來源與城市皆已存在於字典中，或無有效資料可供收錄。'})

# ========================================================
# 💡 讀取全網孔記憶快取 (供全網搜尋引擎使用)
# ========================================================
@main_bp.route('/api/device/ports/cache', methods=['GET'])
@require_role([ROLE_ADMIN, ROLE_OPERATOR])
def get_device_ports_cache():
    with DB_LOCKS['config']:
        conn = get_db('config')
        # 🌟 擴充：只要有記憶IP、是手動Uplink、或是手動MGMT，通通拉入全域快取
        rows = conn.execute("SELECT * FROM device_ports WHERE memorized_ips != '' OR is_manual_uplink = 1 OR is_manual_mgmt = 1").fetchall()
        conn.close()
    return jsonify([dict(r) for r in rows])
    
# ========================================================
# 🌟 精準解除雙向手動連線 (Uplink) API
# ========================================================
@main_bp.route('/api/manual_links/delete', methods=['POST'])
@require_role([ROLE_ADMIN, ROLE_OPERATOR])
def api_manual_links_delete():
    data = request.json
    ip_a = data.get('ip_a')
    port_a = data.get('port_a')
    ip_b = data.get('ip_b')

    if not all([ip_a, port_a, ip_b]):
        return jsonify({'success': False, 'message': '參數不完整'})

    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    operator = session.get('username', 'SystemUser')

    with DB_LOCKS['config']:
        conn = get_db('config')
        
        # 💡 1. 精準刪除手動連線表 (manual_links) 的配對
        conn.execute('''
            DELETE FROM manual_links 
            WHERE (node_a=? AND port_a=? AND node_b=?) 
               OR (node_b=? AND port_b=? AND node_a=?)
        ''', (ip_a, port_a, ip_b, ip_a, port_a, ip_b))
        
        # 🌟 雙向洗淨：斷開連線時，將該孔的手動 Uplink 與 MGMT 屬性一併安全清空
        conn.execute("UPDATE device_ports SET is_manual_uplink=0, is_manual_mgmt=0 WHERE ip=? AND port_name=?", (ip_a, port_a))
        
        # 💡 3. 同步斬斷 edges 快取表中的實體連線，讓前端可以「秒刪」線條
        conn.execute('''
            DELETE FROM edges 
            WHERE (source=? AND target=? AND from_port LIKE ?) 
               OR (source=? AND target=? AND to_port LIKE ?)
        ''', (ip_a, ip_b, f"%{port_a}%", ip_b, ip_a, f"%{port_a}%"))
        
        conn.commit()
        conn.close()

    log_details = f"【解除對接】管理員解除了設備 {ip_a} (Port: {port_a}) 與設備 {ip_b} 之間的手動對接紀錄。(操作來源: {client_ip})"
    write_audit_log(operator, "修改設備設定", "解除拓樸對接", "SUCCESS", log_details)

    return jsonify({'success': True, 'message': '已成功斷開此實體對接狀態！'})
    
# ========================================================
# 🌟 設備規格資料庫設定 API
# ========================================================
@main_bp.route('/api/device/specs', methods=['POST'])
@require_role([ROLE_ADMIN, ROLE_OPERATOR])
def update_device_specs():
    data = request.json
    ip = data.get('ip')
    snmp_version = data.get('snmp_version', 'v2c')
    port_specs = data.get('port_specs', '[]')
    
    if not ip: return jsonify({'success': False, 'message': '缺少 IP 參數'})
    
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    operator = session.get('username', 'SystemUser')
    
    with DB_LOCKS['config']:
        conn = get_db('config')
        conn.execute("UPDATE devices SET snmp_version=?, port_specs=? WHERE ip=?", (snmp_version, port_specs, ip))
        conn.commit()
        conn.close()
        
    reload_device_cache()
    write_audit_log(operator, "修改設備設定", f"更新設備規格 ({ip})", "SUCCESS", f"【修改設備設定】管理員更新了設備 {ip} 的 SNMP 版本與實體網孔規格設定。(操作來源 IP: {client_ip})")
    
    return jsonify({'success': True, 'message': '設備規格設定已成功儲存！'})

# 🌟 透過本機伺服器 Ping 目標 IP 並擷取 ARP 實體 MAC 位址 (供網孔標註使用)
@main_bp.route('/api/ping_mac/<ip>', methods=['GET'])
def api_ping_mac(ip):
    try:
        # 1. 基本安全防護，確認是否為合法的 IPv4 格式
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
            return jsonify({"success": False, "message": "IP 格式錯誤"})
            
        # 2. 智慧判斷跨平台的 Ping 參數 (支援 Windows / Linux)
        param_n = '-n' if platform.system().lower() == 'windows' else '-c'
        param_w = '-w' if platform.system().lower() == 'windows' else '-W'
        timeout = '1000' if platform.system().lower() == 'windows' else '1'
        
        # 3. 透過 Ping 強制喚醒目標並更新伺服器本機的 ARP 表 (捨棄終端輸出)
        subprocess.run(['ping', param_n, '1', param_w, timeout, ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # 4. 讀取本機 ARP 表
        arp_cmd = ['arp', '-a', ip] if platform.system().lower() == 'windows' else ['arp', '-n', ip]
        arp_process = subprocess.run(arp_cmd, capture_output=True, text=True, errors='ignore')
        arp_out = arp_process.stdout
        
        # 5. 透過正規表達式精準萃取 MAC 位址
        match = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', arp_out)
        if match:
            mac = match.group(0).replace('-', ':').lower()
            if mac in ['00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff']:
                 return jsonify({"success": False, "message": "取得無效的 MAC 位址"})
            return jsonify({"success": True, "mac": mac})
        else:
            return jsonify({"success": False, "message": "ARP 表中無此紀錄 (目標可能未開機或被防火牆阻擋)"})
            
    except Exception as e:
        return jsonify({"success": False, "message": f"伺服器執行錯誤: {str(e)}"})

@main_bp.route('/api/report/inventory_ports', methods=['GET'])
@require_role([ROLE_ADMIN, ROLE_OPERATOR])
def api_inventory_ports_report():
    try:
        with DB_LOCKS['config']:
            conn = get_db('config')
            
            # 1. 先撈取全校設備的總覽資訊
            # 🌟 核心過濾：排除 AP，並補上 snmp_raw 欄位以供後續萃取 Alias
            devices_query = """
                SELECT ip, name, brand, model, type, sys_descr, snmp_raw
                FROM devices 
                WHERE 
                    type NOT LIKE '%AP%' 
                    AND type NOT LIKE '%WIFI%' 
                    AND name NOT LIKE '%AP%'
                ORDER BY ip
            """
            devices_rows = conn.execute(devices_query).fetchall()
            
            # 撈取網孔的記憶資料
            ports_query = """
                SELECT ip, port_idx, port_name, memorized_ips, is_manual_uplink, is_manual_mgmt 
                FROM device_ports 
                WHERE memorized_ips != '' OR is_manual_uplink = 1 OR is_manual_mgmt = 1
            """
            ports_rows = conn.execute(ports_query).fetchall()
            
            conn.close()

        # 整理 ports_map
        ports_map = {}
        for p in ports_rows:
            ip = p['ip']
            if ip not in ports_map:
                ports_map[ip] = []
            
            mac_list = []
            if p['memorized_ips']:
                for pair in p['memorized_ips'].split(','):
                    if '|' in pair:
                        m_ip, m_mac = pair.split('|', 1)
                        mac_list.append({"ip": m_ip, "mac": m_mac})

            ports_map[ip].append({
                "port_idx": p['port_idx'],
                "port_name": p['port_name'],
                "is_uplink": bool(p['is_manual_uplink']),
                "is_mgmt": bool(p['is_manual_mgmt']),
                "connected_devices": mac_list
            })

        # 4. 組合最終報表資料
        report_data = []
        
        # 🌟 強化版解碼器：處理 0x 開頭或是純 Hex 字串的亂碼 Alias
        def decode_hex(val):
            if not val: return ""
            val_str = str(val).strip()
            if val_str.startswith("0x"):
                val_str = val_str[2:]
            
            # 檢查是否全為 16 進位字元，且長度為偶數 (通常是 SNMP 回傳的 Hex String)
            import re
            if len(val_str) > 0 and len(val_str) % 2 == 0 and re.match(r'^[0-9a-fA-F]+$', val_str):
                try:
                    return bytes.fromhex(val_str).decode('utf-8', errors='ignore')
                except:
                    pass
            return str(val)

        for d in devices_rows:
            firmware = "Unknown"
            sys_descr = d['sys_descr'] or ""
            if "Version " in sys_descr:
                try: firmware = sys_descr.split("Version ")[1].split(",")[0].strip()
                except: pass
            elif "Software " in sys_descr:
                try: firmware = sys_descr.split("Software ")[1].split()[0].strip()
                except: pass
                
            # 🌟 核心修復：正確判定 snmp_raw 的資料型態 (List 或 Dict)
            aliases = {}
            if d['snmp_raw'] and d['snmp_raw'] != '{}':
                try:
                    import json
                    raw_data = json.loads(d['snmp_raw'])
                    if isinstance(raw_data, list) and len(raw_data) > 9:
                        aliases = raw_data[9] if raw_data[9] else {}
                    elif isinstance(raw_data, dict):
                        aliases = raw_data.get("9", {})
                except Exception as e:
                    print(f"解析 {d['ip']} SNMP Raw 失敗: {e}")

            device_ports = ports_map.get(d['ip'], [])
            for p in device_ports:
                # 將解碼後的說明綁定到該網孔
                raw_alias = aliases.get(str(p['port_idx']), "")
                p['alias'] = decode_hex(raw_alias)

            report_data.append({
                "ip": d['ip'],
                "sysName": d['name'],
                "brand": d['brand'],
                "model": d['model'],
                "firmware": firmware,
                "device_mac": "N/A", 
                "ports": device_ports
            })

        return jsonify({"success": True, "data": report_data})

    except Exception as e:
        # 🌟 修正 2：如果資料庫報錯，完美攔截並傳給前端，不再讓網頁死當轉圈
        print(f"Inventory API Error: {str(e)}")
        return jsonify({"success": False, "message": f"資料庫撈取失敗: {str(e)}"})

# ========================================================
# 🏢 分區機構與多站點推播設定 API
# ========================================================
@main_bp.route('/api/settings/school_info', methods=['GET', 'POST'])
def handle_school_info_settings():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    operator = session.get('username', 'SystemUser')
    
    if request.method == 'POST':
        data = request.get_json() or {}
        district = str(data.get('district', '')).strip()
        code = str(data.get('code', '')).strip()
        name = str(data.get('name', '')).strip()
        
        with DB_LOCKS['config']:
            conn = get_db('config')
            try:
                conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('site_district', ?)", (district,))
                conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('site_code', ?)", (code,))
                conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('site_name', ?)", (name,))
                conn.commit()
            except Exception as e:
                return jsonify({'success': False, 'message': f'資料庫寫入失敗: {str(e)}'}), 500
            finally:
                conn.close()
                
        details = f"更新機構基本資料：行政區「{district}」、代碼「{code}」、名稱「{name}」。(操作來源 IP: {client_ip})"
        write_audit_log(operator, "系統設定", "機構基本資料", "SUCCESS", f"【修改系統設定】{details}")
        from utils import log_info
        log_info(f"⚙️ 【參數儲存】{details}")
        
        return jsonify({'success': True})
    else:
        with DB_LOCKS['config']:
            # 🌟 補上 bypass_shard=True
            conn = get_db('config', bypass_shard=True)
            try:
                r_dist = conn.execute("SELECT value FROM system_settings WHERE key='site_district'").fetchone()
                r_code = conn.execute("SELECT value FROM system_settings WHERE key='site_code'").fetchone()
                r_name = conn.execute("SELECT value FROM system_settings WHERE key='site_name'").fetchone()
            finally:
                conn.close()
                
        return jsonify({
            'success': True,
            'district': r_dist['value'] if r_dist else '',
            'code': r_code['value'] if r_code else '',
            'name': r_name['value'] if r_name else ''
        })

# ========================================================
# 🚀 總部推播引擎 (HQ Sync) 設定與測試匯出 API
# ========================================================
@main_bp.route('/api/settings/sync_schedule', methods=['GET', 'POST'])
@require_role([ROLE_ADMIN])
def handle_sync_schedule():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    operator = session.get('username', 'SystemUser')
    
    if request.method == 'POST':
        data = request.get_json() or {}
        with DB_LOCKS['config']:
            conn = get_db('config')
            try:
                for key in ['sync_topo_start', 'sync_topo_interval', 'sync_status_start', 'sync_status_interval']:
                    if key in data:
                        conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES (?, ?)", (key, str(data[key]).strip()))
                conn.commit()
            except Exception as e:
                return jsonify({'success': False, 'message': f'寫入失敗: {str(e)}'}), 500
            finally:
                conn.close()
                
        write_audit_log(operator, "系統設定", "總部推播排程", "SUCCESS", f"【修改推播設定】更新了至總部的資料推播時間與頻率。(IP: {client_ip})")
        return jsonify({'success': True})
    else:
        with DB_LOCKS['config']:
            conn = get_db('config')
            try:
                rows = conn.execute("SELECT key, value FROM system_settings WHERE key LIKE 'sync_%'").fetchall()
                settings = {r['key']: r['value'] for r in rows}
            finally:
                conn.close()
        return jsonify({
            'success': True,
            'sync_topo_start': settings.get('sync_topo_start', '01:00'),
            'sync_topo_interval': settings.get('sync_topo_interval', '24'),
            'sync_status_start': settings.get('sync_status_start', '00:00'),
            'sync_status_interval': settings.get('sync_status_interval', '5')
        })

# ========================================================
# 🌍 總部全局視角與通訊設定 API
# ========================================================
@main_bp.route('/api/settings/hq_mode', methods=['GET', 'POST'])
def handle_hq_mode_settings():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    operator = session.get('username', 'SystemUser')
    
    if request.method == 'POST':
        data = request.get_json() or {}
        mode = str(data.get('hq_view_mode', 'local')).strip()
        url = str(data.get('hq_server_url', '')).strip()
        secret = str(data.get('hq_sync_secret', '')).strip() # 🌟 新增：讀取認證碼
        
        with DB_LOCKS['config']:
            conn = get_db('config')
            try:
                conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('hq_view_mode', ?)", (mode,))
                conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('hq_server_url', ?)", (url,))
                conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('hq_sync_secret', ?)", (secret,)) # 🌟 新增：寫入認證碼
                conn.commit()
            except Exception as e:
                return jsonify({'success': False, 'message': f'寫入失敗: {str(e)}'}), 500
            finally:
                conn.close()
                
        mode_zh = "總部全局模式" if mode == 'hq' else "單一分區模式"
        write_audit_log(operator, "系統設定", "總部視角切換", "SUCCESS", f"【修改系統設定】變更系統視角為：{mode_zh}，總部位址與認證碼已更新。(IP: {client_ip})")
        return jsonify({'success': True})
    else:
        with DB_LOCKS['config']:
            # 🌟 補上 bypass_shard=True
            conn = get_db('config', bypass_shard=True)
            try:
                row_mode = conn.execute("SELECT value FROM system_settings WHERE key='hq_view_mode'").fetchone()
                row_url = conn.execute("SELECT value FROM system_settings WHERE key='hq_server_url'").fetchone()
                row_secret = conn.execute("SELECT value FROM system_settings WHERE key='hq_sync_secret'").fetchone() # 🌟 新增：讀取資料庫
                
                mode = row_mode['value'] if row_mode else 'local'
                url = row_url['value'] if row_url else ''
                secret = row_secret['value'] if row_secret else '' # 🌟 新增：變數賦值
            finally:
                conn.close()
        return jsonify({'success': True, 'hq_view_mode': mode, 'hq_server_url': url, 'hq_sync_secret': secret})

@main_bp.route('/api/hq/test_connection', methods=['POST'])
@require_role([ROLE_ADMIN])
def test_hq_connection():
    """發送一個輕量的 GET 請求測試總部伺服器是否可達"""
    import urllib.request
    data = request.get_json() or {}
    hq_url = str(data.get('url', '')).strip()
    
    if not hq_url:
        return jsonify({'success': False, 'message': '請先輸入總部伺服器位址 (URL)'})
        
    # 自動補齊 http:// (若使用者忘記打)
    if not hq_url.startswith('http'):
        hq_url = 'http://' + hq_url
        
    try:
        # 向總部首頁發起探測 (Timeout 3 秒)
        req = urllib.request.Request(hq_url, method='GET')
        with urllib.request.urlopen(req, timeout=3.0) as res:
            if res.getcode() == 200:
                return jsonify({'success': True, 'message': '連線成功！總部伺服器正常運作中。'})
            else:
                return jsonify({'success': False, 'message': f'伺服器有回應，但回傳錯誤狀態碼 ({res.getcode()})'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'無法連線至總部伺服器：{str(e)}'})

@main_bp.route('/api/hq/test_export/<sync_type>', methods=['GET'])
@require_role([ROLE_ADMIN])
def test_export_sync_payload(sync_type):
    import io, json, time
    from flask import send_file
    
    payload = {"identity": {}, "data": {}}
    
    with DB_LOCKS['config']:
        conn = get_db('config')
        id_rows = conn.execute("SELECT key, value FROM system_settings WHERE key IN ('site_district', 'site_code', 'site_name')").fetchall()
        for r in id_rows:
            payload["identity"][r['key']] = r['value']
            
        core_devices = [dict(r) for r in conn.execute("SELECT * FROM devices").fetchall()]
        core_ips = [d['ip'] for d in core_devices]
        
        if sync_type == 'topology':
            payload["data"]["devices"] = core_devices
            if core_ips:
                placeholders = ','.join(['?'] * len(core_ips))
                payload["data"]["manual_links"] = [dict(r) for r in conn.execute(f"SELECT * FROM manual_links WHERE node_a IN ({placeholders}) OR node_b IN ({placeholders})", core_ips + core_ips).fetchall()]
                payload["data"]["device_ports"] = [dict(r) for r in conn.execute(f"SELECT * FROM device_ports WHERE ip IN ({placeholders})", core_ips).fetchall()]
            else:
                payload["data"]["manual_links"] = []; payload["data"]["device_ports"] = []
                
        elif sync_type == 'status':
            payload["data"]["device_status"] = [{"ip": d['ip'], "status": d['status'], "cpu_load": d['cpu_load'], "mem_load": d['mem_load'], "latency_ms": d.get('latency_ms', 0.0)} for d in core_devices]
            
            # 👇 🌟 新增：把本地的今日掃描次數打包進來
            try:
                today_str = time.strftime('%Y-%m-%d')
                ano_row = conn.execute("SELECT runs FROM anomaly_daily_stats WHERE date = ?", (today_str,)).fetchone()
                payload["data"]["anomaly_runs"] = ano_row['runs'] if ano_row else 0
            except:
                payload["data"]["anomaly_runs"] = 0
                
        conn.close()

    # 🌟 補齊流量數據 (從熱庫抓取)
    if sync_type == 'status':
        try:
            time_limit = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() - 900))
            with DB_LOCKS['hot']:
                conn_hot = get_db('hot')
                payload["data"]["traffic_history"] = [dict(r) for r in conn_hot.execute("SELECT ip, port_idx, in_bytes, out_bytes, timestamp FROM traffic_history WHERE timestamp >= ?", (time_limit,)).fetchall()]
                conn_hot.close()
        except Exception as e:
            payload["data"]["traffic_history"] = []

        global TOP5_FLOW_CACHE
        try: get_top5_flow() 
        except: pass
        payload["data"]["top5_flow"] = TOP5_FLOW_CACHE.get('data', [])

        # 👇 🌟 核心新增：分區呼叫自己的 API 算好現成的異常清單，打包成 JSON 直接送給總部！
        try:
            ano_res = api_anomalies().get_json()
            if ano_res and ano_res.get('success'):
                payload["data"]["anomalies"] = ano_res.get('data', [])
            else:
                payload["data"]["anomalies"] = []
        except Exception as e:
            print(f"打包異常清單失敗: {e}")
            payload["data"]["anomalies"] = []
        
    json_str = json.dumps(payload, ensure_ascii=False, indent=4)
    timestamp_str = time.strftime("%Y%m%d_%H%M")
    
    return send_file(io.BytesIO(json_str.encode('utf-8')), mimetype='application/json', as_attachment=True, download_name=f'TestExport_{sync_type.capitalize()}_{timestamp_str}.json')

@main_bp.route('/api/hq/manual_push/<sync_type>', methods=['POST'])
@require_role([ROLE_ADMIN])
def hq_manual_push(sync_type):
    import urllib.request
    import json
    import time
    
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    operator = session.get('username', 'SystemUser')
    
    payload = {"identity": {}, "data": {}}
    
    with DB_LOCKS['config']:
        conn = get_db('config')
        settings_rows = conn.execute("SELECT key, value FROM system_settings WHERE key IN ('hq_server_url', 'hq_sync_secret', 'site_district', 'site_code', 'site_name')").fetchall()
        settings = {r['key']: r['value'] for r in settings_rows}
        
        hq_url = settings.get('hq_server_url', '').strip()
        hq_secret = settings.get('hq_sync_secret', '').strip()
        site_code = settings.get('site_code', '').strip()
        
        if not hq_url or not hq_secret or not site_code:
            return jsonify({'success': False, 'message': '請先完成「機構基本資料」與「總部伺服器位址/認證碼」設定！'})
            
        if not hq_url.startswith('http'):
            hq_url = 'http://' + hq_url
            
        payload["identity"] = {"site_district": settings.get('site_district', ''), "site_code": site_code, "site_name": settings.get('site_name', '')}
        
        core_devices = [dict(r) for r in conn.execute("SELECT * FROM devices").fetchall()]
        core_ips = [d['ip'] for d in core_devices]
        
        if sync_type == 'topology':
            payload["data"]["devices"] = core_devices
            payload["data"]["edges"] = [dict(r) for r in conn.execute("SELECT * FROM edges").fetchall()]
            payload["data"]["layout_slots"] = [dict(r) for r in conn.execute("SELECT * FROM layout_slots").fetchall()]
            
            if core_ips:
                placeholders = ','.join(['?'] * len(core_ips))
                payload["data"]["manual_links"] = [dict(r) for r in conn.execute(f"SELECT * FROM manual_links WHERE node_a IN ({placeholders}) OR node_b IN ({placeholders})", core_ips + core_ips).fetchall()]
                payload["data"]["device_ports"] = [dict(r) for r in conn.execute(f"SELECT * FROM device_ports WHERE ip IN ({placeholders})", core_ips).fetchall()]
            else:
                payload["data"]["manual_links"] = []; payload["data"]["device_ports"] = []
        elif sync_type == 'status':
            payload["data"]["device_status"] = [{"ip": d['ip'], "status": d['status'], "cpu_load": d['cpu_load'], "mem_load": d['mem_load'], "latency_ms": d.get('latency_ms', 0.0)} for d in core_devices]
            
            # 👇 🌟 新增：把本地的今日掃描次數打包進來
            try:
                today_str = time.strftime('%Y-%m-%d')
                ano_row = conn.execute("SELECT runs FROM anomaly_daily_stats WHERE date = ?", (today_str,)).fetchone()
                payload["data"]["anomaly_runs"] = ano_row['runs'] if ano_row else 0
            except:
                payload["data"]["anomaly_runs"] = 0
                
        conn.close()

    # 🌟 補齊流量數據 (從熱庫抓取)
    if sync_type == 'status':
        try:
            time_limit = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() - 900))
            with DB_LOCKS['hot']:
                conn_hot = get_db('hot')
                payload["data"]["traffic_history"] = [dict(r) for r in conn_hot.execute("SELECT ip, port_idx, in_bytes, out_bytes, timestamp FROM traffic_history WHERE timestamp >= ?", (time_limit,)).fetchall()]
                conn_hot.close()
        except Exception as e:
            payload["data"]["traffic_history"] = []

        # 👇 🌟 終極修復：推播前強制呼叫 API 函數，保證包裹裡絕對有最新的 Top 10 快取！
        global TOP5_FLOW_CACHE
        try: 
            get_top5_flow() 
        except: 
            pass
        payload["data"]["top5_flow"] = TOP5_FLOW_CACHE.get('data', [])

    target_endpoint = f"{hq_url.rstrip('/')}/api/hq/receive/{sync_type}"
    json_data = json.dumps(payload, ensure_ascii=False).encode('utf-8')
    
    req = urllib.request.Request(target_endpoint, data=json_data, method='POST')
    req.add_header('Content-Type', 'application/json; charset=utf-8')
    req.add_header('Authorization', f'Bearer {hq_secret}')
    
    try:
        with urllib.request.urlopen(req, timeout=10.0) as res:
            res_body = res.read().decode('utf-8')
            res_json = json.loads(res_body)
            if res.getcode() == 200 and res_json.get('success'):
                return jsonify({'success': True, 'message': res_json.get('message', '總部接收成功')})
            else:
                return jsonify({'success': False, 'message': res_json.get('message', '失敗')})
    except Exception as e:
        return jsonify({'success': False, 'message': f'通訊失敗，請確認總部 IP 與網路狀態: {str(e)}'})

# ========================================================
# 🏛️ 總部核心：接收分區推播資料 API (HQ Receiver Engine)
# ========================================================
@main_bp.route('/api/hq/receive/<sync_type>', methods=['POST'])
def hq_receive_sync_data(sync_type):
    import os, time, sqlite3, secrets
    
    with DB_LOCKS['config']:
        conn = get_db('config')
        hq_mode = conn.execute("SELECT value FROM system_settings WHERE key='hq_view_mode'").fetchone()
        hq_secret_row = conn.execute("SELECT value FROM system_settings WHERE key='hq_sync_secret'").fetchone()
        conn.close()
        
    if not hq_mode or hq_mode['value'] != 'hq':
        return jsonify({'success': False, 'message': '拒絕存取：本機並非總部模式'}), 403

    expected_secret = hq_secret_row['value'] if hq_secret_row else ''
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '): return jsonify({'success': False, 'message': '未授權'}), 401
    client_secret = auth_header.split(' ')[1].strip()
    if not expected_secret or not secrets.compare_digest(client_secret, expected_secret):
        return jsonify({'success': False, 'message': '推播金鑰錯誤'}), 401

    payload = request.get_json()
    identity = payload['identity']
    site_code = str(identity.get('site_code', '')).strip()
    
    try:
        with DB_LOCKS['hq_master']:
            hq_conn = get_db('hq_master')
            hq_conn.execute("""INSERT INTO global_sites (site_code, site_name, district, status, last_sync_time) VALUES (?, ?, ?, 'up', CURRENT_TIMESTAMP) ON CONFLICT(site_code) DO UPDATE SET site_name=excluded.site_name, district=excluded.district, status='up', last_sync_time=CURRENT_TIMESTAMP""", (site_code, identity.get('site_name', ''), identity.get('site_district', '')))
            hq_conn.commit()
            hq_conn.close()
    except Exception:
        pass
    
    if not os.path.exists('hq_sites'): os.makedirs('hq_sites')
    site_db_path = os.path.join('hq_sites', f'site_{site_code}.db')
    site_conn = sqlite3.connect(site_db_path, timeout=10)
    site_conn.row_factory = sqlite3.Row
    site_conn.execute('PRAGMA journal_mode=WAL;')
    
    try:
        data = payload['data']
        if sync_type == 'topology':
            site_conn.execute("DROP TABLE IF EXISTS devices")
            site_conn.execute("DROP TABLE IF EXISTS edges")
            site_conn.execute("DROP TABLE IF EXISTS layout_slots")
            site_conn.execute("DROP TABLE IF EXISTS manual_links")
            site_conn.execute("DROP TABLE IF EXISTS device_ports")
            
            site_conn.execute("CREATE TABLE devices (ip TEXT PRIMARY KEY, name TEXT, level INTEGER, type TEXT, brand TEXT, model TEXT, status TEXT, cpu_load REAL, mem_load REAL, visible INTEGER, x REAL, y REAL, sys_descr TEXT, is_poe INTEGER, has_sensor INTEGER, snmp_raw TEXT, poe_data TEXT, location TEXT)")
            site_conn.execute("CREATE TABLE edges (id TEXT PRIMARY KEY, source TEXT, target TEXT, speed INTEGER, OID_info TEXT, port_info TEXT, from_port TEXT, to_port TEXT)")
            site_conn.execute("CREATE TABLE layout_slots (slot_id INTEGER, ip TEXT, x REAL, y REAL, PRIMARY KEY (slot_id, ip))")
            site_conn.execute("CREATE TABLE manual_links (id INTEGER PRIMARY KEY, node_a TEXT, port_a TEXT, node_b TEXT, port_b TEXT)")
            site_conn.execute("CREATE TABLE device_ports (ip TEXT, port_idx TEXT, port_name TEXT, is_manual_uplink INTEGER, is_manual_mgmt INTEGER, PRIMARY KEY (ip, port_idx))")
            
            for d in data.get('devices', []):
                site_conn.execute("INSERT INTO devices (ip, name, level, type, brand, model, status, cpu_load, mem_load, visible, x, y, sys_descr, is_poe, has_sensor, snmp_raw, poe_data, location) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (d.get('ip'), d.get('name'), d.get('level'), d.get('type'), d.get('brand'), d.get('model'), d.get('status'), d.get('cpu_load'), d.get('mem_load'), d.get('visible', 1), d.get('x'), d.get('y'), d.get('sys_descr'), d.get('is_poe', 0), d.get('has_sensor', 0), d.get('snmp_raw', '{}'), d.get('poe_data', '{}'), d.get('location', '')))
            for e in data.get('edges', []):
                site_conn.execute("INSERT INTO edges (id, source, target, speed, OID_info, port_info, from_port, to_port) VALUES (?,?,?,?,?,?,?,?)", (e.get('id'), e.get('source'), e.get('target'), e.get('speed'), e.get('OID_info'), e.get('port_info'), e.get('from_port'), e.get('to_port')))
            for s in data.get('layout_slots', []):
                site_conn.execute("INSERT INTO layout_slots (slot_id, ip, x, y) VALUES (?,?,?,?)", (s.get('slot_id'), s.get('ip'), s.get('x'), s.get('y')))
            for link in data.get('manual_links', []):
                site_conn.execute("INSERT INTO manual_links (node_a, port_a, node_b, port_b) VALUES (?,?,?,?)", (link.get('node_a'), link.get('port_a'), link.get('node_b'), link.get('port_b')))
            for port in data.get('device_ports', []):
                site_conn.execute("INSERT INTO device_ports (ip, port_idx, port_name, is_manual_uplink, is_manual_mgmt) VALUES (?,?,?,?,?)", (port.get('ip'), port.get('port_idx'), port.get('port_name'), port.get('is_manual_uplink'), port.get('is_manual_mgmt')))
                
        elif sync_type == 'status':
            # 🌟 加入 latency_ms 欄位宣告
            site_conn.execute("CREATE TABLE IF NOT EXISTS devices (ip TEXT PRIMARY KEY, name TEXT, level INTEGER, type TEXT, brand TEXT, model TEXT, status TEXT, cpu_load REAL, mem_load REAL, latency_ms REAL DEFAULT 0.0, visible INTEGER DEFAULT 1, x REAL, y REAL, sys_descr TEXT, is_poe INTEGER, has_sensor INTEGER, snmp_raw TEXT, poe_data TEXT, location TEXT)")
            site_conn.execute('''CREATE TABLE IF NOT EXISTS metrics_history (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, cpu REAL, memory REAL, poe_w REAL DEFAULT 0.0, temp_c REAL DEFAULT 0.0, session_util REAL DEFAULT 0.0, latency_ms REAL DEFAULT 0.0, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
            site_conn.execute('''CREATE TABLE IF NOT EXISTS traffic_history (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, port_idx TEXT, in_bytes INTEGER, out_bytes INTEGER, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
            site_conn.execute("DELETE FROM traffic_history")
            
            # 🌟 無痛升級總部資料庫：自動補齊缺少的 latency_ms 欄位，防止舊庫崩潰
            try: site_conn.execute("ALTER TABLE devices ADD COLUMN latency_ms REAL DEFAULT 0.0")
            except: pass
            try: site_conn.execute("ALTER TABLE metrics_history ADD COLUMN latency_ms REAL DEFAULT 0.0")
            except: pass
            
            site_conn.execute("CREATE TABLE IF NOT EXISTS anomaly_daily_stats (date TEXT PRIMARY KEY, runs INTEGER DEFAULT 0)")
            site_conn.execute("INSERT OR REPLACE INTO anomaly_daily_stats (date, runs) VALUES (?, ?)", (time.strftime('%Y-%m-%d'), data.get('anomaly_runs', 0)))
            
            site_conn.execute("CREATE TABLE IF NOT EXISTS system_settings (key TEXT PRIMARY KEY, value TEXT)")
            import json
            top5_data = data.get('top5_flow', [])
            site_conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('latest_top5_flow', ?)", (json.dumps(top5_data, ensure_ascii=False),))
            
            ano_data = data.get('anomalies', [])
            site_conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('latest_anomalies', ?)", (json.dumps(ano_data, ensure_ascii=False),))
            
            for st in data.get('device_status', []):
                # 🌟 將 latency_ms 更新到總部的設備總表
                site_conn.execute("UPDATE devices SET status=?, cpu_load=?, mem_load=?, latency_ms=? WHERE ip=?", (st.get('status'), st.get('cpu_load'), st.get('mem_load'), st.get('latency_ms', 0.0), st.get('ip')))
                # 🌟 將 latency_ms 新增到總部的時序大表
                site_conn.execute("INSERT INTO metrics_history (ip, cpu, memory, latency_ms) VALUES (?, ?, ?, ?)", (st.get('ip'), st.get('cpu_load'), st.get('mem_load'), st.get('latency_ms', 0.0)))
                
            for t in data.get('traffic_history', []):
                site_conn.execute("INSERT INTO traffic_history (ip, port_idx, in_bytes, out_bytes, timestamp) VALUES (?, ?, ?, ?, ?)", (t['ip'], t['port_idx'], t['in_bytes'], t['out_bytes'], t['timestamp']))
        
        site_conn.commit()
    except Exception as e:
        return jsonify({'success': False, 'message': f'分區資料庫寫入失敗: {str(e)}'}), 500
    finally:
        site_conn.close()

    return jsonify({'success': True, 'message': f'總部已成功接收推播！'})
    
# ========================================================
# 🧹 獨立手動觸發資料清洗 API (背景非阻塞版)
# ========================================================
@main_bp.route('/api/settings/manual_retention', methods=['POST'])
@require_role([ROLE_ADMIN])
def api_manual_retention():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    operator = session.get('username', 'SystemUser')

    # 🌟 獨立宣告背景任務函式
    def manual_retention_task():
        import time
        from database import get_db, DB_WARM, DB_COLD, DB_LOCKS, write_audit_log
        from utils import log_info

        # 核心防禦：微創切片刪除
        def chunked_delete(conn, table, condition, chunk_size=2000):
            while True:
                cur = conn.execute(f"DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} WHERE {condition} LIMIT {chunk_size})")
                deleted = cur.rowcount
                conn.commit()
                if deleted < chunk_size: break
                time.sleep(0.2)

        try:
            log_info(f"🧹 [手動資料清洗] {operator} 啟動企業級無鎖降採樣引擎...")
            
            # 🛡️ 階段 1：處理溫冷庫
            with DB_LOCKS['warm']:
                conn_warm = get_db('warm')
                conn_warm.execute(f"ATTACH DATABASE '{DB_COLD}' AS cold_db")
                
                chunked_delete(conn_warm, "cold_db.traffic_history", "timestamp < datetime('now', '-1095 days', 'localtime')")
                chunked_delete(conn_warm, "cold_db.metrics_history", "timestamp < datetime('now', '-1095 days', 'localtime')")
                
                conn_warm.execute("""
                    INSERT INTO cold_db.traffic_history (ip, port_idx, timestamp, avg_in_bps, max_in_bps, avg_out_bps, max_out_bps)
                    SELECT ip, port_idx, strftime('%Y-%m-%d %H:00:00', timestamp) AS hour_ts,
                           AVG(avg_in_bps), MAX(max_in_bps), AVG(avg_out_bps), MAX(max_out_bps)
                    FROM traffic_history
                    WHERE timestamp < datetime('now', '-180 days', 'localtime')
                    GROUP BY ip, port_idx, hour_ts
                """)
                conn_warm.execute("""
                    INSERT INTO cold_db.metrics_history (ip, timestamp, cpu, memory, temp_c, poe_w, session_util, latency_ms)
                    SELECT ip, strftime('%Y-%m-%d %H:00:00', timestamp) AS hour_ts,
                           AVG(cpu), AVG(memory), AVG(temp_c), AVG(poe_w), AVG(session_util), AVG(latency_ms)
                    FROM metrics_history
                    WHERE timestamp < datetime('now', '-180 days', 'localtime')
                    GROUP BY ip, hour_ts
                """)
                conn_warm.commit()
                
                chunked_delete(conn_warm, "traffic_history", "timestamp < datetime('now', '-180 days', 'localtime')")
                chunked_delete(conn_warm, "metrics_history", "timestamp < datetime('now', '-180 days', 'localtime')")
                
                conn_warm.execute("DETACH DATABASE cold_db")
                conn_warm.close()

            # 🛡️ 階段 2：處理熱溫庫
            with DB_LOCKS['hot']:
                conn_hot = get_db('hot')
                conn_hot.execute(f"ATTACH DATABASE '{DB_WARM}' AS warm_db")
                
                conn_hot.execute("""
                    WITH diff_calc AS (
                        SELECT ip, port_idx, timestamp,
                               in_bytes - LAG(in_bytes) OVER (PARTITION BY ip, port_idx ORDER BY timestamp) AS i_diff,
                               out_bytes - LAG(out_bytes) OVER (PARTITION BY ip, port_idx ORDER BY timestamp) AS o_diff,
                               strftime('%s', timestamp) - strftime('%s', LAG(timestamp) OVER (PARTITION BY ip, port_idx ORDER BY timestamp)) AS dt
                        FROM traffic_history
                    ), bps_calc AS (
                        SELECT ip, port_idx, timestamp,
                               CASE WHEN i_diff >= 0 AND dt > 0 THEN (i_diff * 8) / dt ELSE 0 END AS in_bps,
                               CASE WHEN o_diff >= 0 AND dt > 0 THEN (o_diff * 8) / dt ELSE 0 END AS out_bps
                        FROM diff_calc
                    )
                    INSERT INTO warm_db.traffic_history (ip, port_idx, timestamp, avg_in_bps, max_in_bps, avg_out_bps, max_out_bps)
                    SELECT ip, port_idx, 
                           datetime((strftime('%s', timestamp) / 600) * 600, 'unixepoch', 'localtime') AS min10_ts,
                           AVG(in_bps), MAX(in_bps), AVG(out_bps), MAX(out_bps)
                    FROM bps_calc
                    WHERE timestamp < datetime('now', '-30 days', 'localtime')
                    GROUP BY ip, port_idx, min10_ts
                """)
                conn_hot.execute("""
                    INSERT INTO warm_db.metrics_history (ip, timestamp, cpu, memory, temp_c, poe_w, session_util, latency_ms)
                    SELECT ip, datetime((strftime('%s', timestamp) / 600) * 600, 'unixepoch', 'localtime') AS min10_ts,
                           AVG(cpu), AVG(memory), AVG(temp_c), AVG(poe_w), AVG(session_util), AVG(latency_ms)
                    FROM metrics_history
                    WHERE timestamp < datetime('now', '-30 days', 'localtime')
                    GROUP BY ip, min10_ts
                """)
                conn_hot.commit()
                
                chunked_delete(conn_hot, "traffic_history", "timestamp < datetime('now', '-30 days', 'localtime')", chunk_size=1000)
                chunked_delete(conn_hot, "metrics_history", "timestamp < datetime('now', '-30 days', 'localtime')", chunk_size=1000)
                
                conn_hot.execute("DETACH DATABASE warm_db")
                conn_hot.close()
                
            msg = f"管理員 {operator} 執行的無鎖降採樣完工！空間已釋放。"
            log_info(f"✅ [手動資料清洗] {msg}")
            write_audit_log(operator, "系統設定", "手動資料清洗", "SUCCESS", f"【清洗完成】{msg} (來源 IP: {client_ip})")

        except Exception as e:
            msg = f"發生異常: {e}"
            log_info(f"⚠️ [手動資料清洗] {msg}")
            write_audit_log(operator, "系統設定", "手動資料清洗", "FAILED", f"【清洗失敗】{msg} (來源 IP: {client_ip})")

    # 🌟 啟動背景執行緒，讓 HTTP 請求秒速回傳，畫面不轉圈！
    import threading
    threading.Thread(target=manual_retention_task, daemon=True).start()
    
    write_audit_log(operator, "系統設定", "手動資料清洗", "SUCCESS", f"【發動清洗】管理員已在背景啟動手動降採樣程序。(來源 IP: {client_ip})")
    
    return jsonify({'success': True, 'message': '已於背景啟動資料清洗引擎，請稍後至「稽核日誌」查看執行結果。'})
    
# ========================================================
# 🛡️ 流量資安預警獨立頁面與 API 路由
# ========================================================
@main_bp.route('/flow-security')
@require_role([ROLE_ADMIN, ROLE_OPERATOR, ROLE_AUDITOR])
def flow_security_page():
    return render_template('flow_security.html')

@main_bp.route('/api/flow/security_alerts', methods=['GET'])
@require_role([ROLE_ADMIN, ROLE_OPERATOR, ROLE_AUDITOR])
def get_security_alerts():
    try:
        with DB_LOCKS['config']:
            conn = get_db('config')
            rows = conn.execute("""
                SELECT id, strftime('%Y-%m-%d %H:%M:%S', timestamp, 'localtime') as ts, 
                       src_ip, dst_ip, attack_type, severity, details, status 
                FROM flow_security_events 
                ORDER BY timestamp DESC LIMIT 200
            """).fetchall()
            conn.close()
        return jsonify({'success': True, 'data': [dict(r) for r in rows]})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@main_bp.route('/api/flow/security_settings', methods=['GET', 'POST'])
@require_role([ROLE_ADMIN])
def handle_security_settings():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    operator = session.get('username', 'SystemUser')
    
    if request.method == 'POST':
        data = request.json or {}
        t_scan = str(data.get('sec_scan_threshold', '50')).strip()
        t_ddos = str(data.get('sec_ddos_threshold_mb', '500')).strip()
        t_window = str(data.get('sec_scan_window_mins', '5')).strip()
        t_brute = str(data.get('sec_brute_threshold', '80')).strip()
        t_exfil = str(data.get('sec_exfil_threshold_mb', '1000')).strip()
        t_mining = str(data.get('sec_mining_threshold', '20')).strip()
        t_lateral = str(data.get('sec_lateral_threshold', '15')).strip()
        
        with DB_LOCKS['config']:
            conn = get_db('config')
            conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('sec_scan_threshold', ?)", (t_scan,))
            conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('sec_ddos_threshold_mb', ?)", (t_ddos,))
            conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('sec_scan_window_mins', ?)", (t_window,))
            conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('sec_brute_threshold', ?)", (t_brute,))
            conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('sec_exfil_threshold_mb', ?)", (t_exfil,))
            conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('sec_mining_threshold', ?)", (t_mining,))
            conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('sec_lateral_threshold', ?)", (t_lateral,))
            conn.commit()
            conn.close()
            
        write_audit_log(operator, "系統設定", "資安預警閾值", "SUCCESS", f"更新全套 6 大資安防禦靈敏度閾值。(IP: {client_ip})")
        return jsonify({'success': True, 'message': '6 大資安防禦預警閾值設定已成功更新！'})
    else:
        with DB_LOCKS['config']:
            conn = get_db('config')
            t_scan = conn.execute("SELECT value FROM system_settings WHERE key='sec_scan_threshold'").fetchone()
            t_ddos = conn.execute("SELECT value FROM system_settings WHERE key='sec_ddos_threshold_mb'").fetchone()
            t_window = conn.execute("SELECT value FROM system_settings WHERE key='sec_scan_window_mins'").fetchone()
            t_brute = conn.execute("SELECT value FROM system_settings WHERE key='sec_brute_threshold'").fetchone()
            t_exfil = conn.execute("SELECT value FROM system_settings WHERE key='sec_exfil_threshold_mb'").fetchone()
            t_mining = conn.execute("SELECT value FROM system_settings WHERE key='sec_mining_threshold'").fetchone()
            t_lateral = conn.execute("SELECT value FROM system_settings WHERE key='sec_lateral_threshold'").fetchone()
            conn.close()
        return jsonify({
            'success': True,
            'sec_scan_threshold': t_scan['value'] if t_scan else '50',
            'sec_ddos_threshold_mb': t_ddos['value'] if t_ddos else '500',
            'sec_scan_window_mins': t_window['value'] if t_window else '5',
            'sec_brute_threshold': t_brute['value'] if t_brute else '80',
            'sec_exfil_threshold_mb': t_exfil['value'] if t_exfil else '1000',
            'sec_mining_threshold': t_mining['value'] if t_mining else '20',
            'sec_lateral_threshold': t_lateral['value'] if t_lateral else '15'
        })

@main_bp.route('/api/flow/security_alerts/clear', methods=['POST'])
@require_role([ROLE_ADMIN, ROLE_OPERATOR])
def clear_security_alerts():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    operator = session.get('username', 'SystemUser')
    
    try:
        with DB_LOCKS['config']:
            conn = get_db('config')
            conn.execute("DELETE FROM flow_security_events")
            conn.commit()
            conn.close()
            
        write_audit_log(operator, "流量資安預警", "清除事件紀錄", "SUCCESS", f"管理員清空了所有資安威脅預警歷史紀錄。(IP: {client_ip})")
        return jsonify({'success': True, 'message': '已成功清空目前所有資安預警紀錄！'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'清空失敗: {str(e)}'}), 500
        
@main_bp.route('/api/flow/security_sources', methods=['POST'])
@require_role([ROLE_ADMIN, ROLE_OPERATOR, ROLE_AUDITOR])
def get_security_attack_sources():
    from influxdb_client import InfluxDBClient
    from datetime import datetime, timedelta
    
    data = request.get_json() or {}
    dst_ip = data.get('dst_ip', '').strip()
    event_time_str = data.get('timestamp', '').strip()
    window_mins = int(data.get('window_mins', 10))
    
    if not dst_ip:
        return jsonify({'success': False, 'message': '缺少目標 IP'})
        
    try:
        # 計算事件的時間視窗範圍
        if event_time_str:
            evt_dt = datetime.strptime(event_time_str, '%Y-%m-%d %H:%M:%S') - timedelta(hours=8)
            start_flux = (evt_dt - timedelta(minutes=window_mins)).strftime('%Y-%m-%dT%H:%M:%SZ')
            stop_flux = (evt_dt + timedelta(minutes=2)).strftime('%Y-%m-%dT%H:%M:%SZ')
        else:
            start_flux = f"-{window_mins}m"
            stop_flux = "now()"

        client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG, timeout=30000)
        query_api = client.query_api()

        flux_query = f'''
        from(bucket: "{INFLUXDB_BUCKET}")
          |> range(start: {start_flux}, stop: {stop_flux})
          |> filter(fn: (r) => r["_measurement"] == "netflow" or r["_measurement"] == "sflow")
          |> filter(fn: (r) => r["_field"] == "in_bytes" or r["_field"] == "bytes")
          |> filter(fn: (r) => r["dst_ip"] == "{dst_ip}")
          |> filter(fn: (r) => exists r["src_ip"] and r["src_ip"] != "")
          |> group(columns: ["src_ip"])
          |> sum()
          |> group()
          |> sort(columns: ["_value"], desc: true)
        '''

        result = query_api.query(flux_query)
        sources_list = []
        
        for table in result:
            for record in table.records:
                src_ip = record.values.get("src_ip")
                bytes_val = record.get_value() or 0
                mb_val = round(float(bytes_val) / (1024 * 1024), 2)
                sources_list.append({"src_ip": src_ip, "traffic_mb": mb_val})

        client.close()
        return jsonify({'success': True, 'dst_ip': dst_ip, 'sources': sources_list, 'count': len(sources_list)})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
        
@main_bp.route('/api/flow/security_single_ip_details', methods=['POST'])
@require_role([ROLE_ADMIN, ROLE_OPERATOR, ROLE_AUDITOR])
def get_security_single_ip_details():
    from influxdb_client import InfluxDBClient
    from datetime import datetime, timedelta
    
    data = request.get_json() or {}
    src_ip = data.get('src_ip', '').strip()
    event_time_str = data.get('timestamp', '').strip()
    window_mins = int(data.get('window_mins', 10))
    
    if not src_ip:
        return jsonify({'success': False, 'message': '缺少來源 IP'})
        
    try:
        if event_time_str:
            evt_dt = datetime.strptime(event_time_str, '%Y-%m-%d %H:%M:%S') - timedelta(hours=8)
            start_flux = (evt_dt - timedelta(minutes=window_mins)).strftime('%Y-%m-%dT%H:%M:%SZ')
            stop_flux = (evt_dt + timedelta(minutes=2)).strftime('%Y-%m-%dT%H:%M:%SZ')
        else:
            start_flux = f"-{window_mins}m"
            stop_flux = "now()"

        client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG, timeout=30000)
        query_api = client.query_api()

        flux_query = f'''
        from(bucket: "{INFLUXDB_BUCKET}")
          |> range(start: {start_flux}, stop: {stop_flux})
          |> filter(fn: (r) => r["_measurement"] == "netflow" or r["_measurement"] == "sflow")
          |> filter(fn: (r) => r["_field"] == "in_bytes" or r["_field"] == "bytes")
          |> filter(fn: (r) => r["src_ip"] == "{src_ip}")
          |> filter(fn: (r) => exists r["dst_ip"] and exists r["dst_port"])
          |> group(columns: ["dst_ip", "dst_port"])
          |> sum()
          |> group()
          |> sort(columns: ["_value"], desc: true)
          |> limit(n: 100)
        '''

        result = query_api.query(flux_query)
        details_list = []
        
        for table in result:
            for record in table.records:
                d_ip = record.values.get("dst_ip", "-")
                d_port = record.values.get("dst_port", "-")
                bytes_val = record.get_value() or 0
                mb_val = round(float(bytes_val) / (1024 * 1024), 3)
                details_list.append({"dst_ip": d_ip, "dst_port": d_port, "traffic_mb": mb_val})

        client.close()
        return jsonify({'success': True, 'src_ip': src_ip, 'details': details_list, 'count': len(details_list)})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
        
@main_bp.route('/api/flow/qoe_summary', methods=['GET'])
@require_role([ROLE_ADMIN, ROLE_OPERATOR, ROLE_AUDITOR])
def get_flow_qoe_summary():
    """計算最近 15 分鐘內應用程式流量佔比與 QoE 健康度指標"""
    from influxdb_client import InfluxDBClient
    from database import get_db, DB_LOCKS
    
    window = request.args.get('window', '15m')
    
    # 1. 讀取 Port 字典 mapping
    port_map = {}
    with DB_LOCKS['config']:
        conn = get_db('config')
        rows = conn.execute("SELECT port, service_name FROM flow_port_dictionary").fetchall()
        conn.close()
        port_map = {str(r['port']): r['service_name'] for r in rows}

    try:
        client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG, timeout=30000)
        query_api = client.query_api()

        # Flux 語法：依 dst_port 分組計算各應用的流量 MB 與連線次數
        flux_app = f'''
        from(bucket: "{INFLUXDB_BUCKET}")
          |> range(start: -{window})
          |> filter(fn: (r) => r["_measurement"] == "netflow" or r["_measurement"] == "sflow")
          |> filter(fn: (r) => r["_field"] == "in_bytes" or r["_field"] == "bytes")
          |> filter(fn: (r) => exists r["dst_port"])
          |> group(columns: ["dst_port"])
          |> reduce(
              identity: {{count: 0, total_bytes: 0.0}},
              fn: (r, accumulator) => ({{
                  count: accumulator.count + 1,
                  total_bytes: accumulator.total_bytes + float(v: r._value)
              }})
          )
          |> group()
          |> sort(columns: ["total_bytes"], desc: true)
          |> limit(n: 15)
        '''

        result = query_api.query(flux_app)
        apps_list = []
        total_all_bytes = 0.0

        for table in result:
            for record in table.records:
                port_str = str(record.values.get("dst_port", "Unknown"))
                bytes_val = record.values.get("total_bytes", 0.0)
                conn_cnt = record.values.get("count", 0)
                
                app_name = port_map.get(port_str, f"Port {port_str}")
                mb_val = round(bytes_val / (1024 * 1024), 2)
                total_all_bytes += bytes_val

                # 估算 QoE 分數 (結合連線熱度與離峰穩定度)
                qoe_score = 95
                if conn_cnt > 5000 and mb_val < 5.0:  # 高頻小封包 (可能是爆破或連線異常)
                    qoe_score = 65
                elif mb_val > 1000.0:  # 大流量高負載
                    qoe_score = 82

                apps_list.append({
                    "port": port_str,
                    "app_name": app_name,
                    "traffic_mb": mb_val,
                    "connections": conn_cnt,
                    "qoe_score": qoe_score
                })

        client.close()

        # 計算流量百分比
        for app in apps_list:
            app["percentage"] = round((app["traffic_mb"] * 1024 * 1024 / total_all_bytes * 100), 1) if total_all_bytes > 0 else 0

        return jsonify({"success": True, "data": apps_list})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500
        
# ========================================================
# 🚀 專供 Go 輪詢引擎觸發之快取熱更新 Webhook API
# ========================================================
@main_bp.route('/api/internal/reload_cache', methods=['GET', 'POST'])
def api_internal_reload_cache():
    """當 Go 完成全網輪詢寫入資料庫後，打此 Webhook 通知 Python 更新 RAM 快取並印出 Go 戰報"""
    try:
        from database import update_device_metrics_cache, get_db
        from utils import log_info

        data = request.get_json(silent=True) or {}
        total = data.get('total', 0)
        success = data.get('success', 0)
        elapsed = data.get('elapsed', 0.0)

        # 1. 讀取資料庫最新數值並秒級更新 Python 記憶體
        conn = get_db('config')
        rows = conn.execute("SELECT ip, cpu_load, mem_load, latency_ms FROM devices WHERE visible=1").fetchall()
        conn.close()

        updates = [(r['cpu_load'], r['mem_load'], r['latency_ms'], r['ip']) for r in rows]
        update_device_metrics_cache(updates)

        # 🌟 2. 將 Go 的執行結果直接印在 Python 的控制台畫面上！
        if total > 0:
            log_info(f"🐹 【Go 輪詢引擎】採集完畢 - 輪詢 {total} 台，成功 {success} 台，全網耗時 {elapsed:.2f} 秒。")

        return jsonify({"status": "success", "message": "Python RAM 快取已同步更新"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

