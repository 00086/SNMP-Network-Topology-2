import multiprocessing
import warnings
import sys
import threading
import ipaddress
import time
import platform
import subprocess
import ctypes
import os
from flask import Flask, request

# 🌟 1. 全域靜音過濾器 (消滅 InfluxDB 重複欄位警告)
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", message=".*duplicated names.*")

# 🌟 2. 雙重精準封殺：覆蓋 InfluxDB SDK 內部兩大解析模組的 warn 函數
try:
    import influxdb_client.client.flux_csv_parser as flux_csv_parser
    flux_csv_parser.warn = lambda *args, **kwargs: None
except Exception:
    pass

try:
    import influxdb_client.client.flux_table as flux_table
    flux_table.warn = lambda *args, **kwargs: None
except Exception:
    pass

# 💡 導入微服務模組
from utils import log_info
from database import init_db, get_db, write_audit_log, DB_LOCKS
from routes import main_bp
from snmp_core import (
    traffic_polling_worker, topology_scan_worker, 
    data_retention_worker, snmp_trap_receiver_worker, 
    flow_security_worker
)
from tftp_backup_core import init_backup_db, trigger_tftp_backup, sys_tftp_server

def is_admin():
    """檢查目前是否具備 Windows 系統管理員或 Linux root 權限"""
    try:
        if platform.system().lower() == 'windows':
            return ctypes.windll.shell32.IsUserAnAdmin()
        else:
            return os.getuid() == 0
    except Exception:
        return False

app = Flask(__name__)
app.secret_key = os.urandom(24)  # 🌟 Flask Session 加密金鑰
app.register_blueprint(main_bp)

# ==========================================
# ⏱️ 背景自動 NTP 校時引擎守護行程
# ==========================================
def ntp_sync_worker():
    import time, subprocess, platform, re
    from database import get_db, DB_LOCKS, write_audit_log
    from utils import log_info
    
    log_info("⏱️ [NTP背景排程] NTP 自動校時守護行程已啟動！")
    time.sleep(15) 
    
    last_sync_time = 0
    
    while True:
        try:
            with DB_LOCKS['config']:
                conn = get_db('config')
                cur_s = conn.execute("SELECT value FROM system_settings WHERE key='ntp_servers'").fetchone()
                cur_i = conn.execute("SELECT value FROM system_settings WHERE key='ntp_interval'").fetchone()
                conn.close()
            
            servers_str = cur_s['value'] if cur_s else 'tw.pool.ntp.org'
            interval_mins = int(cur_i['value']) if cur_i else 60
            
            if time.time() - last_sync_time >= interval_mins * 60:
                last_sync_time = time.time()
                
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
                                success = True; used_server = s; break
                            else:
                                err_text = (res.stderr + res.stdout).strip()
                                if "存取被拒" in err_text or "Access is denied" in err_text: error_reasons.add("權限不足")
                                elif "沒有服務" in err_text or "not started" in err_text.lower(): error_reasons.add("Windows Time 服務未啟動")
                                else: error_reasons.add(f"連線失敗 ({s})")
                        else:
                            res = subprocess.run(['ntpdate', '-u', s], capture_output=True, text=True)
                            if res.returncode == 0:
                                success = True; used_server = s
                                m = re.search(r'offset ([-0-9.]+) sec', res.stdout)
                                if m: offset_info = f"偏差值 {m.group(1)} 秒"
                                break
                            else: error_reasons.add("執行 ntpdate 失敗")
                    except Exception as e: error_reasons.add(str(e))
                        
                elapsed = round(time.time() - start_time, 2)
                
                if success:
                    msg = f"背景守護行程已成功向 NTP 伺服器【 {used_server} 】完成系統時間同步，耗時 {elapsed} 秒。"
                    if offset_info: msg += f" (校正 {offset_info})"
                    
                    write_audit_log("SystemEngine", "NTP背景排程", "背景守護行程", "SUCCESS", f"⏱️ 【NTP背景排程】{msg}")
                    log_info(f"⏱️ [NTP背景排程] {msg}")
                else:
                    reason_str = "、".join(list(error_reasons)) if error_reasons else "所有伺服器皆無回應"
                    msg = f"背景守護行程嘗試向【 {servers_str} 】進行校時失敗。原因: {reason_str}。"
                    
                    write_audit_log("SystemEngine", "NTP背景排程", "背景守護行程", "FAILED", f"⚠️ 【NTP背景排程】{msg}")
                    log_info(f"⚠️ [NTP背景排程] {msg}")
                    
        except Exception as e:
            log_info(f"⚠️ [NTP背景排程] 發生異常: {e}")
            
        time.sleep(60)

# ==========================================
# 💾 背景每日自動備份引擎守護行程 (8 並發)
# ==========================================
def auto_backup_worker():
    import time, datetime, random
    import concurrent.futures
    from database import get_db, DB_LOCKS, write_audit_log
    from utils import log_info
    
    log_info("⏰ [自動排程] 每日自動備份設定檔守護行程已啟動！")
    time.sleep(30)
    
    last_run_date = ""
    
    while True:
        try:
            with DB_LOCKS['config']:
                conn = get_db('config')
                hq_row = conn.execute("SELECT value FROM system_settings WHERE key='hq_view_mode'").fetchone()
                en_row = conn.execute("SELECT value FROM system_settings WHERE key='autobackup_enabled'").fetchone()
                time_row = conn.execute("SELECT value FROM system_settings WHERE key='autobackup_time'").fetchone()
                scope_row = conn.execute("SELECT value FROM system_settings WHERE key='autobackup_scope'").fetchone()
                conn.close()
                
            if hq_row and hq_row['value'] == 'hq':
                time.sleep(60)
                continue
                
            is_enabled = (en_row['value'] == '1') if en_row else False
            target_time = time_row['value'] if time_row else '02:00'
            scope = scope_row['value'] if scope_row else 'all'
            
            now = datetime.datetime.now()
            current_time = now.strftime("%H:%M")
            current_date = now.strftime("%Y-%m-%d")
            
            if is_enabled and current_time == target_time and last_run_date != current_date:
                last_run_date = current_date
                log_info(f"🚀 [自動備份] 時間到 ({target_time})！啟動背景 10 並發備份任務，範圍: {scope}")
                
                with DB_LOCKS['config']:
                    conn = get_db('config')
                    devs = conn.execute("SELECT * FROM devices WHERE status != 'down'").fetchall()
                    conn.close()
                    
                targets = []
                for d in devs:
                    lvl = int(d['level'] if d['level'] else 3)
                    t = str(d['type']).strip()
                    vis = int(d['visible'] if d['visible'] else 1)
                    ip = d['ip']
                    
                    if (1 <= lvl <= 4) and t in ['交換器', '防火牆', 'AP控制器'] and ip:
                        if scope == 'all' or (scope == 'visible' and vis == 1):
                            targets.append(dict(d))
                            
                if not targets:
                    log_info("⚠️ [自動備份] 找不到符合條件的活躍設備，跳過本次備份。")
                    continue
                    
                success_count = 0; fail_count = 0; failed_list = []
                start_timer = time.time()
                
                def backup_task(dev):
                    ip = dev['ip']
                    username = dev.get('ssh_user', '').strip()
                    password = dev.get('ssh_pass', '').strip()
                    secret = dev.get('ssh_secret', '').strip()
                    cli_type = dev.get('cli_type', '').strip()
                    brand = str(dev.get('brand', 'Unknown')).lower()
                    model = str(dev.get('model', '')).lower()
                    sys_descr = str(dev.get('sys_descr', '')).lower()
                    
                    if cli_type: d_type = cli_type
                    else:
                        if 'ruckus' in brand: d_type = 'ruckus_fastiron'
                        elif 'cisco' in brand: d_type = 'cisco_ios'
                        elif 'cx' in model or 'aos-cx' in sys_descr: d_type = 'aruba_aoscx' 
                        elif 'aruba' in brand or 'hp' in brand: d_type = 'aruba_os'
                        elif 'palo' in brand or 'pan-os' in brand: d_type = 'paloalto_panos'
                        elif 'mikrotik' in brand or 'routeros' in sys_descr: d_type = 'mikrotik_routeros'
                        else: d_type = 'generic'

                    success = False
                    for attempt in range(1, 4):
                        if attempt > 1: time.sleep(random.uniform(2.0, 5.0))
                        success = trigger_tftp_backup(ip, username, password, secret, d_type)
                        if success: break
                    return (dev['name'] or ip, ip, success)

                with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
                    results = executor.map(backup_task, targets)
                    
                for name, ip, success in results:
                    if success: success_count += 1
                    else: fail_count += 1; failed_list.append(f"{name} ({ip})")
                        
                time_taken = round(time.time() - start_timer, 1)
                scope_text = "顯示中設備" if scope == 'visible' else "全網(L1~L4)"
                
                audit_details = f"背景批次備份任務結束。範圍: {scope_text}，總耗時: {time_taken} 秒。總計: {len(targets)} 台，成功: {success_count} 台，失敗: {fail_count} 台。"
                if fail_count > 0: audit_details += f" ❌ 失敗清單: {', '.join(failed_list)}"
                    
                write_audit_log("SystemEngine", "批次備份總結", "夜間自動備份排程", "SUCCESS" if fail_count==0 else "WARNING", f"【自動排程】{audit_details}")
                log_info(f"📊 [自動備份] 任務完畢！耗時 {time_taken}s，成功: {success_count}，失敗: {fail_count}。")

        except Exception as e:
            log_info(f"⚠️ [自動備份排程] 發生異常: {e}")
            
        time.sleep(60)

# ==========================================
# 🌍 背景總部推播引擎 (HQ Sync Engine)
# ==========================================
def hq_sync_worker():
    import time
    from datetime import datetime
    from database import get_db, DB_LOCKS
    from utils import log_info

    log_info("📡 [推播排程] 多站點自動推播守護行程已啟動！")
    time.sleep(20)

    while True:
        try:
            with DB_LOCKS['config']:
                conn = get_db('config', bypass_shard=True)
                settings = {r['key']: r['value'] for r in conn.execute("SELECT key, value FROM system_settings WHERE key IN ('hq_view_mode', 'hq_server_url', 'hq_sync_secret', 'site_district', 'site_code', 'site_name', 'sync_topo_start', 'sync_topo_interval', 'sync_status_start', 'sync_status_interval', 'last_sync_topo', 'last_sync_status')").fetchall()}
                conn.close()

            if settings.get('hq_view_mode') == 'local' and settings.get('hq_server_url') and settings.get('hq_sync_secret'):
                current_time = datetime.now()
                
                # ── 1. 處理狀態高頻推播 ──
                interval_status = int(settings.get('sync_status_interval', '0'))
                if interval_status > 0:
                    last_status_str = settings.get('last_sync_status')
                    should_push_status = False
                    
                    if not last_status_str:
                        should_push_status = True
                    else:
                        try:
                            last_status = datetime.strptime(last_status_str, '%Y-%m-%d %H:%M:%S')
                            if (current_time - last_status).total_seconds() >= (interval_status * 60):
                                should_push_status = True
                        except:
                            should_push_status = True

                    if should_push_status:
                        try:
                            with DB_LOCKS['config']:
                                conn = get_db('config', bypass_shard=True)
                                conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('last_sync_status', ?)", (current_time.strftime('%Y-%m-%d %H:%M:%S'),))
                                conn.commit()
                                conn.close()
                                
                            from routes import hq_manual_push
                            with app.test_request_context('/api/hq/manual_push/status', method='POST'):
                                from flask import session
                                session['role'] = 'admin'
                                session['username'] = 'BackgroundWorker'
                                hq_manual_push('status')
                                
                            log_info(f"📡 【排程引擎】自動推播戰情狀態至總部完成。")
                        except Exception as e:
                            log_info(f"⚠️ 【排程引擎】自動推播狀態失敗: {e}")

                # ── 2. 處理拓樸低頻推播 ──
                interval_topo = int(settings.get('sync_topo_interval', '0'))
                if interval_topo > 0:
                    last_topo_str = settings.get('last_sync_topo')
                    should_push_topo = False
                    
                    if not last_topo_str:
                        should_push_topo = True
                    else:
                        try:
                            last_topo = datetime.strptime(last_topo_str, '%Y-%m-%d %H:%M:%S')
                            if (current_time - last_topo).total_seconds() >= (interval_topo * 60 * 60): 
                                should_push_topo = True
                        except:
                            should_push_topo = True

                    if should_push_topo:
                        try:
                            with DB_LOCKS['config']:
                                conn = get_db('config', bypass_shard=True)
                                conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('last_sync_topo', ?)", (current_time.strftime('%Y-%m-%d %H:%M:%S'),))
                                conn.commit()
                                conn.close()
                                
                            from routes import hq_manual_push
                            with app.test_request_context('/api/hq/manual_push/topology', method='POST'):
                                from flask import session
                                session['role'] = 'admin'
                                session['username'] = 'BackgroundWorker'
                                hq_manual_push('topology')
                                
                            log_info(f"📡 【排程引擎】自動推播拓樸藍圖至總部完成。")
                        except Exception as e:
                            log_info(f"⚠️ 【排程引擎】自動推播拓樸失敗: {e}")

        except Exception as e:
            pass
            
        time.sleep(60)

# =========================================================================
# 🛠️ 終極資料庫效能優化引擎
# =========================================================================
def optimize_database():
    try:
        log_info("🛠️ 正在最佳化資料庫效能 (開啟 WAL 與索引用以解決轉圈圈)...")
        for db_name in ['hot', 'warm', 'config']:
            if db_name in DB_LOCKS:
                with DB_LOCKS[db_name]:
                    conn = get_db(db_name)
                    conn.execute("PRAGMA busy_timeout = 3000;")
                    conn.execute("PRAGMA journal_mode=WAL;")
                    conn.execute("PRAGMA synchronous=NORMAL;")
                    conn.execute("PRAGMA temp_store=MEMORY;")
                    conn.execute("PRAGMA wal_autocheckpoint=10000;")
                    
                    if db_name == 'hot':
                        conn.execute("CREATE INDEX IF NOT EXISTS idx_traffic_hist ON traffic_history(ip, port_idx, timestamp);")
                        conn.execute("CREATE INDEX IF NOT EXISTS idx_metrics_hist ON metrics_history(ip, timestamp);")
                    conn.commit()
                    conn.close()
        log_info("✅ 資料庫效能最佳化完成！(記憶體高吞吐模式已啟動)")
    except Exception as e:
        log_info(f"⚠️ 資料庫已被佔用，略過本次最佳化: {e}")

if __name__ == '__main__':
    multiprocessing.freeze_support()  # 🌟 核心修復：防止 Windows Spawn 子進程控制代碼失效[cite: 10]
    
    init_backup_db()
    sys_tftp_server.start()
    
    if not is_admin():
        sys_requirements = "NTP 網路校時、底層 ICMP 探測、服務控管等系統層級操作"
        print(f"\n⚠️ 【系統權限不足】")
        print(f"為了確保網管系統能夠順利執行 {sys_requirements}，本系統需要較高的執行權限。")
        
        if platform.system().lower() == 'windows':
            print("🔄 正在自動請求 Windows 系統管理員 (Administrator) 權限...")
            print("👉 請在稍後彈出的 UAC 視窗中點選「是」即可。\n")
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            sys.exit()
        else:
            print("❌ 系統啟動中止！")
            print("👉 在 Linux 系統下，請使用 sudo 重新啟動本系統，例如：")
            print("   sudo python app.py\n")
            sys.exit()

    try:
        init_db()
        optimize_database()
        
        threading.Thread(target=traffic_polling_worker, daemon=True).start()
        threading.Thread(target=topology_scan_worker, daemon=True).start()
        threading.Thread(target=data_retention_worker, daemon=True).start()
        threading.Thread(target=ntp_sync_worker, daemon=True).start()
        threading.Thread(target=snmp_trap_receiver_worker, daemon=True).start()
        threading.Thread(target=auto_backup_worker, daemon=True).start()
        threading.Thread(target=hq_sync_worker, daemon=True).start()
        threading.Thread(target=flow_security_worker, daemon=True).start()

        from waitress import serve
        print("🔒 【生產級伺服器】Waitress 服務引擎已成功發動，正監聽 Port 5000...")
        print("👉 請開啟瀏覽器進入 http://127.0.0.1:5000 或 http://您的主機IP:5000")
        
        serve(app, host='0.0.0.0', port=5000, threads=12)
    
    except KeyboardInterrupt:
        print("\n👋 【系統通知】偵測到關閉指令，正在釋放多核心子進程並優雅退出...")
        os._exit(0)