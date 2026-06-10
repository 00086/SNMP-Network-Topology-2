import threading
import ipaddress
import time
import platform
import subprocess
import ctypes
import sys
import os
from flask import Flask, request

# 💡 導入微服務模組
from utils import log_info
from database import init_db, get_db, write_audit_log, DB_LOCKS
from routes import main_bp
from snmp_core import traffic_polling_worker, topology_scan_worker, data_retention_worker, snmp_trap_receiver_worker

# 1. 在檔案最上方引入我們剛寫好的備份資料庫初始化函式
from tftp_backup_core import init_backup_db, trigger_tftp_backup

def is_admin():
    """檢查目前是否具備 Windows 系統管理員或 Linux root 權限"""
    try:
        if platform.system().lower() == 'windows':
            return ctypes.windll.shell32.IsUserAnAdmin()
        else:
            # Linux / macOS 系統下，root 的 UID 永遠是 0
            return os.getuid() == 0
    except:
        return False

app = Flask(__name__)

app.secret_key = os.urandom(24)  # 🌟 必須加入這行，Flask 的 Session (RBAC 登入狀態) 才能運作！

# 🌟 補上這行，設定 Flask Session 專用的加密密鑰
# 建議使用 os.urandom(24) 或一串複雜的隨機字串
#app.secret_key = 'admin'

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
                    
                    # 💡 加上表情符號，精準寫入資料庫
                    write_audit_log("SystemEngine", "NTP背景排程", "背景守護行程", "SUCCESS", f"⏱️ 【NTP背景排程】{msg}")
                    # 💡 使用 [] 代替 【】，避開 log_info 的自動資料庫攔截！
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
                en_row = conn.execute("SELECT value FROM system_settings WHERE key='autobackup_enabled'").fetchone()
                time_row = conn.execute("SELECT value FROM system_settings WHERE key='autobackup_time'").fetchone()
                scope_row = conn.execute("SELECT value FROM system_settings WHERE key='autobackup_scope'").fetchone()
                conn.close()
                
            is_enabled = (en_row['value'] == '1') if en_row else False
            target_time = time_row['value'] if time_row else '02:00'
            scope = scope_row['value'] if scope_row else 'all'
            
            now = datetime.datetime.now()
            current_time = now.strftime("%H:%M")
            current_date = now.strftime("%Y-%m-%d")
            
            # 時間到，且今天還沒跑過，啟動大備份！
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

                # 🚀 10 核心引擎
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

# =========================================================================
# 🛠️ 終極資料庫效能優化引擎 (加入 Timeout 防呆，解決卡 2 分鐘死鎖)
# =========================================================================
def optimize_database():
    try:
        log_info("🛠️ 正在最佳化資料庫效能 (開啟 WAL 與索引用以解決轉圈圈)...")
        for db_name in ['hot', 'warm', 'config']:
            if db_name in DB_LOCKS:
                with DB_LOCKS[db_name]:
                    conn = get_db(db_name)
                    # 💡 防呆機制：只等 3 秒，若被舊行程死鎖就放棄，保證伺服器秒開
                    conn.execute("PRAGMA busy_timeout = 3000;")
                    conn.execute("PRAGMA journal_mode=WAL;")
                    conn.execute("PRAGMA synchronous=NORMAL;")
                    
                    # 🌟 效能革命新增：
                    # 1. 強制所有暫存索引運算在 RAM 記憶體中執行，完全不碰硬碟
                    conn.execute("PRAGMA temp_store=MEMORY;")
                    # 2. 拉高 WAL 寫入硬碟的閾值至 10,000 頁 (約 40MB)，讓資料長時間駐留 OS 記憶體快取中批次處理
                    conn.execute("PRAGMA wal_autocheckpoint=10000;")
                    
                    if db_name == 'hot':
                        conn.execute("CREATE INDEX IF NOT EXISTS idx_traffic_hist ON traffic_history(ip, port_idx, timestamp);")
                        conn.execute("CREATE INDEX IF NOT EXISTS idx_metrics_hist ON metrics_history(ip, timestamp);")
                    conn.commit()
                    conn.close()
        log_info("✅ 資料庫效能最佳化完成！(記憶體高吞吐模式已啟動)")
    except Exception as e:
        log_info(f"⚠️ 資料庫已被佔用，略過本次最佳化 (請確認無其他舊 Python 執行緒): {e}")

if __name__ == '__main__':
    
    from tftp_backup_core import init_backup_db, sys_tftp_server
    
    # 💡 觸發建立或檢查備份資料庫 (bkpswcfg.db)
    init_backup_db()
    
    # 💡 啟動背景 TFTP 接球員
    sys_tftp_server.start()
    
    # 💡 智慧權限守門員：不限於 NTP，將來擴充任何底層功能都適用
    if not is_admin():
        # 這裡將原因抽離成變數，不寫死單一原因，涵蓋未來的系統級操作
        sys_requirements = "NTP 網路校時、底層 ICMP 探測、服務控管等系統層級操作"
        print(f"\n⚠️ 【系統權限不足】")
        print(f"為了確保網管系統能夠順利執行 {sys_requirements}，本系統需要較高的執行權限。")
        
        if platform.system().lower() == 'windows':
            print("🔄 正在自動請求 Windows 系統管理員 (Administrator) 權限...")
            print("👉 請在稍後彈出的 UAC 視窗中點選「是」即可。\n")
            # 觸發 UAC 授權視窗，並以管理員身分重新執行
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            sys.exit() # 結束目前無權限的舊視窗，把舞台交給新開的管理員視窗
        else:
            print("❌ 系統啟動中止！")
            print("👉 在 Linux 系統下，請使用 sudo 重新啟動本系統，例如：")
            print("   sudo python app.py\n")
            sys.exit() # Linux 無法輕易透過 GUI 彈窗，因此提示後退出，要求使用者打 sudo

    try:
        init_db()
        optimize_database()
        
        threading.Thread(target=traffic_polling_worker, daemon=True).start()
        threading.Thread(target=topology_scan_worker, daemon=True).start()
        threading.Thread(target=data_retention_worker, daemon=True).start()
        threading.Thread(target=ntp_sync_worker, daemon=True).start()
        
        # 🌟 加入這行：啟動 SNMP Trap 主動告警接收引擎
        threading.Thread(target=snmp_trap_receiver_worker, daemon=True).start()
        
        # 🌟 加入這行：啟動自動備份引擎
        threading.Thread(target=auto_backup_worker, daemon=True).start()

        # 🌟 強制解鎖：開啟 threaded=True 讓 Flask 伺服器允許並行處理多個 HTTP 請求！
        #app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False, threaded=True)        
        
        # 🚀 換上商用級 Waitress 伺服器引擎
        from waitress import serve
        print("🔒 【生產級伺服器】Waitress 服務引擎已成功發動，正監聽 Port 5000...")
        print("👉 請開啟瀏覽器進入 http://127.0.0.1:5000 或 http://您的主機IP:5000")
        
        # 啟動 Waitress，開啟 12 個執行緒應付多用戶同時操作
        serve(app, host='0.0.0.0', port=5000, threads=12)
    
    except KeyboardInterrupt:
        print("\n👋 【系統通知】偵測到關閉指令，正在釋放多核心子進程並優雅退出...")
        os._exit(0)