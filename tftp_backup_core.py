import os
import time
import socket
import struct
import threading
import sqlite3
from netmiko import ConnectHandler

DB_FILE = 'bkpswcfg.db'

# ==========================================
# 📘 模組 1：資料庫初始化與寫入
# ==========================================
def init_backup_db():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS config_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                device_type TEXT,
                backup_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                config_text TEXT,
                status TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ip ON config_history(ip)")
        conn.commit()
        
    # 🌟 關鍵修正：直接在內部載入原生的系統日誌與終端機輸出函式！
    try:
        from utils import log_info
        from database import write_audit_log
        log_info("✅ [DB] 設定檔專屬資料庫 (bkpswcfg.db) 已準備就緒！")
        write_audit_log("SystemEngine", "服務啟動", "設定檔資料庫就緒", "SUCCESS", "✅ 【服務啟動】設定檔專屬備份資料庫 (bkpswcfg.db) 已初始化並準備就緒。")
    except:
        # 防呆：萬一獨立測試此腳本時抓不到外部模組，依然能印出字
        print("✅ [DB] 設定檔專屬資料庫 (bkpswcfg.db) 已準備就緒！")

def save_config_to_db(ip, device_type, config_text, status="success"):
    try:
        # 將超時排隊時間由 15 秒放寬至 30 秒，避免 10 機併發時硬碟寫入打結
        with sqlite3.connect(DB_FILE, timeout=30.0) as conn:
            # 1. 寫入本次最新的備份紀錄
            conn.execute("""
                INSERT INTO config_history (ip, device_type, config_text, status)
                VALUES (?, ?, ?, ?)
            """, (ip, device_type, config_text, status))
            conn.commit()

            # 🌟 2. 自動清理機制：如果該設備備份成功的歷史紀錄超過 3 次，就刪除最早的！
            if status == "success":
                # 撈出前 3 最新紀錄的 id
                cursor = conn.execute("""
                    SELECT id FROM config_history 
                    WHERE ip = ? AND status = 'success' 
                    ORDER BY backup_time DESC LIMIT 3
                """, (ip,))
                keep_ids = [str(row[0]) for row in cursor.fetchall()]
                
                if len(keep_ids) == 3:
                    # 刪除不在這 3 個最新 id 裡面的更早歷史紀錄
                    placeholders = ",".join("?" for _ in keep_ids)
                    conn.execute(f"""
                        DELETE FROM config_history 
                        WHERE ip = ? AND status = 'success' AND id NOT IN ({placeholders})
                    """, (ip, *keep_ids))
                    conn.commit()
                    
        print(f"💾 [入庫成功] 設備 {ip} 的設定檔已安全存入，並維持最新 3 筆歷史版本！")
    except Exception as e:
        print(f"❌ [入庫失敗] 設備 {ip} 寫入資料庫發生錯誤: {e}")

# ==========================================
# 📘 模組 2：內建背景 TFTP 伺服器 (完美接球員)
# ==========================================
class SmartTFTPServer:
    def __init__(self, temp_dir="temp_tftp"):
        self.temp_dir = temp_dir
        self.sock = None
        self.running = False
        self.current_bind_ip = '0.0.0.0'

    def start(self):
        if self.running: return
        os.makedirs(self.temp_dir, exist_ok=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.sock.bind(('0.0.0.0', 69))
            self.running = True
            threading.Thread(target=self._listen_loop, daemon=True).start()
            
            # 🌟 原生呼叫：完美寫入終端機與資料庫
            try:
                from utils import log_info
                from database import write_audit_log
                log_info("🚀 [TFTP] 背景智慧 TFTP 伺服器已啟動 (Port 69等待接球)...")
                write_audit_log("SystemEngine", "服務啟動", "TFTP 接收伺服器", "SUCCESS", "🚀 【服務啟動】背景智慧 TFTP 伺服器已成功啟動，正於 Port 69 等待設備回傳設定檔。")
            except:
                print("🚀 [TFTP] 背景智慧 TFTP 伺服器已啟動 (Port 69等待接球)...")
            
        except Exception as e:
            # 🌟 原生呼叫：異常時也要完美通報
            try:
                from utils import log_info
                from database import write_audit_log
                log_info(f"❌ [TFTP] 啟動失敗: {e} (可能 Port 69 被其他程式佔用了)")
                write_audit_log("SystemEngine", "服務異常", "TFTP 接收伺服器", "FAILED", f"❌ 【服務異常】啟動失敗，請檢查 Port 69 是否被其他程式佔用。錯誤訊息: {e}")
            except:
                print(f"❌ [TFTP] 啟動失敗: {e} (可能 Port 69 被其他程式佔用了)")

    def stop(self):
        self.running = False
        if self.sock:
            try: self.sock.close()
            except: pass

    def _listen_loop(self):
        self.sock.settimeout(1.0) 
        while self.running:
            try:
                data, addr = self.sock.recvfrom(2048)
                if len(data) < 4: continue
                opcode = struct.unpack("!H", data[0:2])[0]
                
                if opcode == 2:  # 收到 WRQ (寫入請求)
                    filename = data[2:].split(b'\x00')[0].decode('utf-8', errors='ignore')
                    save_path = os.path.join(self.temp_dir, os.path.basename(filename))
                    print(f"\n📥 [TFTP] 正在接收來自 {addr[0]} 的設定檔: {filename}")
                    threading.Thread(target=self._handle_transfer, args=(addr, save_path, filename), daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                pass

    def _handle_transfer(self, client_addr, save_path, filename):
        transfer_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        transfer_sock.bind(('0.0.0.0', 0))
        
        blksize = 512
        transfer_sock.sendto(struct.pack("!HH", 4, 0), client_addr)
        expected_block = 1
        transfer_sock.settimeout(3.0)
        
        try:
            with open(save_path, "wb") as f:
                while self.running:
                    try:
                        packet, addr = transfer_sock.recvfrom(blksize + 128)
                        if addr[0] != client_addr[0] or len(packet) < 4: continue
                        
                        op, block = struct.unpack("!HH", packet[:4])
                        if op == 3:  # DATA
                            if block == expected_block:
                                f.write(packet[4:])
                                transfer_sock.sendto(struct.pack("!HH", 4, block), client_addr)
                                expected_block += 1
                                
                                if len(packet[4:]) < blksize:
                                    print(f"✅ [TFTP] 接收完畢！正在將 {client_addr[0]} 的設定檔寫入資料庫...")
                                    break
                            elif block < expected_block:
                                transfer_sock.sendto(struct.pack("!HH", 4, block), client_addr)
                    except socket.timeout:
                        transfer_sock.sendto(struct.pack("!HH", 4, expected_block - 1), client_addr)
                        
            # 💡 傳輸成功後，智慧判斷是純文字還是二進位檔！
            time.sleep(0.5)
            import base64
            with open(save_path, 'rb') as f:
                raw_data = f.read()
            
            try:
                # 先嘗試用純文字 (UTF-8) 解碼 (Cisco, Ruckus, Aruba 等都是文字檔)
                config_text = raw_data.decode('utf-8')
                print(f"📝 [格式偵測] {client_addr[0]} 傳回的是純文字設定檔。")
            except UnicodeDecodeError:
                # 發生解碼錯誤，代表這是二進位檔 (如 D-Link 1210 的 .bin 檔)
                print(f"📦 [格式偵測] {client_addr[0]} 傳回的是二進位檔案 (.bin)！啟動 Base64 無損封裝。")
                # 將二進位檔轉成 Base64 字串，安全存入 SQLite 的文字欄位
                encoded_bin = base64.b64encode(raw_data).decode('utf-8')
                config_text = f"=== [SYSTEM_BINARY_CONFIG_BASE64] ===\n{encoded_bin}"
                
            # 🌟 智慧校正：嘗試從檔名提取真實目標 IP，解決 Mgmt IP 偏移或 NAT 造成的來源 IP 錯誤
            db_ip = client_addr[0]
            import re
            ip_match = re.search(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})_config", filename)
            if ip_match:
                db_ip = ip_match.group(1)
                if db_ip != client_addr[0]:
                    print(f"🔍 [IP 校正] 從檔名識別出真實設備 IP 為: {db_ip} (實際傳輸來源 IP: {client_addr[0]})")

            # ==========================================
            # 🌟 終極潔癖防線：這個 IP 真的在我們的管轄範圍內嗎？
            # ==========================================
            is_valid_device = False
            try:
                import sqlite3
                # 🌟 同步加上 timeout=30.0，確保 10 台設備同時透過 UDP 69 回傳設定檔時不塞車
                with sqlite3.connect('network_topology.db', timeout=30.0) as top_conn:
                    cursor = top_conn.execute("SELECT 1 FROM devices WHERE ip = ?", (db_ip,))
                    if cursor.fetchone():
                        is_valid_device = True
            except:
                # 防呆機制：萬一資料庫讀不到，為避免誤刪，先放行寫入
                is_valid_device = True 
                
            if is_valid_device:
                # ✅ 只有合法的 IP 才能寫入設定檔歷史庫
                save_config_to_db(db_ip, "auto", config_text, "success")
            else:
                # ❌ 拒絕寫入，並留下日誌軌跡
                print(f"⚠️ [TFTP 拒絕] 收到檔案，但解析出的 IP ({db_ip}) 不在設備清單內，直接當作垃圾丟棄！")
                try:
                    from database import write_audit_log
                    write_audit_log("SystemEngine", "設定檔接收異常", "攔截陌生來源", "WARNING", f"拒絕寫入來自 {client_addr[0]} 的設定檔，因為目標 {db_ip} 不在設備清單中。")
                except: pass

            # 無論成功寫入或拒絕，最後都把硬碟裡的暫存檔刪掉保持乾淨
            os.remove(save_path)
            
        except Exception as e:
            print(f"❌ [TFTP 傳輸錯誤] {e}")
        finally:
            transfer_sock.close()

sys_tftp_server = SmartTFTPServer()

# ==========================================
# 📘 模組 3：SSH / Telnet 萬能指令派發引擎
# ==========================================
def get_local_ip_facing_target(target_host):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target_host, 1))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = "127.0.0.1"
    finally:
        s.close()
    return local_ip

def trigger_tftp_backup(ip, username, password, secret, device_type):
    local_tftp_ip = get_local_ip_facing_target(ip)
    
    # 🌟 統一使用 .cfg 副檔名
    ext = ".cfg"
    if "mikrotik" in device_type:
        ext = ".rsc"
        
    filename = f"{ip}_config{ext}"
    
    # =========================================================================
    # 🌟 驅動層精準切離：新舊型 D-Link 走完全不同的底層通道，根除自動探測卡死
    # =========================================================================
    netmiko_type = device_type
    is_completely_old_dlink = False
    
    # 🎯 第一重防線：如果在 CSV 裡指定為 old 驅動，直接強行進駐通用 cisco 通道！
    if device_type == 'dlink_old':
        netmiko_type = 'cisco_ios_telnet'
        is_completely_old_dlink = True
    elif device_type == 'aruba_aoscx' or device_type == 'aruba_cx':
        netmiko_type = 'aruba_os'
    elif 'ruckus' in device_type and 'telnet' not in device_type:
        netmiko_type = 'ruckus_fastiron'
    elif 'cisco' in device_type and 'telnet' not in device_type:
        netmiko_type = 'cisco_ios'
        
    device_params = {
        'device_type': netmiko_type,  
        'host': ip,
        'username': username,
        'password': password,
        'secret': secret,  
        'timeout': 60,             
        'session_timeout': 120,    
        'global_delay_factor': 6,  
        'fast_cli': False
    }
        
    print(f"📡 [觸發備份] 正在連線 {ip} (驅動通道: {netmiko_type}) ...")

    net_connect = None
    try:
        # 🛡️ 智慧降級相容機制：對付 D-Link 提示字元為 '>' 的老舊機型
        try:
            net_connect = ConnectHandler(**device_params)
        except Exception as conn_e:
            if 'dlink' in netmiko_type and ('Pattern not detected' in str(conn_e) or 'timeout' in str(conn_e).lower()):
                fallback_type = 'dlink_ds_telnet' if 'telnet' in netmiko_type else 'dlink_ds'
                print(f"    [!] 偵測到 D-Link 提示字元為 '>', 自動切換為正宗舊型相容驅動 ({fallback_type})...")
                device_params['device_type'] = fallback_type
                net_connect = ConnectHandler(**device_params)
                is_old_dlink = True
            else:
                raise conn_e
        
        print(f"🔓 [連線成功] 順利進入設備！本機接收 IP: {local_tftp_ip}")
        
        if secret:
            try:
                net_connect.enable()
                print("    [🔓 特權提權成功] 已進入特權模式 (#)！")
            except: pass
        
        # 清除登入可能殘留的畫面字元
        net_connect.read_channel()

        if "cisco" in device_type:
            cmd = f"copy running-config tftp://{local_tftp_ip}/{filename}"
            print(f"    [+] 送出 Cisco 指令: {cmd}")
            out = net_connect.send_command_timing(cmd, delay_factor=1)
            out += net_connect.send_command_timing("\n", delay_factor=1)
            out += net_connect.send_command_timing("\n", delay_factor=1)
            
        elif "aruba_aoscx" in device_type or "aruba_cx" in device_type:
            cmd = f"copy running-config tftp://{local_tftp_ip}/{filename} cli"
            print(f"    [+] 送出 CX 指令: {cmd}")
            out = net_connect.send_command_timing(cmd, delay_factor=2)
            if "vrf" in out.lower() or "continue" in out.lower():
                out += net_connect.send_command_timing("\n", delay_factor=1)
                
        elif "paloalto" in device_type or "pan" in device_type:
            cmd = "show config running"
            print(f"    [+] 送出 Palo Alto 指令: {cmd} (改由直接擷取終端機畫面，不走 TFTP)")
            out = net_connect.send_command(cmd, read_timeout=120)
            print(f"    [>] Palo Alto 設定檔擷取完成，資料長度: {len(out)} bytes")
            if len(out) > 100:
                save_config_to_db(ip, device_type, out, "success")
                print(f"✅ [備份完成] {ip} 已透過 CLI 直讀模式，將設定檔完美寫入資料庫！")
                return True
            else:
                print(f"❌ [擷取失敗] {ip} 擷取到的資料過短。")
                save_config_to_db(ip, device_type, "Error: Config data too short", "fail")
                return False
            
        # =========================================================================
        # 🌟 乾淨重構版：D-Link 舊型 (dlink_old) 與 新型 (1250/1510) 獨立雙通道
        # =========================================================================
        elif "dlink" in device_type or device_type == "dlink_old":
            if is_completely_old_dlink:
                # -------------------------------------------------------------
                # 🛑 模式 A：純淨獨立通道 —— 專治 DGS-1210 老舊二進位檔案機型 (.bin)
                # -------------------------------------------------------------
                bin_filename = filename.replace(".cfg", ".bin")
                
                cmd_1210_v1 = f"upload cfg_toTFTP tftp://{local_tftp_ip}/{bin_filename}"
                print(f"    [+] [D-Link老舊通道] 嘗試語法一: {cmd_1210_v1}")
                net_connect.write_channel(cmd_1210_v1 + "\n")
                time.sleep(2)
                out = net_connect.read_channel()
                
                if "Invalid input" in out or "^" in out or "ERROR" in out or "Incomplete" in out:
                    print(f"    [!] 語法一無效，嘗試語法二...")
                    net_connect.write_channel("\n"); time.sleep(1); net_connect.read_channel()
                    
                    cmd_1210_v2 = f"upload cfg_toTFTP {local_tftp_ip} {bin_filename}"
                    print(f"    [+] [D-Link老舊通道] 嘗試語法二: {cmd_1210_v2}")
                    net_connect.write_channel(cmd_1210_v2 + "\n")
                    time.sleep(2)
                    out = net_connect.read_channel()
                    
                    if "Invalid input" in out or "^" in out or "ERROR" in out or "Incomplete" in out:
                        print(f"    [!] 語法二無效，嘗試語法三...")
                        net_connect.write_channel("\n"); time.sleep(1); net_connect.read_channel()
                        
                        cmd_1210_v3 = f"upload cfg_toTFTP {local_tftp_ip} {bin_filename} config_id 1"
                        print(f"    [+] [D-Link老舊通道] 嘗試語法三: {cmd_1210_v3}")
                        net_connect.write_channel(cmd_1210_v3 + "\n")
                        time.sleep(2)
                        out = net_connect.read_channel()
                    
                print(f"    [>] D-Link 老舊機型 TFTP 指令已送出，回覆摘要: {out.strip()[:100]}")
                print(f"✅ [前台結案] {ip} (DGS-1210老機器) 已成功透過裸通道派發，直接交由背景接球！")
                return True
                
            else:
                # -------------------------------------------------------------
                # 🚀 模式 B：標準通道 —— 針對新世代文字檔機型 (1250 / 1510) 與 AP控制器
                # -------------------------------------------------------------
                # 補回 D-Link 1250/1510 嚴格要求的空格語法
                cmd_1250 = f"copy running-config tftp: //{local_tftp_ip}/{filename}"
                print(f"    [+] 送出 D-Link 新世代 (1250/1510) 標準指令: {cmd_1250}")
                
                net_connect.write_channel(cmd_1250 + "\n")
                time.sleep(2)
                out = net_connect.read_channel()
                print(f"    [>] 設備初步回覆: {out.strip()}")
                
                # 🔍 判斷是否為 DWS-3160 等打槍 copy 語法的 AP 控制器
                if "Next possible completions" in out or "Invalid input" in out or "Unrecognized command" in out:
                    print(f"    [!] 1250/1510 語法被拒絕，自動切換為 DWS AP 控制器專屬 TFTP 語法...")
                    net_connect.write_channel("\n"); time.sleep(1); net_connect.read_channel()
                    
                    cmd_dws = f"upload cfg_toTFTP {local_tftp_ip} dest_file {filename}"
                    print(f"    [+] 送出 DWS AP 控制器指令: {cmd_dws}")
                    net_connect.write_channel(cmd_dws + "\n")
                    time.sleep(4)  # 多留一些時間給 Connecting... Done. 跑完
                    out_dws = net_connect.read_channel()
                    print(f"    [>] DWS 設備回覆: {out_dws.strip()}")
                    
                    if "Invalid input" in out_dws or "Unknown command" in out_dws or "Next possible" in out_dws:
                        print(f"    [!] 所有 TFTP 語法皆不適用，啟動 CLI 純文字暴力直讀備用方案...")
                        net_connect.write_channel("\n"); time.sleep(1); net_connect.read_channel()
                        net_connect.write_channel("disable clipaging\n"); time.sleep(1)
                        net_connect.write_channel("terminal length 0\n"); time.sleep(1)
                        net_connect.read_channel()
                        
                        print(f"    [+] 執行直讀擷取: show running-config")
                        net_connect.write_channel("show running-config\n")
                        time.sleep(3)
                        text_out = ""
                        idle_count = 0
                        while idle_count < 15:
                            data = net_connect.read_channel()
                            if data:
                                text_out += data; idle_count = 0
                                if any(x in data for x in ["Next Page", "a All", "Quit:"]): net_connect.write_channel("a")
                                elif any(x in data for x in ["More:", "--More--"]): net_connect.write_channel(" ")
                            else:
                                idle_count += 1; time.sleep(1)
                                
                        if len(text_out) > 100:
                            save_config_to_db(ip, device_type, text_out, "success")
                            print(f"✅ [備份完成] {ip} 已透過無干擾純文字模式成功存入資料庫！")
                            return True
                        else:
                            save_config_to_db(ip, device_type, "Error: Config too short", "fail")
                            return False
                    else:
                        print(f"✅ [前台結案] DWS AP控制器指令執行成功，交由背景接球！")
                        return True
                        
                else:
                    # 雙 Enter 問答與完全退場
                    time.sleep(1)
                    if "host" in out.lower() or "address" in out.lower() or "?" in out:
                        print(f"    [+] 偵測到 IP 確認詢問，手動回覆 Enter")
                        net_connect.write_channel("\n")
                        time.sleep(1)
                        out = net_connect.read_channel()
                        
                    if "file" in out.lower() or "destination" in out.lower() or "?" in out:
                        print(f"    [+] 偵測到檔名確認詢問，手動回覆 Enter")
                        net_connect.write_channel("\n")
                        time.sleep(1)
                        out = net_connect.read_channel()
                        
                    print(f"✅ [前台結案] {ip} (D-Link 1250/1510) 問答完成，順利進入背景 TFTP 傳輸。")
                    return True
            
        elif "fortinet" in device_type:
            cmd = "show full-configuration"
            print(f"    [+] 送出 Fortinet 指令: {cmd} (改由直接擷取終端機畫面，不走 TFTP)")
            out = net_connect.send_command(cmd, read_timeout=120)
            print(f"    [>] Fortinet 設定檔擷取完成，資料長度: {len(out)} bytes")
            if len(out) > 100:
                save_config_to_db(ip, device_type, out, "success")
                print(f"✅ [備份完成] {ip} 已透過 CLI 直讀模式，將設定檔完美寫入資料庫！")
                return True
            else:
                print(f"❌ [擷取失敗] {ip} 擷取到的資料過短，可能權限不足或發生錯誤。")
                save_config_to_db(ip, device_type, "Error: Config data too short or empty", "fail")
                return False
        
        elif "mikrotik" in device_type or "routeros" in device_type:
            cmd = "/export"
            print(f"    [+] 送出 MikroTik 指令: {cmd} (改由直接擷取終端機畫面，不走 TFTP)")
            out = net_connect.send_command(cmd, read_timeout=120)
            print(f"    [>] MikroTik 設定檔擷取完成，資料長度: {len(out)} bytes")
            if len(out) > 50:
                save_config_to_db(ip, device_type, out, "success")
                print(f"✅ [備份完成] {ip} 已透過 CLI 直讀模式，將設定檔完美寫入資料庫！")
                return True
            else:
                print(f"❌ [擷取失敗] {ip} 擷取到的資料過短。")
                save_config_to_db(ip, device_type, "Error: Config data too short or empty", "fail")
                return False

        elif "dell" in device_type:
            cmd = f"copy running-config tftp://{local_tftp_ip}/{filename} include-plaintext"
            print(f"    [+] 送出 Dell 指令: {cmd}")
            out = net_connect.send_command_timing(cmd, delay_factor=2)
            if "y/n" in out.lower() or "proceed" in out.lower() or "sure" in out.lower():
                out += net_connect.send_command_timing("y\n", delay_factor=2)
            elif "?" in out:
                out += net_connect.send_command_timing("\n", delay_factor=2)
            print(f"    [>] Dell 回覆內容: {out.strip()}")
            
        else:
            cmd = f"copy running-config tftp {local_tftp_ip} {filename}"
            print(f"    [+] 送出 Ruckus/通用 指令: {cmd}")
            out = net_connect.send_command_timing(cmd, delay_factor=2)
            print(f"    [>] 設備回覆: {out.strip()}")

        print(f"✅ [指令完成] {ip} 等待背景 UDP 69 接收中...")
        return True
        
    except Exception as e:
        print(f"❌ [連線或執行失敗]: {e}")
        save_config_to_db(ip, device_type, f"Error: {str(e)}", "fail")
        return False
    finally:
        if net_connect:
            try: net_connect.disconnect()
            except: pass
            
