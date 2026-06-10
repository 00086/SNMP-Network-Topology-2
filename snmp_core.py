import time
import json
import re
import asyncio
import os
import zipfile
import signal
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool  # 🌟 加入這行專屬的崩潰攔截器
#from concurrent.futures import ThreadPoolExecutor  # 🌟 換成 ThreadPoolExecutor

# 🌟 宣告全域除錯模式開關 (預設關閉 False，開啟為 True)
GLOBAL_DEBUG_MODE = False
GLOBAL_TRAP_ENABLED = True  # 🌟 新增：全域 UDP 162 Trap 接收服務控制開關 (預設開啟)

# ==========================================
# ⚙️ 全域監控與快取配置控制項
# ==========================================
DEBUG_SSH_LOG = False       # 💡 設為 True 則會在終端機狂噴 SSH 爬蟲紀錄；設為 False 則保持無聲乾淨
DEBUG_PA_LOG = True         # 💡 新增：Palo Alto API 終端機全面偵錯開關 (預設開啟)

ARUBA_SSH_CACHE = {}        # 💡 Aruba CX 光纖數據記憶快取庫，防止背景輪詢填零覆蓋
PALO_ALTO_CACHE = {}        # 💡 新增：Palo Alto 光纖數據 API 記憶快取庫

def debug_print(message):
    """安全除錯印出函式：只有在開關開啟時才會在終端機輸出"""
    global GLOBAL_DEBUG_MODE
    if GLOBAL_DEBUG_MODE:
        print(message, flush=True)

def _init_child_process():
    """ 防止子進程洗版 """
    signal.signal(signal.SIGINT, signal.SIG_IGN)

try:
    from pysnmp.hlapi.v3arch.asyncio import (
        SnmpEngine as AsyncSnmpEngine, CommunityData as AsyncCommunityData, 
        UdpTransportTarget as AsyncUdpTransportTarget, ContextData as AsyncContextData,
        ObjectType as AsyncObjectType, ObjectIdentity as AsyncObjectIdentity, 
        get_cmd, bulk_cmd, next_cmd
    )
    HAS_PYSNMP = True
except ImportError as e:
    HAS_PYSNMP = False
    print(f"⚠️ snmp_core 模組載入 pysnmp 失敗: {e}")

from utils import (
    log_info, safe_int, is_valid_ipv4, extract_brand_model, 
    parse_snmp_val, check_ping, try_acquire_scan, release_scan, send_ntfy_alert
)
from database import (
    DB_LOCKS, DB_WARM, DB_COLD, DB_AUDIT_WARM, DB_AUDIT_COLD, 
    get_db, read_db_devices, write_db_devices
)

# ==========================================
# 🧱 1. 多進程獨立執行單元 (Fail-Fast 快速止損版)
# ==========================================
def _process_snmp_single_device(ip, community, brand, is_poe=0, has_sensor=0, debug_mode=False):
    import asyncio
    import subprocess
    import platform
    import sys
    import re
    
    # 🌟 核心修正：接收主進程傳入的開關狀態，並同步給子進程的全域空間
    global GLOBAL_DEBUG_MODE
    GLOBAL_DEBUG_MODE = debug_mode
    
    from pysnmp.hlapi.v3arch.asyncio import (
        SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
        ObjectType, ObjectIdentity, bulk_cmd, next_cmd
    )
    from utils import parse_snmp_val

    def _fast_ping(target_ip):
        try:
            if platform.system().lower() == 'windows':
                res = subprocess.run(['ping', '-n', '1', '-w', '500', target_ip], capture_output=True, text=True, timeout=1.5, creationflags=0x08000000)
                return "TTL=" in res.stdout.upper()
            else:
                res = subprocess.run(['ping', '-c', '1', '-W', '1', target_ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1.5)
                return res.returncode == 0
        except:
            return False
    
    def extract_float(val):
        try:
            m = re.search(r'[-+]?\d*\.\d+|\d+', str(val))
            return float(m.group()) if m else 0.0
        except: return 0.0

    def ext_num(val):
        try:
            m = re.search(r'[-+]?\d*\.\d+|\d+', str(val))
            return float(m.group()) if m else 0.0
        except: return 0.0
    
    # 💡 終極防護防禦：起手式直接把 poe_w、temp_c 以及 admin/oper_status 初始化！
    out_dict = {"ip": ip, "in": {}, "out": {}, "cpu": 0.0, "mem": 0.0, "poe_w": 0.0, "temp_c": 0.0, "success": False, "ping_ok": False, "admin_status": {}, "oper_status": {}}

    async def run_snmp_task():
        try:
            engine = SnmpEngine()
            auth = CommunityData(community, mpModel=1)
            ctx = ContextData()
            b = str(brand).lower()
            is_dlink = 'd-link' in b

            async def async_walk(oid_prefix, force_next=False):
                if not oid_prefix: return {}
                results = {}
                try:
                    if force_next:
                        t_timeout = 1.5 if is_dlink else 1.0  
                        max_steps = 32                        
                        t_retries = 1                         
                    else:
                        t_timeout = 2.0 if is_dlink else 1.2
                        max_steps = 50
                        t_retries = 1

                    transport = await UdpTransportTarget.create((ip, 161), timeout=t_timeout, retries=t_retries)
                    current_oid = ObjectType(ObjectIdentity(oid_prefix))
                    
                    for _ in range(max_steps):
                        if force_next:
                            err, stat, idx, binds = await next_cmd(engine, auth, transport, ctx, current_oid)
                        else:
                            err, stat, idx, binds = await bulk_cmd(engine, auth, transport, ctx, 0, 15, current_oid)
                                                        
                        if err or stat or not binds: break
                        out_of_tree = False
                        for row in binds:
                            name, val = row[0] if isinstance(row, list) else row
                            oid_str = str(name)
                            if not oid_str.startswith(oid_prefix): out_of_tree = True; break
                            val_str = parse_snmp_val(val)
                            if val_str: results[oid_str.replace(oid_prefix + '.', '')] = val_str
                            current_oid = ObjectType(ObjectIdentity(name))
                        if out_of_tree: break
                except: pass
                return results

            # ========================================================
            # 💡 全面回歸循序快速採集 (Sequential Await)
            # ========================================================
            res_map = {}
            res_map["in"] = await async_walk('1.3.6.1.2.1.31.1.1.1.6')
            res_map["out"] = await async_walk('1.3.6.1.2.1.31.1.1.1.10')
            
            # 🌟 新增：快速輪詢順便索要網孔實體開關狀態與連線狀態
            res_map["admin_status"] = await async_walk('1.3.6.1.2.1.2.2.1.7')  # ifAdminStatus
            res_map["oper_status"] = await async_walk('1.3.6.1.2.1.2.2.1.8')   # ifOperStatus
            
            out_dict["in"] = res_map.get("in", {})
            out_dict["out"] = res_map.get("out", {})
            if not out_dict["in"] and not out_dict["out"]:
                alive_check = await async_walk('1.3.6.1.2.1.1.2')
                if not alive_check:
                    engine.close_dispatcher()
                    return 
            out_dict["success"] = True

            res_map["cpu_std"] = await async_walk('1.3.6.1.2.1.25.3.3.1.2')
            res_map["mem_size"] = await async_walk('1.3.6.1.2.1.25.2.3.1.5')
            res_map["mem_used"] = await async_walk('1.3.6.1.2.1.25.2.3.1.6')

            if 'ruckus' in b or 'foundry' in b:
                res_map["cpu_brand"] = await async_walk('1.3.6.1.4.1.1991.1.1.2.1.52')
                res_map["mem_brand"] = await async_walk('1.3.6.1.4.1.1991.1.1.2.1.53')
            elif 'cisco' in b:
                res_map["cpu_brand"] = await async_walk('1.3.6.1.4.1.9.9.109.1.1.1.1.7')

            if is_poe:
                res_map["poe_std_mw"] = await async_walk('1.3.6.1.2.1.105.1.3.1.1.4')
                if 'ruckus' in b or 'foundry' in b: 
                    res_map["poe_brand"] = await async_walk('1.3.6.1.4.1.1991.1.1.2.14.2.2.1.6')
                if is_dlink: 
                    res_map["poe_brand"] = await async_walk('1.3.6.1.4.1.171.10.76.12.22.1.1.9', force_next=True)

            if has_sensor:
                res_map["temp_std"] = await async_walk('1.3.6.1.2.1.99.1.1.1')
                if 'ruckus' in b or 'foundry' in b: 
                    res_map["temp_brand"] = await async_walk('1.3.6.1.4.1.1991.1.1.2.13.1.1.4')
                if 'cisco' in b: 
                    res_map["temp_brand"] = await async_walk('1.3.6.1.4.1.9.9.13.1.3.1.3')
                if 'mikrotik' in b: 
                    res_map["temp_brand"] = await async_walk('1.3.6.1.4.1.14988.1.1.3')

            # ========================================================
            # 📊 數據解算
            # ========================================================
            cpu_vals = []
            if "cpu_brand" in res_map and res_map["cpu_brand"]:
                cpu_vals = [float(v) for v in res_map["cpu_brand"].values() if str(v).replace('.','').isdigit()]
            if not cpu_vals and "cpu_std" in res_map and res_map["cpu_std"]:
                cpu_vals = [float(v) for v in res_map["cpu_std"].values() if str(v).replace('.','').isdigit()]
            if cpu_vals: out_dict["cpu"] = round(sum(cpu_vals)/len(cpu_vals), 1)

            mem_val = 0.0
            if "mem_brand" in res_map and res_map["mem_brand"]:
                try: mem_val = float(list(res_map["mem_brand"].values())[0])
                except: pass
            if mem_val == 0.0:
                sizes = res_map.get("mem_size", {})
                useds = res_map.get("mem_used", {})
                for idx, sz in sizes.items():
                    if idx in useds and float(sz) > 0:
                        mem_val = (float(useds[idx]) / float(sz)) * 100; break
            out_dict["mem"] = round(mem_val, 1)
            
            poe_w = 0.0
            if is_poe:
                sum_mw = 0
                if "poe_std_mw" in res_map and res_map["poe_std_mw"]:
                    for v in res_map["poe_std_mw"].values():
                        val = extract_float(v)
                        if 500 <= val < 95000 and val != 1500: sum_mw += val
                        elif 0.5 <= val < 500: poe_w += val
                
                if "poe_brand" in res_map and res_map["poe_brand"] and ('ruckus' in b or 'foundry' in b):
                    for v in res_map["poe_brand"].values():
                        val = extract_float(v)
                        if 500 <= val < 95000: sum_mw += val
                        elif 0.5 <= val < 500: poe_w += val
                            
                poe_w += sum_mw / 1000.0
                
                if "poe_brand" in res_map and res_map["poe_brand"] and is_dlink:
                    for v in res_map["poe_brand"].values():
                        val = extract_float(v)
                        if val > 500:          
                            poe_w += val / 1000.0
                        elif val > 95.0:       
                            poe_w += val / 10.0
                        elif 0.1 <= val <= 95.0: 
                            poe_w += val
                        
            out_dict["poe_w"] = round(poe_w, 1)

            temp_c = 0.0
            if has_sensor:
                temps = []
                if "temp_std" in res_map and res_map["temp_std"]:
                    for v in res_map["temp_std"].values():
                        t = extract_float(v)
                        if 0 < t < 150: temps.append(t)
                if "temp_brand" in res_map and res_map["temp_brand"]:
                    if 'ruckus' in b or 'foundry' in b:
                        for v in res_map["temp_brand"].values():
                            t = extract_float(v) / 2.0
                            if 0 < t < 150: temps.append(t)
                    elif 'cisco' in b:
                        for v in res_map["temp_brand"].values():
                            t = extract_float(v)
                            if 0 < t < 150: temps.append(t)
                    elif 'mikrotik' in b:
                        for k, v in res_map["temp_brand"].items():
                            if str(k).endswith('.10') or str(k) == '10':
                                t = extract_float(v) / 10.0
                                if 0 < t < 150: temps.append(t)
                if temps: temp_c = round(max(temps), 1)
            out_dict["temp_c"] = temp_c

            # 🌟 補上這兩行賦值，將快速輪詢抓到的實體狀態塞進回傳物件中
            out_dict["admin_status"] = res_map.get("admin_status", {})
            out_dict["oper_status"] = res_map.get("oper_status", {})

            engine.close_dispatcher()
        except: pass

    debug_print(f"👉 [流量輪詢] 子進程開始處理 IP: {ip} ...")
    try:
        import asyncio
        loop = asyncio.new_event_loop()
        loop.set_exception_handler(lambda loop, context: None) 
        asyncio.set_event_loop(loop)
        
        loop.run_until_complete(asyncio.wait_for(run_snmp_task(), timeout=12.0))
        loop.close()
        debug_print(f"✅ [流量輪詢] 子進程成功完成 IP: {ip}")
    except Exception as e: 
        debug_print(f"❌ [流量輪詢] 子進程卡死或逾時！強制中斷 IP: {ip} (原因: {type(e).__name__})")
        pass

    if not out_dict["success"]:
        out_dict["ping_ok"] = _fast_ping(ip)
    
    return out_dict

# ==========================================
# 📊 2. 異步單點採集單元
# ==========================================
async def async_get_device_info(snmpEngine, ip, community):
    sys_descr, sys_name, sys_location = "無回應", "", ""
    try:
        transport = await AsyncUdpTransportTarget.create((ip, 161), timeout=1.0, retries=1)
        err, stat, idx, varBinds = await get_cmd(
            snmpEngine, AsyncCommunityData(community, mpModel=1), transport, AsyncContextData(), 
            AsyncObjectType(AsyncObjectIdentity('1.3.6.1.2.1.1.1.0')), AsyncObjectType(AsyncObjectIdentity('1.3.6.1.2.1.1.5.0')), AsyncObjectType(AsyncObjectIdentity('1.3.6.1.2.1.1.6.0'))
        )
        if not err and not stat:
            for varBind in varBinds:
                oid = str(varBind[0])
                val = parse_snmp_val(varBind[1]).replace('\r', '').replace('\n', ' | ')
                if '1.3.6.1.2.1.1.1.0' in oid: sys_descr = val
                elif '1.3.6.1.2.1.1.5.0' in oid: sys_name = val
                elif '1.3.6.1.2.1.1.6.0' in oid: sys_location = val
    except: pass
    return sys_descr, sys_name, sys_location

# 💡 將原本的 (snmpEngine, ip, community) 替換為以下這行：
async def async_get_device_full_data(snmpEngine, ip, community, sys_descr="", ssh_user="", ssh_pass=""):
    auth = AsyncCommunityData(community, mpModel=1)
    # 🌟 降低為 1，代表對這台交換器「一次只問一個表」，不要一次發 3 個請求塞爆它，這樣反而會跑得更順、不會當機！
    sem = asyncio.Semaphore(1)
    async def walk(oid_prefix):
        async with sem:
            results = {}
            try:
                transport = await AsyncUdpTransportTarget.create((ip, 161), timeout=2.0, retries=2)
                ctx = AsyncContextData()
                current_oid = AsyncObjectType(AsyncObjectIdentity(oid_prefix))
                for _ in range(150): 
                    err, stat, idx, binds = await bulk_cmd(snmpEngine, auth, transport, ctx, 0, 15, current_oid)
                    if err or stat or not binds: break
                    out_of_tree = False
                    for row in binds:
                        name, val = row[0] if isinstance(row, list) else row
                        oid_str = str(name)
                        if not oid_str.startswith(oid_prefix): out_of_tree = True; break
                        val_str = parse_snmp_val(val)
                        if val_str: results[oid_str.replace(oid_prefix + '.', '')] = val_str
                        current_oid = AsyncObjectType(AsyncObjectIdentity(name))
                    if out_of_tree: break
            except: pass
            return results

    # =====================================================================
    # 📡 啟動非同步多執行緒資料採集 (Asynchronous Bulk Data Polling)
    # 備註：此區塊收集的順序會直接對應到回傳陣列 (res) 的索引值 (0 ~ 34)
    # =====================================================================
    res = await asyncio.gather(
        # --- [區塊 A：LLDP 鄰居網路拓樸發現 (0 ~ 3)] ---
        walk('1.0.8802.1.1.2.1.4.1.1.9'),       # 0: LLDP 鄰居設備名稱 (Rem Sys Name)
        walk('1.0.8802.1.1.2.1.4.1.1.7'),       # 1: LLDP 鄰居連接埠 ID (Rem Port Id)
        walk('1.0.8802.1.1.2.1.4.1.1.6'),       # 2: LLDP 鄰居連接埠描述 (Rem Port Desc)
        walk('1.0.8802.1.1.2.1.4.1.1.8'),       # 3: LLDP 鄰居系統描述 (Rem Sys Desc)
        
        # --- [區塊 B：實體介面基礎資訊 (4 ~ 9)] ---
        walk('1.3.6.1.2.1.31.1.1.1.1'),         # 4: 介面名稱 ifName (如 GigabitEthernet1/0/1)
        walk('1.3.6.1.2.1.31.1.1.1.15'),        # 5: 介面最高速度 ifHighSpeed (單位 Mbps)
        walk('1.3.6.1.2.1.2.2.1.5'),            # 6: 介面基礎速度 ifSpeed (舊版 OID，單位 bps)
        walk('1.3.6.1.2.1.2.2.1.6'),            # 7: 介面硬體 MAC 位址 ifPhysAddress
        walk('1.3.6.1.2.1.2.2.1.2'),            # 8: 介面描述 ifDescr (通常同 ifName)
        walk('1.3.6.1.2.1.31.1.1.1.18'),        # 9: 介面自訂別名 ifAlias (管理員填寫的說明)
        
        # --- [區塊 C：終端設備尋址 - MAC / ARP 表 (10 ~ 17)] ---
        walk('1.3.6.1.2.1.17.4.3.1.2'),         # 10: Bridge MIB - 轉發資料庫 (FDB / MAC Address Table)
        walk('1.3.6.1.2.1.17.1.4.1.2'),         # 11: Bridge MIB - 橋接埠與 ifIndex 映射表
        walk('1.3.6.1.2.1.17.7.1.2.2.1.2'),     # 12: Q-BRIDGE MIB - 包含 VLAN 標籤的 MAC 轉發資料庫
        walk('1.3.6.1.2.1.4.22.1.2'),           # 13: 傳統 IPv4 ARP 快取表 (IP 對應 MAC)
        walk('1.3.6.1.2.1.4.35.1.4'),           # 14: 新版 IP 網路層實體位址表 (支援 IPv6)
        walk('1.3.6.1.2.1.3.1.1.2'),            # 15: 舊版位址轉換表 (部分老舊設備需要)
        walk('1.3.6.1.4.1.1991.1.1.2.1.35.1.3'),# 16: Ruckus/Foundry 專用 ARP 對應埠口表
        walk('1.3.6.1.2.1.4.21.1.7'),           # 17: IPv4 路由表下一跳位址 (ipRouteNextHop)
        
        # --- [區塊 D：硬體特規與 PoE 供電感測 (18 ~ 21)] ---
        walk('1.3.6.1.2.1.105.1.3.1.1.4'),      # 18: PoE 埠口供電等級 (Power Class 0~4)
        walk('1.3.6.1.4.1.1991.1.1.2.14.2.2.1.6'), # 19: Ruckus/Foundry LLDP 鄰居 IP 解析 (特規)
        walk('1.3.6.1.4.1.9.9.402.1.2.1.7'),    # 20: Cisco PoE 實時瓦數消耗 (cpeExtPsePortPwrConsumption)
        walk('1.3.6.1.4.1.171.10.76.12.22.1.1.9'), # 21: D-Link PoE 實時瓦數消耗 (特規)
        
        # --- [區塊 E：設備狀態與網路錯誤封包品質 (22 ~ 25)] ---
        walk('1.3.6.1.2.1.1.3'),                # 22: 系統連續運行時間 (sysUpTime)
        walk('1.3.6.1.2.1.2.2.1.14'),           # 23: 介面接收錯誤封包數 (ifInErrors) - 查修線路關鍵
        walk('1.3.6.1.2.1.2.2.1.20'),           # 24: 介面發送錯誤封包數 (ifOutErrors)
        walk('1.3.6.1.2.1.105.1.3.1.1.2'),      # 25: PoE 埠口供電偵測狀態 (On/Off/Searching)
        
        # --- [區塊 F：資源監控 (CPU/RAM/溫度) (26 ~ 31)] ---
        walk('1.3.6.1.4.1.1991.1.1.2.13.1.1.4'),# 26: Ruckus/Foundry 溫度感測器
        walk('1.3.6.1.4.1.1991.1.1.2.2.1.1.2'), # 27: Ruckus/Foundry CPU 使用率
        walk('1.3.6.1.4.1.1991.1.1.2.3.1.1.3'), # 28: Ruckus/Foundry 記憶體使用率
        walk('1.3.6.1.4.1.9.9.13.1.3.1.3'),     # 29: Cisco 溫度感測器
        walk('1.3.6.1.4.1.14988.1.1.3'),        # 30: MikroTik 硬體監控 (溫度/電壓)
        walk('1.3.6.1.2.1.99.1.1.1'),           # 31: 通用實體感測器 MIB (支援多廠牌溫度/風扇)
        
        # --- [區塊 G：進階診斷 - 網孔管理與光學模組 (32 ~ 34)] ---
        walk('1.3.6.1.2.1.2.2.1.7'),            # 32: ifAdminStatus (管理員狀態 - 區分正常斷線與強制 Shutdown)
        walk('1.3.6.1.4.1.1991.1.1.3.3.6.1.4'), # 33: Ruckus DOM Tx Power (光纖模組發送功率，單位 µW)
        walk('1.3.6.1.4.1.1991.1.1.3.3.6.1.5'), # 34: Ruckus DOM Rx Power (光纖模組接收功率，單位 µW)
        
        # --- [區塊 H：多廠牌光纖 DOM (舊 HP / 實體關聯 / 新 Aruba CX) (35 ~ 39)] ---
        walk('1.3.6.1.4.1.11.2.14.11.5.1.122.1.1.2'), # 35: 舊版 HP/Aruba 專屬 Tx Power
        walk('1.3.6.1.4.1.11.2.14.11.5.1.122.1.1.3'), # 36: 舊版 HP/Aruba 專屬 Rx Power
        walk('1.3.6.1.2.1.47.1.1.1.1.7'),             # 37: ENTITY-MIB 實體設備名稱 (通用多廠牌 DOM 識別)
        walk('1.3.6.1.4.1.47196.4.1.1.3.38.1.1.9'),   # 38: 新版 Aruba CX 專屬 Tx Power (千分之一 dBm 或 µW)
        walk('1.3.6.1.4.1.47196.4.1.1.3.38.1.1.10'),  # 39: 新版 Aruba CX 專屬 Rx Power
        
        # 💡 挖寶發現：Ruckus ICX 真實光學 OID (回傳格式如 "-001.8428 dBm Normal")
        walk('1.3.6.1.4.1.1991.1.1.3.3.10.1.3'),      # 40: Ruckus ICX 實際 Tx 字串
        walk('1.3.6.1.4.1.1991.1.1.3.3.10.1.4')       # 41: Ruckus ICX 實際 Rx 字串
    )
    
    # 💡 由於陣列擴充到了 42 個元素(0~41)，SSH 備援資料現在會被塞到第 [42] 號索引
    # 💡 核心修正：加入記憶快取保護防線！
    if ("CX8100" in sys_descr or "AOS-CX" in sys_descr):
        if ssh_user and ssh_pass:
            # A. 使用者有提供帳密（點擊獨立掃描），呼叫實體爬蟲抓取最新資料
            loop = asyncio.get_event_loop()
            ssh_data = await loop.run_in_executor(None, _sync_aruba_ssh, ip, ssh_user, ssh_pass)
            
            if ssh_data:
                # 抓取成功，立刻寫入全域記憶庫中
                ARUBA_SSH_CACHE[ip] = ssh_data
            res.append(ssh_data)
        else:
            # B. 背景輪詢（沒給帳密），自動從快取庫取出上一次成功抓到的資料送回前端，拒絕填空！
            cached_data = ARUBA_SSH_CACHE.get(ip, {})
            if DEBUG_SSH_LOG and cached_data:
                print(f"📦 [快取機制] 偵測到背景輪詢，已自動為 Aruba ({ip}) 指派歷史光纖快取資料。")
            res.append(cached_data)
    else:
        # 非 Aruba 設備，直接補空字典
        res.append({})

    # 💡 安全優化：將描述全部轉小寫比對，徹底消除大小寫不對稱的黑箱陷阱
    # 💡 Palo Alto 專屬 SSH 攔截防線
    sys_descr_lower = sys_descr.lower() if sys_descr else ""
    
    if "palo alto" in sys_descr_lower or "pan-os" in sys_descr_lower or "pa-" in sys_descr_lower or (ssh_pass and sys_descr_lower == "無回應"):
        # 💡 已經改回走 SSH 路線，所以需要驗證帳號和密碼
        if ssh_user and ssh_pass:
            loop = asyncio.get_event_loop()
            # 呼叫剛寫好的 SSH 引擎
            pa_data = await loop.run_in_executor(None, _sync_palo_alto_ssh, ip, ssh_user, ssh_pass)
            if pa_data:
                PALO_ALTO_CACHE[ip] = pa_data
            res.append(pa_data)
        else:
            # 背景輪詢沒給帳密時，沿用快取記憶
            res.append(PALO_ALTO_CACHE.get(ip, {}))
        
    return res

# ==========================================
# ⚡ 3. 核心背景引擎守護行程 (狀態異動感知進階版)
# ==========================================
def traffic_polling_worker():
    # 💡 確保匯入 write_audit_log 寫入引擎
    from database import get_db, DB_LOCKS, write_audit_log 
    
    log_info("📊 [多核心並行輪詢] 效能與流量多進程並行輪詢已啟動！")
    time.sleep(3)
    
    # 動態自動補齊資料庫的告警狀態欄位 (防止舊 config.db 報錯)
    try:
        with DB_LOCKS['config']:
            conn = get_db('config')
            conn.execute("ALTER TABLE devices ADD COLUMN alert_count INTEGER DEFAULT 0;")
            conn.execute("ALTER TABLE devices ADD COLUMN last_alert_time TEXT DEFAULT '';")
            conn.commit(); conn.close()
    except: pass

    last_poll_time = 0
    
    # 🌟 復原：讓 32 核心進程池「常駐」在記憶體，省下每次開機的 7 秒成本！
    executor = ProcessPoolExecutor(max_workers=16, initializer=_init_child_process)
    
    # 🌟 換成多執行緒池！因為執行緒共享主記憶體，不需要再用 initializer 去攔截中斷訊號了
    # executor = ThreadPoolExecutor(max_workers=16)
    
    device_alert_debounce = {}  
    cpu_alert_debounce = {}     

    while True:
        try:
            conn = get_db('config')
            row = conn.execute("SELECT value FROM system_settings WHERE key='polling_interval'").fetchone()
            conn.close()
            interval_mins = safe_int(row['value'], 3) if row else 3

            if time.time() - last_poll_time >= interval_mins * 60:
                last_poll_time = time.time()
                cycle_start_time = time.time()

                all_devs = read_db_devices()
                active_devs = [d for d in all_devs if d.get('visible', 1) == 1]
                now_str = time.strftime('%Y-%m-%d %H:%M:%S')

                futures = {}
                
                # 🌟 關鍵：每次輪詢都在這裡建立一個全新的 16 核心拋棄式進程池
                #with ProcessPoolExecutor(max_workers=16, initializer=_init_child_process) as executor:
                # 🌟 關鍵修改：直接換成 try: (下方的 for 迴圈與所有邏輯，縮排完全不用動！)
                try:
                    # ⬇️ ============ 以下所有程式碼都往右縮排了一格 (4 個空白) ============ ⬇️
                    for d in active_devs:
                        future = executor.submit(
                            _process_snmp_single_device, 
                            d['ip'], 
                            d['community'], 
                            d.get('brand', 'Unknown'), 
                            safe_int(d.get('is_poe', 0)), 
                            safe_int(d.get('has_sensor', 0)),
                            GLOBAL_DEBUG_MODE
                        )
                        futures[future] = d

                    traffic_records, dev_table_updates, metrics_history_records, status_updates = [], [], [], []
                    success_count = 0

                    for future in futures:
                        res = future.result()
                        dev = futures[future]
                        ip = res["ip"]
                        name = dev.get('name') or ip
                        old_status = dev.get('status', 'up')
                        
                        curr_alert_count = safe_int(dev.get('alert_count'), 0)
                        last_alert_time_raw = dev.get('last_alert_time') or ""

                        if res["success"]:
                            success_count += 1
                            device_alert_debounce[ip] = 0
                            
                            raw_str = dev.get('snmp_raw') or "{}"
                            try:
                                import json
                                raw_array = json.loads(raw_str)
                                if isinstance(raw_array, list):
                                    while len(raw_array) < 45:
                                        raw_array.append({})
                                    if res["admin_status"]: raw_array[32] = res["admin_status"]
                                    if res["oper_status"]: raw_array[44] = res["oper_status"]
                                    raw_str = json.dumps(raw_array, ensure_ascii=False)
                            except: pass
                            
                            if old_status != 'up' or curr_alert_count > 0:
                                send_ntfy_alert("設備恢復連線", f"✅ 網路設備 {name} ({ip}) 已經重新恢復連線與 SNMP 回應！", "default", "white_check_mark,green_circle")
                                status_updates.append(('up', 0, '', ip))
                                write_audit_log("SystemEngine", "設備狀態異動", f"{name} ({ip})", "SUCCESS", f"【設備恢復】設備已重新連線並恢復 SNMP 回應 (UP)。")

                            if res["cpu"] > 90.0:
                                cpu_alert_debounce[ip] = cpu_alert_debounce.get(ip, 0) + 1
                                if cpu_alert_debounce[ip] == 2: 
                                    send_ntfy_alert("設備高負載警告", f"⚠️ 網路設備 {name} ({ip}) 的 CPU 負載已達 {res['cpu']} %！", "high", "warning,chart_with_upwards_trend")
                            else:
                                cpu_alert_debounce[ip] = 0

                            for p_idx, in_v in res["in"].items():
                                traffic_records.append((ip, p_idx, safe_int(in_v, 0), safe_int(res["out"].get(p_idx, 0), 0), now_str))
                            
                            dev_table_updates.append((res["cpu"], res["mem"], raw_str, ip))
                            metrics_history_records.append((ip, res["cpu"], res["mem"], res.get("poe_w", 0.0), res.get("temp_c", 0.0), now_str))

                        else:
                            new_status = 'warning' if res["ping_ok"] else 'down'
                            device_alert_debounce[ip] = device_alert_debounce.get(ip, 0) + 1
                            
                            if device_alert_debounce[ip] >= 2:
                                if old_status != new_status or curr_alert_count == 0:
                                    curr_alert_count = 1
                                    if new_status == 'down':
                                        send_ntfy_alert(f"🚨 設備斷線警報 (第1次)", f"網路設備 {name} ({ip}) 失去回應，疑似斷線！", "high", "skull,red_circle")
                                        write_audit_log("SystemEngine", "設備狀態異動", f"{name} ({ip})", "FAILED", f"【設備斷線】連續兩次失去 ICMP/SNMP 回應，判定為徹底斷線 (DOWN)。")
                                    else:
                                        send_ntfy_alert(f"⚠️ SNMP 服務異常 (第1次)", f"設備 {name} ({ip}) Ping 會通但 SNMP 拒絕回應！", "default", "warning,orange_circle")
                                        write_audit_log("SystemEngine", "設備狀態異動", f"{name} ({ip})", "WARNING", f"【服務異常】Ping 測試正常，但連續兩次 SNMP 拒絕回應 (WARNING)。")
                                        
                                    status_updates.append((new_status, curr_alert_count, now_str, ip))
                                
                                else:
                                    time_passed = 999999
                                    if last_alert_time_raw:
                                        try:
                                            t_parsed = time.strptime(last_alert_time_raw, '%Y-%m-%d %H:%M:%S')
                                            time_passed = time.time() - time.mktime(t_parsed)
                                        except: pass
                                    
                                    if time_passed >= 300 and curr_alert_count < 3:
                                        curr_alert_count += 1
                                        if new_status == 'down':
                                            send_ntfy_alert(f"🚨 設備重復斷線警報 (第{curr_alert_count}次)", f"持續斷線中：網路設備 {name} ({ip}) 依然無回應！", "high", "skull,red_circle")
                                        else:
                                            send_ntfy_alert(f"⚠️ SNMP 重復異常 (第{curr_alert_count}次)", f"持續異常中：設備 {name} ({ip}) SNMP 依舊無回應！", "default", "warning,orange_circle")
                                        status_updates.append((new_status, curr_alert_count, now_str, ip))
                                        device_alert_debounce[ip] = 0
                                    
                                    elif curr_alert_count >= 3:
                                        status_updates.append((new_status, curr_alert_count, last_alert_time_raw, ip))
                    # ⬆️ ============ 到這行結束，準備退出 with 區塊 ============ ⬆️
                
                # 🌟 加上這段專屬的「急救包」
                except BrokenProcessPool:
                    log_info("⚠️ [多核心並行輪詢] 偵測到子進程意外崩潰！正在自動重建乾淨的進程池...")
                    executor.shutdown(wait=False)
                    executor = ProcessPoolExecutor(max_workers=16, initializer=_init_child_process)
                    continue  # 跳過本次資料庫寫入，直接進入下一輪
                
                # 🌟 當程式執行到這裡時，進程池會被「自動強制摧毀並回收所有記憶體與殭屍進程」
                # 這裡退回原本的縮排層級，開始將整理好的結果寫入資料庫
                with DB_LOCKS['hot']:
                    conn_hot = get_db('hot')
                    if traffic_records: conn_hot.executemany("INSERT INTO traffic_history (ip, port_idx, in_bytes, out_bytes, timestamp) VALUES (?, ?, ?, ?, ?)", traffic_records)
                    if metrics_history_records: conn_hot.executemany("INSERT INTO metrics_history (ip, cpu, memory, poe_w, temp_c, timestamp) VALUES (?, ?, ?, ?, ?, ?)", metrics_history_records)
                    conn_hot.commit(); conn_hot.close()

                if dev_table_updates or status_updates:
                    with DB_LOCKS['config']:
                        # 💡 修正：宣告加入 conn_conf，完美消滅 NameError 錯誤！
                        conn = conf = conn_conf = get_db('config')
                        if dev_table_updates:
                            conn_conf.executemany("UPDATE devices SET cpu_load=?, mem_load=?, snmp_raw=? WHERE ip=?", dev_table_updates)
                        if status_updates:
                            conn_conf.executemany("UPDATE devices SET status=?, alert_count=?, last_alert_time=? WHERE ip=?", status_updates)
                        conn_conf.commit(); conn_conf.close()
                    try:
                        from database import update_device_metrics_cache, reload_device_cache
                        if dev_table_updates: 
                            # 💡 智慧防護：從 4 欄位中精準抽取 (CPU, RAM, IP) 變成原本預期的 3 欄位格式丟給快取部隊
                            cache_updates = [(x[0], x[1], x[3]) for x in dev_table_updates]
                            update_device_metrics_cache(cache_updates)
                        if status_updates: reload_device_cache()
                    except ImportError: pass

                log_info(f"📊 [多核心並行輪詢] 採集完畢 - 輪詢 {len(active_devs)} 台，成功 {success_count} 台，全網耗時 {round(time.time() - cycle_start_time, 2)} 秒。")
        except Exception as e: log_info(f"⚠️ [多核心並行輪詢] 發生錯誤: {e}")
        time.sleep(5)


# ==========================================
# 🧹 4. 資料生命週期與企業級降採樣引擎
# ==========================================
def data_retention_worker():
    import sqlite3, time
    from database import get_db, DB_LOCKS, DB_WARM, DB_COLD
    from utils import log_info
    
    time.sleep(300) # 剛開機先延遲 5 分鐘
    
    while True:
        try:
            if time.localtime().tm_hour == 2:
                log_info("🧹 [資料清洗] 啟動降採樣引擎：熱庫(1分) ➡️ 溫庫(10分) ➡️ 冷庫(1小時)...")
                
                with DB_LOCKS['hot']:
                    conn = get_db('hot')
                    conn.execute(f"ATTACH DATABASE '{DB_WARM}' AS warm_db")
                    conn.execute(f"ATTACH DATABASE '{DB_COLD}' AS cold_db")
                    
                    # 🗑️ A：【冷庫銷毀】清除超過 3 年 (1095 天) 的極舊資料
                    conn.execute("DELETE FROM cold_db.traffic_history WHERE timestamp < datetime('now', '-1095 days', 'localtime')")
                    conn.execute("DELETE FROM cold_db.metrics_history WHERE timestamp < datetime('now', '-1095 days', 'localtime')")
                    
                    # ❄️ B：【溫 ➡️ 冷】溫庫資料 (>180天) 降採樣為「1小時 1筆」寫入冷庫
                    conn.execute("""
                        INSERT INTO cold_db.traffic_history (ip, port_idx, timestamp, avg_in_bps, max_in_bps, avg_out_bps, max_out_bps)
                        SELECT ip, port_idx, strftime('%Y-%m-%d %H:00:00', timestamp) AS hour_ts,
                               AVG(avg_in_bps), MAX(max_in_bps), AVG(avg_out_bps), MAX(max_out_bps)
                        FROM warm_db.traffic_history
                        WHERE timestamp < datetime('now', '-180 days', 'localtime')
                        GROUP BY ip, port_idx, hour_ts
                    """)
                    conn.execute("""
                        INSERT INTO cold_db.metrics_history (ip, timestamp, cpu, memory, temp_c, poe_w)
                        SELECT ip, strftime('%Y-%m-%d %H:00:00', timestamp) AS hour_ts,
                               AVG(cpu), AVG(memory), AVG(temp_c), AVG(poe_w)
                        FROM warm_db.metrics_history
                        WHERE timestamp < datetime('now', '-180 days', 'localtime')
                        GROUP BY ip, hour_ts
                    """)
                    conn.execute("DELETE FROM warm_db.traffic_history WHERE timestamp < datetime('now', '-180 days', 'localtime')")
                    conn.execute("DELETE FROM warm_db.metrics_history WHERE timestamp < datetime('now', '-180 days', 'localtime')")
                    
                    # ⛅ C：【熱 ➡️ 溫】熱庫資料 (>30天) 計算 BPS 並降採樣為「10分鐘 1筆」
                    conn.execute("""
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
                    conn.execute("""
                        INSERT INTO warm_db.metrics_history (ip, timestamp, cpu, memory, temp_c, poe_w)
                        SELECT ip, datetime((strftime('%s', timestamp) / 600) * 600, 'unixepoch', 'localtime') AS min10_ts,
                               AVG(cpu), AVG(memory), AVG(temp_c), AVG(poe_w)
                        FROM metrics_history
                        WHERE timestamp < datetime('now', '-30 days', 'localtime')
                        GROUP BY ip, min10_ts
                    """)
                    conn.execute("DELETE FROM traffic_history WHERE timestamp < datetime('now', '-30 days', 'localtime')")
                    conn.execute("DELETE FROM metrics_history WHERE timestamp < datetime('now', '-30 days', 'localtime')")
                    
                    conn.commit()
                    conn.execute("DETACH DATABASE warm_db")
                    conn.execute("DETACH DATABASE cold_db")
                    
                log_info("✅ [資料清洗] 企業級降採樣完工！空間已完美釋放。")
                time.sleep(3600) 
        except Exception as e:
            from utils import log_info
            log_info(f"⚠️ [資料清洗] 降採樣引擎發生異常: {e}")
            time.sleep(3600)
        time.sleep(3600)

# ==========================================
# 🌐 5. 拓樸深度掃描
# ==========================================
def topology_scan_worker():
    """背景自動排程拓樸掃描守護行程"""
    from database import get_db, DB_LOCKS
    from utils import log_info
    import time
    
    # 💡 更新日誌：明確告知系統不會立刻掃描
    log_info("🔄 [自動拓樸] 拓樸背景掃描已啟動，將依照系統設定之間隔時間等待首次掃描。")
    
    # 🌟 關鍵修改 1：以「伺服器啟動當下」作為計時起點
    last_scan_time = time.time()
    
    while True:
        try:
            # 讀取排程間隔設定
            with DB_LOCKS['config']:
                conn = get_db('config')
                row = conn.execute("SELECT value FROM system_settings WHERE key='topo_scan_interval'").fetchone()
                conn.close()
            
            # 預設 60 分鐘，如果是 0 就代表使用者手動關閉排程
            interval_mins = int(row['value']) if row and row['value'] else 60
            
            # 🌟 關鍵修改 2：只有當「經過的時間」達到「系統設定的時間」，才允許發動掃描
            if interval_mins > 0 and (time.time() - last_scan_time >= interval_mins * 60):
                # 執行前，重置計時器
                last_scan_time = time.time()
                
                log_info("🔍 [自動拓樸] 時間排程已觸發，開始執行背景全網深度掃描...")
                
                from snmp_core import discover_topology, read_db_devices
                devices = read_db_devices()
                discover_topology(devices)
                
                log_info(f"✅ [自動拓樸] 全網深度掃描完成。下次掃描將在 {interval_mins} 分鐘後執行。")
            
            # 🌟 關鍵修改 3：廢除掃描後進入「長睡」的機制，改為「每 60 秒醒來檢查一次」
            # 這樣不但消滅了 time.sleep(0) 的 CPU 100% 陷阱，還能讓您在網頁端修改設定時，最慢 1 分鐘就生效！
            time.sleep(60)
                
        except Exception as e:
            log_info(f"⚠️ [自動拓樸] 背景掃描發生異常: {e}，強制執行冷卻防護，60 秒後重新檢查。")
            time.sleep(60)

def discover_topology(devices):
    scan_start_time = time.time()
    nodes, edges = [], []
    sysname_to_ip_map = {}
    active_devices = [d for d in devices if d.get('visible', 1) == 1]
    hidden_ips = {d['ip'] for d in devices if d.get('visible', 1) == 0}
    connections = {} 
    device_full_data_cache = {}
    global_mac_to_port = {}

    for dev in devices:
        ip = dev['ip']; lvl = safe_int(dev.get('level'))
        if ip in hidden_ips or not is_valid_ipv4(ip) or lvl >= 5:
            sysname_to_ip_map[dev.get('name', '').split('.')[0].strip().lower()] = ip

    async def fetch_all_topo_data(devs):
        sem = asyncio.Semaphore(20) 
        async def fetch(d):
            async with sem:
                ip = d['ip']
                debug_print(f"👉 [拓樸掃描] 啟動掃描 IP: {ip} ...")
                
                if safe_int(d.get('level')) >= 5:
                    debug_print(f"⏭️ [拓樸掃描] 略過終端設備 IP: {ip}")
                    return d, ("邊緣/終端設備 (系統依設定略過主動掃描)", d.get('name',''), ""), tuple({} for _ in range(44))
                
                # 🌟 包裝成獨立協程，準備掛上超時核彈
                async def do_fetch():
                        engine = AsyncSnmpEngine()
                        info = await async_get_device_info(engine, ip, d['community'])
                        
                        # 💡 智慧識別：如果資料庫裡記載它是 Palo Alto 家族，不論 SNMP 有無回應，都必須放行！
                        brand_str = str(d.get('brand', '')).lower()
                        model_str = str(d.get('model', '')).lower()
                        is_palo_alto = "palo" in brand_str or "pan" in brand_str or "pa-" in model_str
                        
                        # 如果不是波羅阿圖，且 SNMP 沒回應，才執行原本的快速止損
                        if info[0] == "無回應" and not is_palo_alto:
                            engine.close_dispatcher()
                            return d, info, tuple({} for _ in range(44))
                        
                        # 💡 防呆防線：萬一 SNMP 沒回應，我們幫它人工合成一個描述，確保能命中後方的採集引擎
                        passed_sys_descr = info[0] if info[0] != "無回應" else "Palo Alto Networks Firewall (SNMP Backup Mode)"
                        
                        # 完美傳遞金鑰與描述
                        full = await async_get_device_full_data(
                            engine, ip, d['community'], passed_sys_descr,
                            ssh_user=d.get('ssh_user', ''),
                            ssh_pass=d.get('ssh_pass', '')
                        )
                        engine.close_dispatcher()
                        
                        passed_info = info if info[0] != "無回應" else (passed_sys_descr, d.get('name', 'SLPS'), "")
                        return d, passed_info, full

                try:
                    result = await asyncio.wait_for(do_fetch(), timeout=120.0)
                    debug_print(f"✅ [拓樸掃描] 成功完成 IP: {ip}")
                    return result
                except asyncio.TimeoutError:
                    debug_print(f"❌ [拓樸掃描] 嚴重超時卡死！強制中斷 IP: {ip}")
                    return d, ("無回應", "掃描超時", ""), tuple({} for _ in range(44))
                except Exception as e:
                    debug_print(f"⚠️ [拓樸掃描] 發生異常 IP: {ip} - 錯誤: {e}")
                    return d, ("無回應", "掃描異常", ""), tuple({} for _ in range(44))

        return await asyncio.gather(*(fetch(d) for d in devs))

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    fetch_results = loop.run_until_complete(fetch_all_topo_data(active_devices))
    loop.close()

    for dev, (sys_descr, sys_name, sys_location), full_data in fetch_results:
        ip = dev['ip']; lvl = safe_int(dev.get('level'))
        if lvl >= 5:
            dev['sys_descr'] = sys_descr
            continue
            
        # 💡 第二關解鎖：如果是波羅阿圖，就算 SNMP 判定無回應，我們也要強制放行，把剛剛 API 刮回來的光纖大禮包塞進快取！
        brand_lower = str(dev.get('brand', '')).lower()
        is_pa = "palo" in brand_lower or "pan" in brand_lower or "palo" in sys_descr.lower()
        
        if (sys_name and sys_name != "無回應") or is_pa:
            dev['sys_descr'] = sys_descr
            if sys_location and (not dev.get('location') or dev.get('location') == '自動探索'): dev['location'] = sys_location
            
            clean_sys_name = sys_name if (sys_name and sys_name != "無回應") else (dev.get('name') or ip)
            sysname_to_ip_map[clean_sys_name.split('.')[0].strip().lower()] = ip
            if dev.get('name') != sys_name and sys_name != "無回應" and sys_name: dev['name'] = sys_name
            
            if sys_descr != "無回應" and "SNMP Backup" not in sys_descr:
                auto_brand, auto_model = extract_brand_model(sys_descr)
                if not dev.get('brand') or dev.get('brand') == 'Unknown': dev['brand'] = auto_brand
                if not dev.get('model'): dev['model'] = auto_model
                
            device_full_data_cache[ip] = full_data
            dev['snmp_raw'] = json.dumps(full_data, ensure_ascii=False) if full_data else "{}"
                        
            poe_dict = {}
            if full_data and len(full_data) >= 22:
                for idx in [18, 19, 20]:
                    if isinstance(full_data[idx], dict):
                        for k, v in full_data[idx].items():
                            try:
                                port_idx = str(k).split('.')[-1]; mw = int(v)
                                if mw > 500 and mw != 1500 and mw < 95000: 
                                    poe_dict[port_idx] = max(poe_dict.get(port_idx, 0.0), round(mw / 1000.0, 1))
                            except: pass
                if isinstance(full_data[21], dict):
                    for k, v in full_data[21].items():
                        try:
                            port_idx = str(k).split('.')[-1]; w = float(v)
                            if w > 500: w_watts = w / 1000.0
                            elif w > 95.0: w_watts = w / 10.0
                            else: w_watts = w
                            if 0.1 <= w_watts < 100.0: poe_dict[port_idx] = max(poe_dict.get(port_idx, 0.0), round(w_watts, 1))
                        except: pass
            dev['poe_data'] = json.dumps(poe_dict, ensure_ascii=False)
            
            has_sensor = 0
            if full_data and len(full_data) >= 32:
                for idx in [26, 29, 31]:
                    if isinstance(full_data[idx], dict) and full_data[idx]: has_sensor = 1; break
                if not has_sensor and isinstance(full_data[30], dict):
                    if any(str(k).endswith('.10') or str(k) == '10' for k in full_data[30].keys()): has_sensor = 1
            dev['has_sensor'] = has_sensor
            
            if full_data and len(full_data) >= 8:
                if_names = full_data[4]; if_macs = full_data[7]
                for idx, mac_raw in if_macs.items():
                    mac_clean = re.sub(r'[^a-fA-F0-9]', '', mac_raw).lower()
                    if mac_clean and len(mac_clean) == 12: global_mac_to_port[mac_clean] = (ip, str(if_names.get(idx, f"Port {idx}")).strip('"'))
                
    added_node_ips = set() 
    color_map = {1: '#ff9999', 2: '#99ccff', 3: '#99ff99', 4: '#ffcc99', 5: '#e6e6fa', 6: '#f8d7da'}

    for dev in active_devices:
        ip = dev['ip']; name = dev.get('name', ''); lvl = safe_int(dev.get('level'))
        status = dev.get('status', 'up'); full_data = device_full_data_cache.get(ip)
        if not full_data or len(full_data) < 8: 
            if ip not in added_node_ips:
                node_data = {'id': ip, 'ip': ip, 'sysName': name, 'brand': dev.get('brand', 'Unknown'), 'model': dev.get('model', '').strip(), 'location': dev.get('location', '').strip(), 'level': lvl, 'shape': 'box', 'color': color_map.get(lvl, '#e0e0e0'), 'sysDescr': dev.get('sys_descr', '無資訊'), 'status': status, 'snmp_raw': dev.get('snmp_raw', '{}'), 'poe_data': dev.get('poe_data', '{}'), 'has_sensor': dev.get('has_sensor', 0)}
                if dev.get('x') is not None and dev.get('y') is not None: node_data['x'] = dev['x']; node_data['y'] = dev['y']
                nodes.append(node_data); added_node_ips.add(ip)
            continue
        
        lldp_sysnames, lldp_portdescs, lldp_portids, lldp_mgmtips, if_names, if_high_speeds, if_speeds, if_macs = full_data[:8]
        parsed_neighbors = []
        all_suffixes = set(lldp_sysnames.keys()) | set(lldp_portdescs.keys()) | set(lldp_portids.keys()) | set(lldp_mgmtips.keys())

        for suffix in all_suffixes:
            sysname_val = lldp_sysnames.get(suffix, '')
            remote_sysname = str(sysname_val).strip('"').split('.')[0]
            if remote_sysname.lower() == 'none': remote_sysname = ''
            parts = suffix.split('.')
            local_port_idx = parts[1] if len(parts) >= 3 else parts[-1]
            local_port_name = str(if_names.get(local_port_idx, f"Port {local_port_idx}")).strip('"')
            speed = 0
            try: speed = int(if_high_speeds.get(local_port_idx, 0))
            except: pass
            if speed <= 0:
                try: 
                    raw_bps = int(if_speeds.get(local_port_idx, 0))
                    speed = 10000 if raw_bps >= 4294967295 else raw_bps // 1000000
                except: pass
            if speed <= 0: speed = 1000 
            remote_port_desc = str(lldp_portdescs.get(suffix, '')).strip('"')
            remote_port_id = str(lldp_portids.get(suffix, '')).strip('"')
            desc_mac_clean = re.sub(r'[^a-fA-F0-9]', '', remote_port_desc).lower()
            id_mac_clean = re.sub(r'[^a-fA-F0-9]', '', remote_port_id).lower()
            is_mac_desc = len(desc_mac_clean) == 12 and bool(re.match(r'^([0-9A-F]{2}[:-]){5}([0-9A-F]{2})$', remote_port_desc, re.I))
            is_mac_id = len(id_mac_clean) == 12 and bool(re.match(r'^([0-9A-F]{2}[:-]){5}([0-9A-F]{2})$', remote_port_id, re.I))
            
            remote_ip = ''
            for mgmt_suffix, val in lldp_mgmtips.items():
                if mgmt_suffix.startswith(suffix + '.'):
                    ip_parts = mgmt_suffix.split('.')
                    if len(ip_parts) >= 4: remote_ip = f"{ip_parts[-4]}.{ip_parts[-3]}.{ip_parts[-2]}.{ip_parts[-1]}"; break

            resolved_by_mac = False; target_node_id = None; remote_port = "未知埠"
            if is_mac_desc and desc_mac_clean in global_mac_to_port: target_node_id, remote_port = global_mac_to_port[desc_mac_clean]; resolved_by_mac = True
            elif is_mac_id and id_mac_clean in global_mac_to_port: target_node_id, remote_port = global_mac_to_port[id_mac_clean]; resolved_by_mac = True
                
            if not resolved_by_mac:
                if not remote_port_desc and not is_mac_id and remote_ip in device_full_data_cache:
                    remote_if_names = device_full_data_cache[remote_ip][4]
                    if remote_port_id in remote_if_names: remote_port_desc = str(remote_if_names[remote_port_id]).strip('"')
                if remote_port_desc and not is_mac_desc: remote_port = remote_port_desc
                elif remote_port_id and not is_mac_id: remote_port = f"Port {remote_port_id}" if remote_port_id.isdigit() else remote_port_id
                elif is_mac_desc: remote_port = f"MAC: {remote_port_desc}"
                if remote_ip and any(d['ip'] == remote_ip for d in devices): target_node_id = remote_ip
                elif remote_sysname and remote_sysname.lower() in sysname_to_ip_map: target_node_id = sysname_to_ip_map[remote_sysname.lower()]
                else:
                    if remote_sysname:
                        for d in devices:
                            if remote_sysname.lower() in d.get('name', '').strip().lower(): target_node_id = d['ip']; break
                if not target_node_id: target_node_id = remote_ip if remote_ip else remote_sysname 

            if not target_node_id: continue
            target_lvl = next((safe_int(d.get('level')) for d in devices if d['ip'] == target_node_id), lvl + 1)
            if target_lvl > 6: target_lvl = 6
            if target_node_id in hidden_ips: continue
            if target_node_id and remote_ip and not is_valid_ipv4(target_node_id) and is_valid_ipv4(remote_ip):
                for d in devices:
                    if d['ip'] == target_node_id: d['ip'] = remote_ip; break
                target_node_id = remote_ip
            if not any(d['ip'] == target_node_id for d in devices): continue
            parsed_neighbors.append({'target_node_id': target_node_id, 'local_port_name': local_port_name, 'remote_port': remote_port, 'speed': speed, 'target_lvl': target_lvl})
            
        port_best_neighbor = {}
        for pn in parsed_neighbors:
            pname = pn['local_port_name']
            if pname not in port_best_neighbor or pn['target_lvl'] < port_best_neighbor[pname]['target_lvl']: port_best_neighbor[pname] = pn

        for pname, best in port_best_neighbor.items():
            target_node_id = best['target_node_id']; remote_port = best['remote_port']; speed = best['speed']; target_lvl = best['target_lvl']
            node_A, node_B = sorted([ip, target_node_id])
            link_key = (node_A, node_B)
            from_node = ip if lvl <= target_lvl else target_node_id
            to_node = target_node_id if lvl <= target_lvl else ip
            if link_key not in connections: connections[link_key] = { 'raw_records': [], 'direction': (from_node, to_node) }
            port_A, port_B = (pname, remote_port) if ip == node_A else (remote_port, pname)
            connections[link_key]['raw_records'].append({'port_A': port_A, 'port_B': port_B, 'speed': speed})

        if ip not in added_node_ips:
            node_data = {'id': ip, 'ip': ip, 'sysName': name, 'brand': dev.get('brand', 'Unknown'), 'model': dev.get('model', '').strip(), 'location': dev.get('location', '').strip(), 'level': lvl, 'shape': 'box', 'color': color_map.get(lvl, '#e0e0e0'), 'sysDescr': dev.get('sys_descr', '無資訊'), 'status': status, 'snmp_raw': dev.get('snmp_raw', '{}'), 'poe_data': dev.get('poe_data', '{}'), 'has_sensor': safe_int(dev.get('has_sensor', 0), 0)}
            if dev.get('x') is not None and dev.get('y') is not None: node_data['x'] = dev['x']; node_data['y'] = dev['y']
            nodes.append(node_data); added_node_ips.add(ip)

    def merge_ports_list(port_list):
        merged = []
        for p in port_list:
            p = str(p).strip()
            if not p: continue
            found = False
            for i, mp in enumerate(merged):
                n1 = re.sub(r'[^0-9/]', '', p); n2 = re.sub(r'[^0-9/]', '', mp)
                if n1 and n2 and (n1 == n2 or ('/' in n1 and n1.endswith('/'+n2)) or ('/' in n2 and n2.endswith('/'+n1))):
                    if len(p) > len(mp) or (p.lower().startswith('gigabit') and not mp.lower().startswith('gigabit')): merged[i] = p
                    found = True; break
            if not found: merged.append(p)
        return [p for p in merged if '/' in p or not re.match(r'^(port|lag|lg|trk|bond|po)\s*-?\d+$', p, re.I)]

    with DB_LOCKS['config']:
        conn = get_db('config')
        conn.execute("DELETE FROM edges")
        node_levels = {d['ip']: safe_int(d.get('level')) for d in devices}
        has_uplink = {}
        for (nA, nB), data in connections.items():
            lA = node_levels.get(nA, 99); lB = node_levels.get(nB, 99)
            if lA > lB: has_uplink[nA] = True
            elif lB > lA: has_uplink[nB] = True

        for (nA, nB), data in connections.items():
            lA = node_levels.get(nA, 99); lB = node_levels.get(nB, 99)
            if lA == lB and has_uplink.get(nA) and has_uplink.get(nB): continue 
            from_node, to_node = data['direction']
            a_raw, b_raw, valid_speeds = [], [], []
            for rec in data['raw_records']:
                a_raw.append(rec['port_A']); b_raw.append(rec['port_B'])
                if rec['speed'] > 0: valid_speeds.append(rec['speed'])
            a_final, b_final = sorted(merge_ports_list(a_raw)), sorted(merge_ports_list(b_raw))
            multiplier = min(len(a_final), len(b_final)) if len(a_final) > 0 and len(b_final) > 0 else max(1, len(a_final), len(b_final))
            total_speed = (min(valid_speeds) if valid_speeds else 1000) * multiplier
            a_str = ", ".join(a_final[:multiplier] if a_final else ['未知'])
            b_str = ", ".join(b_final[:multiplier] if b_final else ['未知'])
            p_from, p_to = (a_str, b_str) if from_node == nA else (b_str, a_str)
            edge_id = f"{from_node}-{to_node}"
            edges.append({'id': edge_id, 'from': from_node, 'to': to_node, 'speed': total_speed, 'from_port': p_from, 'to_port': p_to})
            conn.execute("INSERT INTO edges (id, source, target, speed, from_port, to_port) VALUES (?, ?, ?, ?, ?, ?)", (edge_id, from_node, to_node, total_speed, p_from, p_to))
        
        try:
            manual_rows = conn.execute("SELECT * FROM manual_links").fetchall()
            for row in manual_rows:
                edge_id = f"manual_{row['id']}_{row['node_a']}_{row['node_b']}"
                edges.append({
                    'id': edge_id, 'from': row['node_a'], 'to': row['node_b'],
                    'speed': row['speed'] if row['speed'] else 1000,
                    'from_port': row['port_a'], 'to_port': row['port_b'],
                    'is_manual': True, 'color': {'color': '#17a2b8', 'highlight': '#17a2b8', 'hover': '#17a2b8'}, 'dashes': True
                })
                conn.execute("INSERT OR REPLACE INTO edges (id, source, target, speed, from_port, to_port) VALUES (?, ?, ?, ?, ?, ?)", (edge_id, row['node_a'], row['node_b'], row['speed'] if row['speed'] else 1000, row['port_a'], row['port_b']))
        except Exception as e:
            from utils import log_info
            log_info(f"⚠️ 載入強制連線失敗: {e}")
            
        conn.commit()
        conn.close()
    
    write_db_devices(devices)
    return {'nodes': nodes, 'edges': edges, 'stats': {'elapsed': round(time.time() - scan_start_time, 2), 'scanned': len(nodes), 'added': 0}}

# ========================================================
# 🚨 擴充：SNMP Trap 主動告警接收引擎 (具備網孔深度解析與獨立防震盪)
# ========================================================
def snmp_trap_receiver_worker():
    import socket
    import time
    import re
    from utils import log_info, send_ntfy_alert
    # 💡 引入 get_db 與 DB_LOCKS 以便讀取系統設定
    from database import write_audit_log, read_db_devices, get_db, DB_LOCKS 

    global GLOBAL_TRAP_ENABLED # 💡 宣告使用全域變數，以便從資料庫覆寫它

    # 🌟 新增：開機啟動時，優先從 config.db 讀取管理員上次留下的開關設定
    try:
        with DB_LOCKS['config']:
            conn = get_db('config')
            row = conn.execute("SELECT value FROM system_settings WHERE key='trap_enabled'").fetchone()
            conn.close()
        if row:
            GLOBAL_TRAP_ENABLED = (row['value'] == '1')
    except Exception as e:
        log_info(f"⚠️ 無法讀取 Trap 歷史設定，預設為開啟: {e}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(('0.0.0.0', 162))
        sock.settimeout(1.0)
        
        status_msg = "已正式上線" if GLOBAL_TRAP_ENABLED else "目前處於【暫停/休眠】狀態"
        log_info(f"🚀 【主動告警引擎】網孔深度解析與防震盪 Trap 接收器啟動 ({status_msg})...")
    except Exception as e:
        log_info(f"❌ 【主動告警引擎】無法綁定 UDP Port 162: {e}")
        return

    trap_cooldowns = {}
    COOLDOWN_SECONDS = 60

    while True:
        try:
            if not GLOBAL_TRAP_ENABLED:
                time.sleep(1)
                continue

            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue 
                
            peer_ip = addr[0]
            hex_data = data.hex()

            # ... (下方保持您原本的密碼驗證與解析邏輯完全不變) ...
            
            # 1. 智慧尋址與密碼比對
            device_name = peer_ip
            expected_community = 'public' 
            try:
                for dev in read_db_devices():
                    if dev.get('ip') == peer_ip:
                        device_name = dev.get('name') or peer_ip
                        if dev.get('community'):
                            expected_community = dev.get('community')
                        break
            except Exception: pass

            community_hex = expected_community.encode('utf-8').hex()
            if community_hex not in hex_data: continue

            # 2. 解析斷線/連線特徵碼
            is_link_down = b'linkDown' in data or bytes.fromhex('2b0601060301010503') in data
            is_link_up = b'linkUp' in data or bytes.fromhex('2b0601060301010504') in data

            if is_link_down or is_link_up:
                
                # 3. 網孔深度解析
                port_info = "未知網孔"
                printable_strings = re.findall(b'[\x20-\x7E]{4,}', data)
                for s in printable_strings:
                    try:
                        dec = s.decode('ascii').strip()
                        if re.search(r'(?i)^(port|eth|gig|fa|te|ge|xge)[\s\-]?\d+', dec) or re.match(r'^\d+/\d+', dec):
                            port_info = dec
                            break
                    except: pass
                        
                if port_info == "未知網孔":
                    idx_match = re.search(r'2b0601020102020101([0-9a-f]{2})', hex_data)
                    if idx_match:
                        port_num = int(idx_match.group(1), 16)
                        if 0 < port_num < 200: 
                            port_info = f"Port {port_num}"

                # 4. 發送告警與防洗版邏輯
                cooldown_key = f"{peer_ip}_{port_info}"
                current_time = time.time()
                last_alert_time = trap_cooldowns.get(cooldown_key, 0)
                time_passed = current_time - last_alert_time

                if is_link_down:
                    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 🚨 【Trap 告警】{device_name} ({peer_ip}) 的 [{port_info}] 發生斷線!")
                    write_audit_log("SystemEngine", "SNMP Trap 告警", f"{device_name} ({peer_ip})", "FAILED", f"收到實體斷線警報 ({port_info} Link Down)")
                    
                    if time_passed >= COOLDOWN_SECONDS:
                        title = f"🚨 [主動告警] 設備網孔斷線"
                        body = f"設備：{device_name}\nIP：{peer_ip}\n網孔：{port_info}\n事件：實體斷線 (Link Down)\n時間：{time.strftime('%Y-%m-%d %H:%M:%S')}"
                        send_ntfy_alert(title, body, tags="warning,broken_cable", priority="high", source="SNMP Trap 告警", ip_addr=peer_ip)
                        trap_cooldowns[cooldown_key] = current_time
                    else:
                        print(f"   ↳ 🔕 [防護攔截] {port_info} 頻繁震盪，略過手機推播。")
                        
                elif is_link_up:
                    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] ✅ 【Trap 告警】{device_name} ({peer_ip}) 的 [{port_info}] 恢復連線!")
                    write_audit_log("SystemEngine", "SNMP Trap 告警", f"{device_name} ({peer_ip})", "SUCCESS", f"收到恢復連線警報 ({port_info} Link Up)")
                    
                    if time_passed >= COOLDOWN_SECONDS:
                        title = f"✅ [主動告警] 設備網孔恢復"
                        body = f"設備：{device_name}\nIP：{peer_ip}\n網孔：{port_info}\n事件：恢復連線 (Link Up)\n時間：{time.strftime('%Y-%m-%d %H:%M:%S')}"
                        send_ntfy_alert(title, body, tags="heavy_check_mark,link", priority="default", source="SNMP Trap 告警", ip_addr=peer_ip)
                        trap_cooldowns[cooldown_key] = current_time
                    else:
                        print(f"   ↳ 🔕 [防護攔截] {port_info} 頻繁震盪，略過手機推播。")

        except Exception as e:
            print(f"⚠️ [Trap 接收錯誤] {e}")

# ==========================================
# 💡 終極備援：Aruba CX SSH 實體光學抓取引擎 (安全授權版)
# ==========================================
def _sync_aruba_ssh(ip, ssh_user, ssh_pass):
    if not ssh_user or not ssh_pass:
        return {}
        
    import paramiko
    import time
    import re
    try:
        # 💡 納入除錯開關控制
        if DEBUG_SSH_LOG:
            print(f"🚀 [SSH 偵錯] 正在連線 Aruba CX ({ip}) ...")
            
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=ssh_user, password=ssh_pass, timeout=5, auth_timeout=5)
        channel = ssh.invoke_shell()
        time.sleep(1)
        if channel.recv_ready():
            channel.recv(5000)
            
        channel.send("no page\n")
        time.sleep(0.5)
        while channel.recv_ready():
            channel.recv(5000)
            
        if DEBUG_SSH_LOG:
            print(f"📡 [SSH 偵錯] 已送出指令，正等待交換器實體 I2C 晶片回應 (限時 60 秒)...")
            
        channel.send("show interface transceiver detail\n")
        
        output = ""
        for _ in range(60):
            time.sleep(1)
            while channel.recv_ready():
                output += channel.recv(65535).decode('utf-8', errors='ignore')
            if output.strip().endswith('#') or output.strip().endswith('>'):
                break
            if "More" in output[-50:]: 
                channel.send(" ")
                
        ssh.close()
        
        results = {}
        current_port = None
        port_count = 0
        
        for line in output.split('\n'):
            line_s = line.strip()
            m_port = re.search(r'(?:Transceiver in|Interface Name\s*:)\s*(\d+/\d+/\d+)', line_s, re.I)
            if m_port: 
                current_port = m_port.group(1)
                continue 
            
            if current_port:
                m_lane = re.search(r'1\s+[\d\.]+\s+[\d\.]+\s*/\s*([\-\d\.]+)\s+[\d\.]+\s*/\s*([\-\d\.]+)', line_s)
                if m_lane:
                    results[current_port] = { "rx": m_lane.group(1), "tx": m_lane.group(2) }
                    if DEBUG_SSH_LOG:
                        print(f"✅ [SSH 偵錯] 擷取到 {current_port} -> Tx: {m_lane.group(2)} dBm, Rx: {m_lane.group(1)} dBm")
                    port_count += 1
                    current_port = None 
                    
        if DEBUG_SSH_LOG:
            print(f"🎉 [SSH 偵錯] {ip} 處理完畢，共解析出 {port_count} 個光纖數據！")
        return results
    except Exception as e:
        # ⚠️ 即使關閉除錯，嚴重錯誤依然要提示，方便網管人員知悉
        print(f"⚠️ [SSH 引擎錯誤] Aruba ({ip}) 採集失敗: {e}")
        return {}

# ==========================================
# 🌐 跨界擴充：Palo Alto XML API 實體光學抓取引擎 (終極偵錯版)
# ==========================================
def _sync_palo_alto_api(ip, api_key):
    if not api_key:
        if DEBUG_PA_LOG:
            print(f"⚠️ [PA 偵錯] IP {ip} 沒有提供 API Key (密碼欄位為空)，跳過採集。")
        return {}
        
    import requests
    import xml.etree.ElementTree as ET
    import urllib3
    import traceback
    
    # 關閉自簽憑證產生的 SSL 警告
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    try:
        url = f"https://{ip}/api/?type=op&cmd=<show><transceiver><all/></transceiver></show>&key={api_key}"
        
        if DEBUG_PA_LOG:
            print(f"\n🌐 [PA 偵錯] ─────── 開始探測 Palo Alto 防火牆 ({ip}) ───────")
            # 安全防護：僅顯示 Key 的前 8 碼，其餘遮罩
            masked_key = api_key[:8] + "..." if len(api_key) > 8 else "..."
            print(f"🔍 [PA 偵錯] 目標發送網址: https://{ip}/api/?type=op&cmd=...&key={masked_key}")
            
        # 發送請求，放寬超時到 8 秒，確保高負載防火牆有時間回應
        response = requests.get(url, timeout=8, verify=False)
        
        if DEBUG_PA_LOG:
            print(f"📡 [PA 偵錯] 收到連線回應！HTTP 狀態碼: {response.status_code}")
            print(f"📄 [PA 偵錯] 👇 防火牆回傳的 XML 原始內容前 600 字元如下 👇")
            print("-" * 60)
            print(response.text[:600])
            print("-" * 60)
            
        if response.status_code != 200:
            print(f"❌ [PA 偵錯] 連線失敗，防火牆拒絕了 HTTP 請求。")
            return {}
            
        # 開始解析 XML
        root = ET.fromstring(response.content)
        
        # 💡 關鍵偵錯：檢查 Palo Alto 是否在 XML 裡面回傳了內部錯誤 (例如 status="error")
        if root.get('status') == 'error':
            msg_el = root.find(".//msg")
            err_msg = msg_el.text if msg_el is not None else "未知的 Palo Alto 內部錯誤訊息"
            print(f"❌ [PA API 拒絕] ⚠️ 防火牆內部報錯！拒絕理由: {err_msg}")
            return {}
            
        results = {}
        entry_count = 0
        
        for entry in root.findall(".//entry"):
            port_name = entry.get('name')
            if not port_name:
                continue
                
            tx_el = entry.find("tx-power")
            rx_el = entry.find("rx-power")
            
            if tx_el is not None and rx_el is not None:
                tx_val = tx_el.text.strip() if tx_el.text else "0"
                rx_val = rx_el.text.strip() if rx_el.text else "0"
                results[port_name] = { "tx": tx_val, "rx": rx_val }
                entry_count += 1
                if DEBUG_PA_LOG:
                    print(f"   ✅ [PA 數據成功] 介面 {port_name} -> Tx: {tx_val} mW, Rx: {rx_val} mW")
                    
        if DEBUG_PA_LOG:
            print(f"🎉 [PA 偵錯] 數據解析完畢，本次共成功塞入 {entry_count} 個光纖埠。")
            print(f"🌐 [PA 偵錯] ─────── Palo Alto ({ip}) 探測結束 ───────\n")
            
        return results
        
    except Exception as e:
        print(f"⚠️ [PA 引擎崩潰] 在對接時發生未預期例外錯誤: {e}")
        if DEBUG_PA_LOG:
            traceback.print_exc()
        return {}
        
# ==========================================
# 🌐 跨界擴充：Palo Alto XML API 實體光學抓取引擎
# ==========================================
def _sync_palo_alto_api(ip, api_key):
    if not api_key:
        return {}
        
    import requests
    import xml.etree.ElementTree as ET
    import urllib3
    # 💡 防火牆通常使用自簽憑證，強制關閉 SSL 警告，避免終端機跳出滿滿的紅字警告
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    try:
        # 💡 呼叫 Palo Alto 官方操作指令 API (等同於在 CLI 下達 show transceiver all)
        url = f"https://{ip}/api/?type=op&cmd=<show><transceiver><all/></transceiver></show>&key={api_key}"
        
        # 發送高速 HTTPS 請求
        response = requests.get(url, timeout=5, verify=False)
        if response.status_code != 200:
            return {}
            
        # 💡 精準解析 Palo Alto 回傳的 XML 結構樹
        root = ET.fromstring(response.content)
        results = {}
        
        # 尋找 XML 中所有的 <entry> 節點 (代表每一個實體光纖 Port)
        for entry in root.findall(".//entry"):
            port_name = entry.get('name') # 例如 "ethernet1/1"
            if not port_name:
                continue
                
            tx_el = entry.find("tx-power")
            rx_el = entry.find("rx-power")
            
            if tx_el is not None and rx_el is not None:
                # 💡 Palo Alto 回傳的是原始毫瓦 (mW)，如 "0.62"。
                # 直接保留字串，我們前端寫好的「智慧單位換算引擎」會自動認得 mW 並轉成 dBm！
                results[port_name] = {
                    "tx": tx_el.text.strip(),
                    "rx": rx_el.text.strip()
                }
                
        return results
    except Exception as e:
        print(f"⚠️ [Palo Alto API 錯誤] ({ip}) 擷取失敗: {e}")
        return {}
        
# ==========================================
# 🌐 跨界擴充：Palo Alto SSH 實體光學抓取引擎
# ==========================================
def _sync_palo_alto_ssh(ip, ssh_user, ssh_pass):
    if not ssh_user or not ssh_pass:
        if DEBUG_PA_LOG:
            print(f"⚠️ [PA 偵錯] IP {ip} 缺乏 SSH 帳密，跳過採集。")
        return {}
        
    import paramiko
    import time
    
    try:
        if DEBUG_PA_LOG:
            print(f"\n🌐 [PA SSH 偵錯] ─────── 開始探測 Palo Alto ({ip}) ───────")
            
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=ssh_user, password=ssh_pass, timeout=10, auth_timeout=10)
        
        channel = ssh.invoke_shell()
        time.sleep(1.5)
        if channel.recv_ready():
            channel.recv(8000)
            
        # 💡 關閉分頁功能並下達查詢指令
        channel.send("set cli pager off\n")
        time.sleep(0.5)
        channel.send("show transceiver all\n")
        
        output = ""
        for _ in range(15):
            time.sleep(1)
            while channel.recv_ready():
                chunk = channel.recv(65535).decode('utf-8', errors='ignore')
                output += chunk
                # 防呆：遇到分頁提示自動按空白鍵
                if "lines " in chunk or "More" in chunk or chunk.strip().endswith(":"):
                    channel.send(" ")
            
            if output.strip().endswith('>') or output.strip().endswith('#'):
                break
                
        ssh.close()
        
        results = {}
        for line in output.split('\n'):
            line_s = line.strip()
            # 尋找類似: ethernet1/15  44.78 C  3.22 V  36.83 mA  0.59 mW  0.83 mW
            if line_s.startswith("ethernet"):
                parts = line_s.split()
                if len(parts) >= 11 and parts[8].lower() == 'mw' and parts[10].lower() == 'mw':
                    port_name = parts[0]
                    tx_val = parts[7]
                    rx_val = parts[9]
                    results[port_name] = { "tx": tx_val, "rx": rx_val }
                    if DEBUG_PA_LOG:
                        print(f"   ✅ [PA 數據成功] {port_name} -> Tx: {tx_val} mW | Rx: {rx_val} mW")
                        
        if DEBUG_PA_LOG:
            print(f"🎉 [PA 偵錯] 數據解析完畢，本次共成功擷取 {len(results)} 個光纖埠。")
            
        return results
        
    except Exception as e:
        print(f"⚠️ [PA 引擎崩潰] SSH 連線或解析失敗: {e}")
        return {}