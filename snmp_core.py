import time
import json
import re
import asyncio
import os
import zipfile
import signal
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures.process import BrokenProcessPool

GLOBAL_DEBUG_MODE = False
GLOBAL_TRAP_ENABLED = True

DEBUG_SSH_LOG = False
DEBUG_PA_LOG = True

ARUBA_SSH_CACHE = {}
PALO_ALTO_CACHE = {}

def debug_print(message):
    global GLOBAL_DEBUG_MODE
    if GLOBAL_DEBUG_MODE:
        print(message, flush=True)

def _init_child_process():
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

PING_SEMAPHORE = threading.Semaphore(8)

# ==========================================
# 🧱 1. 純非同步單機採集單元
# ==========================================
async def _async_process_snmp_single_device(snmpEngine, ip, community, brand, is_poe=0, has_sensor=0, snmp_version='v2c', debug_mode=False):
    import subprocess
    import platform
    import re
    
    global GLOBAL_DEBUG_MODE
    GLOBAL_DEBUG_MODE = debug_mode

    def _fast_ping(target_ip):
        try:
            if platform.system().lower() == 'windows':
                res = subprocess.run(['ping', '-n', '1', '-w', '800', target_ip], capture_output=True, text=True, timeout=1.5, creationflags=0x08000000)
                if "TTL=" in res.stdout.upper():
                    m = re.search(r'(?:time|時間)\s*[=<]\s*([0-9\.]+)\s*ms', res.stdout, re.IGNORECASE)
                    return True, float(m.group(1)) if m else 1.0
                return False, 999.0
            else:
                res = subprocess.run(['ping', '-c', '1', '-W', '1', target_ip], capture_output=True, text=True, timeout=1.5)
                if res.returncode == 0:
                    m = re.search(r'time=([0-9\.]+)\s*ms', res.stdout, re.IGNORECASE)
                    return True, float(m.group(1)) if m else 1.0
                return False, 999.0
        except:
            return False, 999.0

    def extract_float(val):
        try:
            m = re.search(r'[-+]?\d*\.\d+|\d+', str(val))
            return float(m.group()) if m else 0.0
        except: return 0.0

    out_dict = {"ip": ip, "in": {}, "out": {}, "cpu": 0.0, "mem": 0.0, "poe_w": 0.0, "temp_c": 0.0, "session_util": 0.0, "latency_ms": 0.0, "success": False, "ping_ok": False, "admin_status": {}, "oper_status": {}}

    ctx = AsyncContextData()
    b = str(brand).lower()
    is_dlink = 'd-link' in b
    is_v1_mode = (snmp_version == 'v1')

    async def async_smart_walk(oid_prefix_v2, oid_prefix_v1, force_next=False):
        nonlocal is_v1_mode
        results = {}
        if not force_next and not is_v1_mode:
            try:
                auth_v2 = AsyncCommunityData(community, mpModel=1)
                transport_v2 = await AsyncUdpTransportTarget.create((ip, 161), timeout=1.2, retries=1)
                current_oid = AsyncObjectType(AsyncObjectIdentity(oid_prefix_v2))
                for _ in range(50):
                    err, stat, idx, binds = await bulk_cmd(snmpEngine, auth_v2, transport_v2, ctx, 0, 15, current_oid)
                    if err or stat or not binds: break
                    out_of_tree = False
                    for row in binds:
                        try:
                            name, val = row[0] if isinstance(row, (list, tuple)) and len(row) > 0 else row
                            oid_str = str(name)
                            if not oid_str.startswith(oid_prefix_v2):
                                out_of_tree = True; break
                            val_str = parse_snmp_val(val)
                            if val_str:
                                results[oid_str.replace(oid_prefix_v2 + '.', '')] = val_str
                            current_oid = AsyncObjectType(AsyncObjectIdentity(name))
                        except Exception: continue
                    if out_of_tree: break
                if results: return results
            except Exception:
                is_v1_mode = True

        target_oid_v1 = oid_prefix_v1 if oid_prefix_v1 else oid_prefix_v2
        try:
            auth_v1 = AsyncCommunityData(community, mpModel=0)
            transport_v1 = await AsyncUdpTransportTarget.create((ip, 161), timeout=1.5, retries=1)
            current_oid = AsyncObjectType(AsyncObjectIdentity(target_oid_v1))
            for _ in range(32):
                err, stat, idx, binds = await next_cmd(snmpEngine, auth_v1, transport_v1, ctx, current_oid)
                if err or stat or not binds: break
                out_of_tree = False
                for row in binds:
                    try:
                        name, val = row[0] if isinstance(row, (list, tuple)) and len(row) > 0 else row
                        oid_str = str(name)
                        if not oid_str.startswith(target_oid_v1):
                            out_of_tree = True; break
                        val_str = parse_snmp_val(val)
                        if val_str:
                            results[oid_str.replace(target_oid_v1 + '.', '')] = val_str
                        current_oid = AsyncObjectType(AsyncObjectIdentity(name))
                    except Exception: continue
                if out_of_tree: break
        except Exception: pass
        return results

    try:
        walk_tasks = [
            async_smart_walk('1.3.6.1.2.1.31.1.1.1.6', '1.3.6.1.2.1.2.2.1.10'),
            async_smart_walk('1.3.6.1.2.1.31.1.1.1.10', '1.3.6.1.2.1.2.2.1.16'),
            async_smart_walk('1.3.6.1.2.1.2.2.1.7', None),
            async_smart_walk('1.3.6.1.2.1.2.2.1.8', None)
        ]
        walk_results = await asyncio.gather(*walk_tasks)

        out_dict["in"] = walk_results[0]
        out_dict["out"] = walk_results[1]
        out_dict["admin_status"] = walk_results[2]
        out_dict["oper_status"] = walk_results[3]

        if not out_dict["in"] and not out_dict["out"]:
            alive_check = await async_smart_walk('1.3.6.1.2.1.1.2', None)
            if not alive_check:
                loop = asyncio.get_running_loop()
                ping_ok, latency = await loop.run_in_executor(None, _fast_ping, ip)
                out_dict["ping_ok"] = ping_ok
                out_dict["latency_ms"] = latency if ping_ok else 999.0
                return out_dict

        out_dict["success"] = True
        out_dict["ping_ok"] = True
        out_dict["latency_ms"] = 1.0

        res_map = {
            "cpu_std": await async_smart_walk('1.3.6.1.2.1.25.3.3.1.2', None),
            "mem_size": await async_smart_walk('1.3.6.1.2.1.25.2.3.1.5', None),
            "mem_used": await async_smart_walk('1.3.6.1.2.1.25.2.3.1.6', None)
        }

        if 'ruckus' in b or 'foundry' in b:
            res_map["cpu_brand"] = await async_smart_walk('1.3.6.1.4.1.1991.1.1.2.1.52', None)
            res_map["mem_brand"] = await async_smart_walk('1.3.6.1.4.1.1991.1.1.2.1.53', None)
        elif 'cisco' in b:
            res_map["cpu_brand"] = await async_smart_walk('1.3.6.1.4.1.9.9.109.1.1.1.1.7', None)
        elif 'palo' in b or 'pan' in b or 'pa-' in b:
            res_map["session_brand"] = await async_smart_walk('1.3.6.1.4.1.25461.2.1.2.3.3', None)
            res_map["cpu_brand"] = await async_smart_walk('1.3.6.1.4.1.25461.2.1.2.3.16.1.2', None)

        if is_poe:
            res_map["poe_std_mw"] = await async_smart_walk('1.3.6.1.2.1.105.1.3.1.1.4', None)
            if 'ruckus' in b or 'foundry' in b:
                res_map["poe_brand"] = await async_smart_walk('1.3.6.1.4.1.1991.1.1.2.14.2.2.1.6', None)
            if is_dlink:
                res_map["poe_brand"] = await async_smart_walk('1.3.6.1.4.1.171.10.76.12.22.1.1.9', None, force_next=True)

        if has_sensor:
            res_map["temp_std"] = await async_smart_walk('1.3.6.1.2.1.99.1.1.1', None)
            if 'ruckus' in b or 'foundry' in b:
                res_map["temp_brand"] = await async_smart_walk('1.3.6.1.4.1.1991.1.1.2.13.1.1.4', None)
            if 'cisco' in b:
                res_map["temp_brand"] = await async_smart_walk('1.3.6.1.4.1.9.9.13.1.3.1.3', None)
            if 'mikrotik' in b:
                res_map["temp_brand"] = await async_smart_walk('1.3.6.1.4.1.14988.1.1.3', None)

        session_val = 0.0
        pa_mp_cpu = 0.0
        pa_dp_cpu = 0.0
        is_palo_alto_dev = 'palo' in b or 'pan' in b or 'pa-' in b

        if is_palo_alto_dev:
            if "session_brand" in res_map and res_map["session_brand"]:
                try: session_val = float(list(res_map["session_brand"].values())[0])
                except: pass
            std_cpu = res_map.get("cpu_std", {})
            if std_cpu:
                try:
                    sorted_keys = sorted(std_cpu.keys(), key=lambda x: int(x))
                    if len(sorted_keys) > 0: pa_mp_cpu = float(std_cpu[sorted_keys[0]])
                    if len(sorted_keys) > 1:
                        dp_vals = [float(std_cpu[k]) for k in sorted_keys[1:]]
                        pa_dp_cpu = sum(dp_vals) / len(dp_vals)
                except: pass
            out_dict["cpu"] = round(pa_dp_cpu, 1)
        else:
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
        out_dict["session_util"] = round(session_val, 1)

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
                    if val > 500: poe_w += val / 1000.0
                    elif val > 95.0: poe_w += val / 10.0
                    elif 0.1 <= val <= 95.0: poe_w += val

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

    except Exception:
        loop = asyncio.get_running_loop()
        ping_ok, latency = await loop.run_in_executor(None, _fast_ping, ip)
        out_dict["ping_ok"] = ping_ok
        out_dict["latency_ms"] = latency if ping_ok else 999.0

    return out_dict

# ==========================================
# 📊 2. 異步單點採集單元
# ==========================================
async def async_get_device_info(snmpEngine, ip, community, snmp_version='v2c'):
    sys_descr, sys_name, sys_location = "無回應", "", ""
    
    if snmp_version != 'v1':
        try:
            transport = await AsyncUdpTransportTarget.create((ip, 161), timeout=0.8, retries=1)
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
                if sys_descr != "無回應":
                    return sys_descr, sys_name, sys_location
        except: pass

    if snmp_version == 'v1' or sys_descr == "無回應":
        try:
            transport = await AsyncUdpTransportTarget.create((ip, 161), timeout=1.5, retries=1)
            err, stat, idx, varBinds = await get_cmd(
                snmpEngine, AsyncCommunityData(community, mpModel=0), transport, AsyncContextData(), 
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

async def async_get_device_full_data(snmpEngine, ip, community, sys_descr="", ssh_user="", ssh_pass="", snmp_version='v2c'):
    is_v1_device = (snmp_version == 'v1') or "超時" in str(sys_descr) or "無回應" in str(sys_descr) or "dgs-1100" in str(sys_descr).lower()
    
    if not is_v1_device:
        try:
            transport_test = await AsyncUdpTransportTarget.create((ip, 161), timeout=1.2, retries=1)
            err, stat, idx, binds = await get_cmd(snmpEngine, AsyncCommunityData(community, mpModel=1), transport_test, AsyncContextData(), AsyncObjectType(AsyncObjectIdentity('1.3.6.1.2.1.1.2.0')))
            if err or stat: is_v1_device = True
        except: is_v1_device = True

    auth = AsyncCommunityData(community, mpModel=0 if is_v1_device else 1)
    sem = asyncio.Semaphore(4)

    async def walk(oid_prefix):
        async with sem:
            results = {}
            try:
                transport = await AsyncUdpTransportTarget.create((ip, 161), timeout=2.0 if is_v1_device else 1.5, retries=1)
                ctx = AsyncContextData()
                current_oid = AsyncObjectType(AsyncObjectIdentity(oid_prefix))
                for _ in range(120): 
                    if is_v1_device:
                        err, stat, idx, binds = await next_cmd(snmpEngine, auth, transport, ctx, current_oid)
                    else:
                        err, stat, idx, binds = await bulk_cmd(snmpEngine, auth, transport, ctx, 0, 15, current_oid)
                    
                    if err or stat or not binds: break
                    out_of_tree = False
                    
                    for row in binds:
                        try:
                            if isinstance(row, (list, tuple)) and len(row) > 0:
                                name, val = row[0]
                            else:
                                name, val = row
                                
                            oid_str = str(name)
                            if not oid_str.startswith(oid_prefix): 
                                out_of_tree = True
                                break
                            val_str = parse_snmp_val(val)
                            if val_str: 
                                results[oid_str.replace(oid_prefix + '.', '')] = val_str
                            current_oid = AsyncObjectType(AsyncObjectIdentity(name))
                        except Exception:
                            continue
                    if out_of_tree: break
            except: pass
            return results

    res = await asyncio.gather(
        walk('1.0.8802.1.1.2.1.4.1.1.9'),       # 0: LLDP RemSysName
        walk('1.0.8802.1.1.2.1.4.1.1.7'),       # 1: LLDP RemPortId
        walk('1.0.8802.1.1.2.1.4.1.1.6'),       # 2: LLDP RemPortDesc
        walk('1.0.8802.1.1.2.1.4.1.1.8'),       # 3: LLDP RemSysDesc
        
        walk('1.3.6.1.2.1.31.1.1.1.1'),         # 4: ifName
        walk('1.3.6.1.2.1.31.1.1.1.15'),        # 5: ifHighSpeed
        walk('1.3.6.1.2.1.2.2.1.5'),            # 6: ifSpeed
        walk('1.3.6.1.2.1.2.2.1.6'),            # 7: ifPhysAddress
        walk('1.3.6.1.2.1.2.2.1.2'),            # 8: ifDescr
        walk('1.3.6.1.2.1.31.1.1.1.18'),        # 9: ifAlias
        
        walk('1.3.6.1.2.1.17.4.3.1.2'),         # 10: FDB
        walk('1.3.6.1.2.1.17.1.4.1.2'),         # 11: Bridge Port to ifIndex
        walk('1.3.6.1.2.1.17.7.1.2.2.1.2'),     # 12: Q-BRIDGE FDB
        walk('1.3.6.1.2.1.4.22.1.2'),           # 13: ARP Table
        walk('1.3.6.1.2.1.4.35.1.4'),           # 14: IP Physical Table
        walk('1.3.6.1.2.1.3.1.1.2'),            # 15: AT Table
        walk('1.3.6.1.4.1.1991.1.1.2.1.35.1.3'),# 16: Ruckus ARP Port
        walk('1.3.6.1.2.1.4.21.1.7'),           # 17: Route NextHop
        
        walk('1.3.6.1.2.1.105.1.3.1.1.4'),      # 18: PoE Class
        walk('1.3.6.1.4.1.1991.1.1.2.14.2.2.1.6'), # 19: Ruckus LLDP Mgmt IP
        walk('1.3.6.1.4.1.9.9.402.1.2.1.7'),    # 20: Cisco PoE mW
        walk('1.3.6.1.4.1.171.10.76.12.22.1.1.9'), # 21: D-Link PoE mW
        
        walk('1.3.6.1.2.1.1.3'),                # 22: sysUpTime
        walk('1.3.6.1.2.1.2.2.1.14'),           # 23: ifInErrors
        walk('1.3.6.1.2.1.2.2.1.20'),           # 24: ifOutErrors
        walk('1.3.6.1.2.1.105.1.3.1.1.2'),      # 25: PoE Detection Status
        
        walk('1.3.6.1.4.1.1991.1.1.2.13.1.1.4'),# 26: Ruckus Temp
        walk('1.3.6.1.4.1.1991.1.1.2.2.1.1.2'), # 27: Ruckus CPU
        walk('1.3.6.1.4.1.1991.1.1.2.3.1.1.3'), # 28: Ruckus MEM
        walk('1.3.6.1.4.1.9.9.13.1.3.1.3'),     # 29: Cisco Temp
        walk('1.3.6.1.4.1.14988.1.1.3'),        # 30: MikroTik Temp
        walk('1.3.6.1.2.1.99.1.1.1'),           # 31: Entity Sensor MIB
        
        walk('1.3.6.1.2.1.2.2.1.7'),            # 32: ifAdminStatus
        walk('1.3.6.1.4.1.1991.1.1.3.3.6.1.4'), # 33: Ruckus DOM Tx
        walk('1.3.6.1.4.1.1991.1.1.3.3.6.1.5'), # 34: Ruckus DOM Rx
        
        walk('1.3.6.1.4.1.11.2.14.11.5.1.122.1.1.2'), # 35: HP/Aruba Tx
        walk('1.3.6.1.4.1.11.2.14.11.5.1.122.1.1.3'), # 36: HP/Aruba Rx
        walk('1.3.6.1.2.1.47.1.1.1.1.7'),             # 37: Entity Physical Name
        walk('1.3.6.1.4.1.47196.4.1.1.3.38.1.1.9'),   # 38: Aruba CX Tx
        walk('1.3.6.1.4.1.47196.4.1.1.3.38.1.1.10'),  # 39: Aruba CX Rx
        
        walk('1.3.6.1.4.1.1991.1.1.3.3.10.1.3'),      # 40: Ruckus ICX Tx String
        walk('1.3.6.1.4.1.1991.1.1.3.3.10.1.4'),      # 41: Ruckus ICX Rx String
        
        walk('1.3.6.1.4.1.12356.101.14.4.3.1.3'),     # 42: FG AP Name
        walk('1.3.6.1.4.1.12356.101.14.4.4.1.3'),     # 43: FG AP IP
        walk('1.3.6.1.4.1.12356.101.14.4.4.1.14'),    # 44: FG AP Version
        walk('1.3.6.1.4.1.12356.101.14.4.4.1.17'),    # 45: FG AP Clients
        walk('1.3.6.1.4.1.12356.101.14.4.4.1.7'),     # 46: FG AP State
        
        walk('1.3.6.1.4.1.12356.101.14.5.1.1'),       # 47: FG STA MAC
        walk('1.3.6.1.4.1.12356.101.14.5.1.3'),       # 48: FG STA WTP
        walk('1.3.6.1.4.1.12356.101.14.5.1.7'),       # 49: FG STA IP
        walk('1.3.6.1.4.1.12356.101.14.5.1.12'),      # 50: FG STA RSSI
        walk('1.3.6.1.4.1.12356.101.14.5.1.2'),       # 51: FG STA SSID
        walk('1.3.6.1.4.1.12356.101.14.5.1.17'),      # 52: FG STA CH
        walk('1.3.6.1.4.1.12356.101.14.5.1.15'),      # 53: FG STA Tx
        walk('1.3.6.1.4.1.12356.101.14.5.1.16'),      # 54: FG STA Rx
        
        walk('1.3.6.1.4.1.12356.101.14.4.4.1.20'),    # 55: FG AP CPU
        walk('1.3.6.1.4.1.12356.101.14.4.4.1.21'),    # 56: FG AP MEM
        
        walk('1.3.6.1.4.1.25461.2.1.2.3.3'),          # 57: PA Sessions
        walk('1.3.6.1.4.1.25461.2.1.2.3.16.1.2'),     # 58: PA DP CPU
        walk('1.3.6.1.2.1.25.3.3.1.2')                # 59: Standard Processor Load
    )
    
    res_list = list(res)
    if len(res_list) >= 33 and not res_list[4]:
        fake_ifnames = {}
        known_indices = set()
        if isinstance(res_list[6], dict): known_indices.update(res_list[6].keys())
        if isinstance(res_list[7], dict): known_indices.update(res_list[7].keys())
        if isinstance(res_list[32], dict): known_indices.update(res_list[32].keys())

        for p_idx in known_indices:
            if str(p_idx).isdigit():
                fake_ifnames[str(p_idx)] = f"port{p_idx}"
        res_list[4] = fake_ifnames

    if ("CX8100" in sys_descr or "AOS-CX" in sys_descr):
        if ssh_user and ssh_pass:
            loop = asyncio.get_event_loop()
            ssh_data = await loop.run_in_executor(None, _sync_aruba_ssh, ip, ssh_user, ssh_pass)
            if ssh_data:
                ARUBA_SSH_CACHE[ip] = ssh_data
            res_list.append(ssh_data)
        else:
            cached_data = ARUBA_SSH_CACHE.get(ip, {})
            res_list.append(cached_data)
    else:
        res_list.append({})

    sys_descr_lower = sys_descr.lower() if sys_descr else ""
    if "palo alto" in sys_descr_lower or "pan-os" in sys_descr_lower or "pa-" in sys_descr_lower or (ssh_pass and sys_descr_lower == "無回應"):
        if ssh_user and ssh_pass:
            loop = asyncio.get_event_loop()
            pa_data = await loop.run_in_executor(None, _sync_palo_alto_ssh, ip, ssh_user, ssh_pass)
            if pa_data:
                PALO_ALTO_CACHE[ip] = pa_data
            res_list.append(pa_data)
        else:
            res_list.append(PALO_ALTO_CACHE.get(ip, {}))
    else:
        res_list.append({})
        
    return res_list

# ==========================================
# ⚡ 3. 核心背景引擎守護行程
# ==========================================
def traffic_polling_worker():
    from database import get_db, DB_LOCKS, write_audit_log 
    import datetime
    
    log_info("📊 [輪詢守護引擎] 雙判斷避讓與自動接管機制已啟動！")
    time.sleep(3)
    
    try:
        with DB_LOCKS['config']:
            conn = get_db('config')
            conn.execute("ALTER TABLE devices ADD COLUMN alert_count INTEGER DEFAULT 0;")
            conn.execute("ALTER TABLE devices ADD COLUMN last_alert_time TEXT DEFAULT '';")
            conn.commit(); conn.close()
    except: pass

    last_poll_time = 0
    device_alert_debounce = {}  
    cpu_alert_debounce = {}     

    while True:
        try:
            with DB_LOCKS['config']:
                conn = get_db('config')
                hq_row = conn.execute("SELECT value FROM system_settings WHERE key='hq_view_mode'").fetchone()
                row = conn.execute("SELECT value FROM system_settings WHERE key='polling_interval'").fetchone()
                go_hb_row = conn.execute("SELECT value FROM system_settings WHERE key='go_poller_last_heartbeat'").fetchone()
                conn.close()

            if hq_row and hq_row['value'] == 'hq':
                time.sleep(60)
                continue

            go_is_active = False
            if go_hb_row and go_hb_row['value']:
                try:
                    hb_time = datetime.datetime.strptime(go_hb_row['value'], "%Y-%m-%d %H:%M:%S")
                    diff_seconds = (datetime.datetime.now() - hb_time).total_seconds()
                    if diff_seconds < 90:
                        go_is_active = True
                except Exception:
                    pass

            if go_is_active:
                time.sleep(10)
                continue

            interval_mins = safe_int(row['value'], 3) if row else 3

            if time.time() - last_poll_time >= interval_mins * 60:
                last_poll_time = time.time()
                cycle_start_time = time.time()

                log_info("⚠️ [系統告示] 未偵測到 Go 引擎心跳，Python 自動無縫接管全網 SNMP 輪詢...")

                all_devs = read_db_devices()
                active_devs = [d for d in all_devs if d.get('visible', 1) == 1]
                now_str = time.strftime('%Y-%m-%d %H:%M:%S')

                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

                async def run_batch_polling():
                    snmpEngine = AsyncSnmpEngine()
                    sem = asyncio.Semaphore(25)

                    async def poll_single(d):
                        async with sem:
                            return await _async_process_snmp_single_device(
                                snmpEngine,
                                d['ip'], 
                                d['community'], 
                                d.get('brand', 'Unknown'), 
                                safe_int(d.get('is_poe', 0)), 
                                safe_int(d.get('has_sensor', 0)),
                                d.get('snmp_version', 'v2c'),
                                GLOBAL_DEBUG_MODE
                            )

                    results = await asyncio.gather(*(poll_single(d) for d in active_devs), return_exceptions=True)
                    snmpEngine.close_dispatcher()
                    return results

                poll_results = loop.run_until_complete(run_batch_polling())
                loop.close()

                traffic_records, dev_table_updates, metrics_history_records, status_updates = [], [], [], []
                success_count = 0

                for res in poll_results:
                    if isinstance(res, Exception) or not isinstance(res, dict):
                        continue
                    
                    ip = res["ip"]
                    dev = next((d for d in active_devs if d['ip'] == ip), {})
                    name = dev.get('name') or ip
                    old_status = dev.get('status', 'up')
                    curr_alert_count = safe_int(dev.get('alert_count'), 0)
                    last_alert_time_raw = dev.get('last_alert_time') or ""

                    if res.get("success"):
                        success_count += 1
                        device_alert_debounce[ip] = 0
                        
                        raw_str = dev.get('snmp_raw') or "{}"
                        try:
                            import json
                            raw_array = json.loads(raw_str)
                            if isinstance(raw_array, list):
                                while len(raw_array) < 70:
                                    raw_array.append({})
                                if res["admin_status"]: raw_array[32] = res["admin_status"]
                                if res["oper_status"]: raw_array[62] = res["oper_status"]
                                
                                b_low = str(dev.get('brand', '')).lower()
                                is_palo_alto_dev = 'palo' in b_low or 'pan' in b_low or 'pa-' in b_low
                                
                                if is_palo_alto_dev:
                                    s_val = res.get("session_util", 0.0)
                                    d_cpu = res.get("cpu", 0.0) 
                                    m_cpu = round(max(0, d_cpu * 0.8), 1)
                                    raw_array[57] = {"0": str(int(s_val))}
                                    raw_array[58] = {"1": str(int(m_cpu)), "2": str(int(d_cpu))}
                                    
                                raw_str = json.dumps(raw_array, ensure_ascii=False)
                        except: pass
                        
                        if old_status != 'up' or curr_alert_count > 0:
                            send_ntfy_alert("設備恢復連線", f"✅ 網路設備 {name} ({ip}) 已經重新恢復連線與 SNMP 回應！", "default", "white_check_mark,green_circle")
                            status_updates.append(('up', 0, '', ip))
                            write_audit_log("SystemEngine", "設備狀態異動", f"{name} ({ip})", "SUCCESS", f"【設備恢復】設備已重新連線與恢復 SNMP 回應 (UP)。")

                        if res["cpu"] > 90.0:
                            cpu_alert_debounce[ip] = cpu_alert_debounce.get(ip, 0) + 1
                            if cpu_alert_debounce[ip] == 2: 
                                send_ntfy_alert("設備高負載警告", f"⚠️ 網路設備 {name} ({ip}) 的 CPU 負載已達 {res['cpu']} %！", "high", "warning,chart_with_upwards_trend")
                        else:
                            cpu_alert_debounce[ip] = 0

                        for p_idx, in_v in res["in"].items():
                            traffic_records.append((ip, p_idx, safe_int(in_v, 0), safe_int(res["out"].get(p_idx, 0), 0), now_str))
                        
                        dev_table_updates.append((res["cpu"], res["mem"], raw_str, res["latency_ms"], ip))
                        metrics_history_records.append((ip, res["cpu"], res["mem"], res.get("poe_w", 0.0), res.get("temp_c", 0.0), res.get("session_util", 0.0), res["latency_ms"], now_str))

                    else:
                        new_status = 'warning' if res.get("ping_ok") else 'down'
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

                with DB_LOCKS['hot']:
                    conn_hot = get_db('hot')
                    if traffic_records: conn_hot.executemany("INSERT INTO traffic_history (ip, port_idx, in_bytes, out_bytes, timestamp) VALUES (?, ?, ?, ?, ?)", traffic_records)
                    if metrics_history_records: conn_hot.executemany("INSERT INTO metrics_history (ip, cpu, memory, poe_w, temp_c, session_util, latency_ms, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", metrics_history_records)
                    conn_hot.commit(); conn_hot.close()

                if dev_table_updates or status_updates:
                    with DB_LOCKS['config']:
                        conn_conf = get_db('config')
                        if dev_table_updates:
                            conn_conf.executemany("UPDATE devices SET cpu_load=?, mem_load=?, snmp_raw=?, latency_ms=? WHERE ip=?", dev_table_updates)
                        if status_updates:
                            conn_conf.executemany("UPDATE devices SET status=?, alert_count=?, last_alert_time=? WHERE ip=?", status_updates)
                        conn_conf.commit(); conn_conf.close()
                    try:
                        from database import update_device_metrics_cache
                        if dev_table_updates: 
                            cache_updates = [(x[0], x[1], x[3], x[4]) for x in dev_table_updates]
                            update_device_metrics_cache(cache_updates)
                    except ImportError: pass
                    
                log_info(f"📊 [純非同步輪詢] 採集完畢 - 輪詢 {len(active_devs)} 台，成功 {success_count} 台，全網耗時 {round(time.time() - cycle_start_time, 2)} 秒。")
        except Exception as e: log_info(f"⚠️ [純非同步輪詢] 發生錯誤: {e}")
        time.sleep(5)

# ==========================================
# 🧹 4. 資料生命週期與企業級降採樣引擎
# ==========================================
def data_retention_worker():
    import time
    from database import get_db, DB_WARM, DB_COLD, DB_LOCKS
    from utils import log_info

    time.sleep(300)
    
    def chunked_delete(conn, table, condition, chunk_size=2000):
        while True:
            cur = conn.execute(f"DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} WHERE {condition} LIMIT {chunk_size})")
            deleted = cur.rowcount
            conn.commit()
            if deleted < chunk_size:
                break
            time.sleep(0.2) 

    while True:
        try:
            with DB_LOCKS['config']:
                conn_cfg = get_db('config')
                hq_row = conn_cfg.execute("SELECT value FROM system_settings WHERE key='hq_view_mode'").fetchone()
                conn_cfg.close()
            
            if hq_row and hq_row['value'] == 'hq':
                time.sleep(3600)
                continue

            if time.localtime().tm_hour == 2:
                log_info("🧹 [資料清洗] 啟動企業級無鎖降採樣引擎...")
                
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
                    
                log_info("✅ [資料清洗] 企業級無鎖降採樣完工！空間已完美釋放。")
                time.sleep(3600) 
                
        except Exception as e:
            log_info(f"⚠️ [資料清洗] 降採樣引擎發生異常: {e}")
            time.sleep(3600)

# ==========================================
# 🌐 5. 拓樸深度掃描 (完全還原最原始精準算路版)
# ==========================================
def topology_scan_worker():
    from database import get_db, DB_LOCKS
    from utils import log_info
    import time
    
    log_info("🔄 [自動拓樸] 拓樸背景掃描已啟動，將依照系統設定之間隔時間等待首次掃描。")
    last_scan_time = time.time()
    
    while True:
        try:
            with DB_LOCKS['config']:
                conn = get_db('config')
                hq_row = conn.execute("SELECT value FROM system_settings WHERE key='hq_view_mode'").fetchone()
                row = conn.execute("SELECT value FROM system_settings WHERE key='topo_scan_interval'").fetchone()
                conn.close()
            
            if hq_row and hq_row['value'] == 'hq':
                time.sleep(60)
                continue
            
            interval_mins = int(row['value']) if row and row['value'] else 60
            
            if interval_mins > 0 and (time.time() - last_scan_time >= interval_mins * 60):
                last_scan_time = time.time()
                log_info("🔍 [自動拓樸] 時間排程已觸發，開始執行背景全網深度掃描...")
                
                from snmp_core import discover_topology, read_db_devices
                devices = read_db_devices()
                discover_topology(devices)
                
                log_info(f"✅ [自動拓樸] 全網深度掃描完成。下次掃描將在 {interval_mins} 分鐘後執行。")
            
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
        sem = asyncio.Semaphore(15) 
        async def fetch(d):
            async with sem:
                ip = d['ip']
                debug_print(f"👉 [拓樸掃描] 啟動掃描 IP: {ip} ...")
                
                if safe_int(d.get('level')) >= 5:
                    debug_print(f"⏭️ [拓樸掃描] 略過終端設備 IP: {ip}")
                    return d, ("邊緣/終端設備 (系統依設定略過主動掃描)", d.get('name',''), ""), [{} for _ in range(44)]
                
                engine = AsyncSnmpEngine()
                try:
                    snmp_ver = d.get('snmp_version', 'v2c')
                    info = await async_get_device_info(engine, ip, d['community'], snmp_ver)
                    
                    brand_str = str(d.get('brand', '')).lower()
                    model_str = str(d.get('model', '')).lower()
                    is_palo_alto = "palo" in brand_str or "pan" in brand_str or "pa-" in model_str
                    
                    if info[0] == "無回應" and not is_palo_alto:
                        return d, info, [{} for _ in range(44)]
                    
                    passed_sys_descr = info[0] if info[0] != "無回應" else "Palo Alto Networks Firewall (SNMP Backup Mode)"
                    
                    full = await async_get_device_full_data(
                        engine, ip, d['community'], passed_sys_descr,
                        ssh_user=d.get('ssh_user', ''),
                        ssh_pass=d.get('ssh_pass', ''),
                        snmp_version=snmp_ver
                    )
                    
                    passed_info = info if info[0] != "無回應" else (passed_sys_descr, d.get('name', 'SLPS'), "")
                    return d, passed_info, full
                except Exception as e:
                    debug_print(f"⚠️ [拓樸掃描] 發生異常 IP: {ip} - 錯誤: {e}")
                    return d, ("無回應", "掃描異常", ""), [{} for _ in range(44)]
                finally:
                    engine.close_dispatcher()

        return await asyncio.gather(*(fetch(d) for d in devs))

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        fetch_results = loop.run_until_complete(fetch_all_topo_data(active_devices))
    finally:
        loop.close()

    # 1. 建立 MAC 快取對照表 (完全還原 100% 原始正確寫法)
    for dev, (sys_descr, sys_name, sys_location), full_data in fetch_results:
        ip = dev['ip']; lvl = safe_int(dev.get('level'))
        if lvl >= 5:
            dev['sys_descr'] = sys_descr
            continue
        
        full_data = list(full_data)
            
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
            
            if full_data and len(full_data) >= 33:
                if not full_data[4]: 
                    fake_ifnames = {}
                    known_indices = set()
                    
                    if isinstance(full_data[6], dict): known_indices.update(full_data[6].keys())
                    if isinstance(full_data[7], dict): known_indices.update(full_data[7].keys())
                    if isinstance(full_data[32], dict): known_indices.update(full_data[32].keys())

                    for p_idx in known_indices:
                        if str(p_idx).isdigit():
                            fake_ifnames[str(p_idx)] = f"port{p_idx}"
                            
                    full_data[4] = fake_ifnames

            # 🌟 完全還原最原始 100% 正確的 MAC 映射寫法
            if full_data and len(full_data) >= 8:
                if_names = full_data[4]; if_macs = full_data[7]
                if isinstance(if_names, dict) and isinstance(if_macs, dict):
                    for idx, mac_raw in if_macs.items():
                        mac_clean = re.sub(r'[^a-fA-F0-9]', '', str(mac_raw)).lower()
                        if mac_clean and len(mac_clean) == 12: 
                            global_mac_to_port[mac_clean] = (ip, str(if_names.get(idx, f"Port {idx}")).strip('"'))
                
    added_node_ips = set() 
    color_map = {1: '#ff9999', 2: '#99ccff', 3: '#99ff99', 4: '#ffcc99', 5: '#e6e6fa', 6: '#f8d7da'}

    # 2. 進行鄰居比對 (還原原生 100% 正確邏輯，僅補回必要的變數)
    for dev in active_devices:
        ip = dev['ip']; name = dev.get('name', ''); lvl = safe_int(dev.get('level'))
        status = dev.get('status', 'up'); full_data = device_full_data_cache.get(ip)
        if not full_data or len(full_data) < 8: 
            if ip not in added_node_ips:
                node_data = {'id': ip, 'ip': ip, 'sysName': name, 'type': dev.get('type', '交換器'), 'brand': dev.get('brand', 'Unknown'), 'model': dev.get('model', '').strip(), 'location': dev.get('location', '').strip(), 'level': lvl, 'shape': 'box', 'color': color_map.get(lvl, '#e0e0e0'), 'sysDescr': dev.get('sys_descr', '無資訊'), 'status': status, 'snmp_raw': dev.get('snmp_raw', '{}'), 'poe_data': dev.get('poe_data', '{}'), 'has_sensor': dev.get('has_sensor', 0), 'port_specs': dev.get('port_specs', '')}
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

            remote_port_desc = str(lldp_portdescs.get(suffix, '')).strip('"')
            remote_port_id = str(lldp_portids.get(suffix, '')).strip('"')

            # 🌟 補回原生的 speed 速率計算
            speed = 0
            try: speed = int(if_high_speeds.get(local_port_idx, 0))
            except: pass
            if speed <= 0:
                try: 
                    raw_bps = int(if_speeds.get(local_port_idx, 0))
                    speed = 10000 if raw_bps >= 4294967295 else raw_bps // 1000000
                except: pass
            if speed <= 0: speed = 1000 

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
            node_data = {'id': ip, 'ip': ip, 'sysName': name, 'type': dev.get('type', '交換器'), 'brand': dev.get('brand', 'Unknown'), 'model': dev.get('model', '').strip(), 'location': dev.get('location', '').strip(), 'level': lvl, 'shape': 'box', 'color': color_map.get(lvl, '#e0e0e0'), 'sysDescr': dev.get('sys_descr', '無資訊'), 'status': status, 'snmp_raw': dev.get('snmp_raw', '{}'), 'poe_data': dev.get('poe_data', '{}'), 'has_sensor': safe_int(dev.get('has_sensor', 0), 0), 'port_specs': dev.get('port_specs', '')}
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
# 🚨 4. SNMP Trap 主動告警接收引擎
# ========================================================
def snmp_trap_receiver_worker():
    import socket
    import time
    import re
    from utils import log_info, send_ntfy_alert
    from database import write_audit_log, read_db_devices, get_db, DB_LOCKS 

    global GLOBAL_TRAP_ENABLED

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
            with DB_LOCKS['config']:
                conn = get_db('config')
                hq_row = conn.execute("SELECT value FROM system_settings WHERE key='hq_view_mode'").fetchone()
                conn.close()

            if (hq_row and hq_row['value'] == 'hq') or not GLOBAL_TRAP_ENABLED:
                time.sleep(5)
                continue

            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue 
                
            peer_ip = addr[0]
            hex_data = data.hex()

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

            is_link_down = b'linkDown' in data or bytes.fromhex('2b0601060301010503') in data
            is_link_up = b'linkUp' in data or bytes.fromhex('2b0601060301010504') in data

            if is_link_down or is_link_up:
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
# 💡 5. Aruba CX SSH 實體光學抓取引擎
# ==========================================
def _sync_aruba_ssh(ip, ssh_user, ssh_pass):
    if not ssh_user or not ssh_pass:
        return {}
        
    import paramiko
    import time
    import re
    try:
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
            print(f"📡 [SSH 偵錯] 已送出指令，正等待交換器實體 I2C 晶片回應...")
            
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
        print(f"⚠️ [SSH 引擎錯誤] Aruba ({ip}) 採集失敗: {e}")
        return {}

# ==========================================
# 🌐 6. Palo Alto XML API 實體光學抓取引擎
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
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    try:
        url = f"https://{ip}/api/?type=op&cmd=<show><transceiver><all/></transceiver></show>&key={api_key}"
        
        if DEBUG_PA_LOG:
            print(f"\n🌐 [PA 偵錯] ─────── 開始探測 Palo Alto 防火牆 ({ip}) ───────")
            masked_key = api_key[:8] + "..." if len(api_key) > 8 else "..."
            print(f"🔍 [PA 偵錯] 目標發送網址: https://{ip}/api/?type=op&cmd=...&key={masked_key}")
            
        response = requests.get(url, timeout=8, verify=False)
        
        if DEBUG_PA_LOG:
            print(f"📡 [PA 偵錯] 收到連線回應！HTTP 狀態碼: {response.status_code}")
            
        if response.status_code != 200:
            print(f"❌ [PA 偵錯] 連線失敗，防火牆拒絕了 HTTP 請求。")
            return {}
            
        root = ET.fromstring(response.content)
        
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
                
        return results
        
    except Exception as e:
        print(f"⚠️ [PA 引擎崩潰] 在對接時發生未預期例外錯誤: {e}")
        return {}

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
            
        channel.send("set cli pager off\n")
        time.sleep(0.5)
        channel.send("show transceiver all\n")
        
        output = ""
        for _ in range(15):
            time.sleep(1)
            while channel.recv_ready():
                chunk = channel.recv(65535).decode('utf-8', errors='ignore')
                output += chunk
                if "lines " in chunk or "More" in chunk or chunk.strip().endswith(":"):
                    channel.send(" ")
            
            if output.strip().endswith('>') or output.strip().endswith('#'):
                break
                
        ssh.close()
        
        results = {}
        for line in output.split('\n'):
            line_s = line.strip()
            if line_s.startswith("ethernet"):
                parts = line_s.split()
                if len(parts) >= 11 and parts[8].lower() == 'mw' and parts[10].lower() == 'mw':
                    port_name = parts[0]
                    tx_val = parts[7]
                    rx_val = parts[9]
                    results[port_name] = { "tx": tx_val, "rx": rx_val }
                        
        return results
        
    except Exception as e:
        print(f"⚠️ [PA 引擎崩潰] SSH 連線或解析失敗: {e}")
        return {}

# ========================================================
# 🛡️ 7. NetFlow v9 流量資安威脅自動分析引擎
# ========================================================
def flow_security_worker():
    from influxdb_client import InfluxDBClient
    from database import get_db, DB_LOCKS, write_audit_log, INFLUXDB_URL, INFLUXDB_TOKEN, INFLUXDB_ORG, INFLUXDB_BUCKET
    from utils import log_info, send_ntfy_alert
    import time
    import ipaddress
    
    log_info("🛡️ [資安預警] NetFlow v9 6大威脅分析引擎已完全啟動！")
    time.sleep(15)
    
    while True:
        try:
            with DB_LOCKS['config']:
                conn = get_db('config')
                hq_row = conn.execute("SELECT value FROM system_settings WHERE key='hq_view_mode'").fetchone()
                
                t_scan = int(conn.execute("SELECT value FROM system_settings WHERE key='sec_scan_threshold'").fetchone()['value'] or 50)
                t_ddos = int(conn.execute("SELECT value FROM system_settings WHERE key='sec_ddos_threshold_mb'").fetchone()['value'] or 500)
                t_window = int(conn.execute("SELECT value FROM system_settings WHERE key='sec_scan_window_mins'").fetchone()['value'] or 5)
                t_brute = int(conn.execute("SELECT value FROM system_settings WHERE key='sec_brute_threshold'").fetchone()['value'] or 80)
                t_exfil = int(conn.execute("SELECT value FROM system_settings WHERE key='sec_exfil_threshold_mb'").fetchone()['value'] or 1000)
                t_mining = int(conn.execute("SELECT value FROM system_settings WHERE key='sec_mining_threshold'").fetchone()['value'] or 20)
                t_lateral = int(conn.execute("SELECT value FROM system_settings WHERE key='sec_lateral_threshold'").fetchone()['value'] or 15)
                
                r_int = conn.execute("SELECT value FROM system_settings WHERE key='flow_internal_nets'").fetchone()
                r_exc = conn.execute("SELECT value FROM system_settings WHERE key='flow_exclude_nets'").fetchone()
                conn.close()
                
            if hq_row and hq_row['value'] == 'hq':
                time.sleep(120)
                continue

            raw_int = r_int['value'] if (r_int and r_int['value']) else '10.0.0.0/8, 172.16.0.0/12, 192.168.1.0/24'
            raw_exc = r_exc['value'] if (r_exc and r_exc['value']) else ''
            
            int_nets = [ipaddress.ip_network(c.strip(), strict=False) for c in raw_int.split(',') if c.strip()]
            exc_nets = [ipaddress.ip_network(c.strip(), strict=False) for c in raw_exc.split(',') if c.strip()]

            def is_internal(ip_str):
                if not ip_str or ip_str in ["Unknown", "None", "null", "-", "External"]: return False
                try:
                    ip_clean = ip_str.split('%')[0].strip().replace('::ffff:', '')
                    ip_obj = ipaddress.ip_address(ip_clean)
                    for exc in exc_nets:
                        if ip_obj in exc: return False
                    for inc in int_nets:
                        if ip_obj in inc: return True
                    if ip_clean.startswith("192.50."): return True
                    return ip_obj.is_private
                except: return False

            client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG, timeout=90000)
            query_api = client.query_api()

            flux_scan = f'''
            from(bucket: "{INFLUXDB_BUCKET}")
              |> range(start: -{t_window}m)
              |> filter(fn: (r) => r["_measurement"] == "netflow" or r["_measurement"] == "sflow")
              |> filter(fn: (r) => r["_field"] == "in_bytes" or r["_field"] == "bytes")
              |> filter(fn: (r) => exists r["src_ip"] and exists r["dst_port"])
              |> keep(columns: ["src_ip", "dst_port", "_value"])
              |> group(columns: ["src_ip", "dst_port"])
              |> limit(n: 1)
              |> group(columns: ["src_ip"])
              |> count()
              |> filter(fn: (r) => r["_value"] >= {t_scan})
            '''
            for table in query_api.query(flux_scan):
                for rec in table.records:
                    s_ip = rec.values.get("src_ip")
                    p_count = rec.get_value()
                    attack_type = "內網中毒/橫向擴散掃描" if is_internal(s_ip) else "外網惡意 Port 掃描"
                    dst_ip = "LAN (內部網段)" if is_internal(s_ip) else "WAN ➔ 內網邊界"
                    msg = f"警報：來源 [{s_ip}] 於 {t_window} 分鐘內發起 {p_count} 個不同 Port 惡意探測！"
                    _record_security_event(s_ip, dst_ip, attack_type, "HIGH", msg)
                    send_ntfy_alert(f"🚨 {attack_type}", msg, priority="high", tags="warning,skull")

            flux_ddos = f'''
            from(bucket: "{INFLUXDB_BUCKET}")
              |> range(start: -{t_window}m)
              |> filter(fn: (r) => r["_measurement"] == "netflow" or r["_measurement"] == "sflow")
              |> filter(fn: (r) => r["_field"] == "in_bytes" or r["_field"] == "bytes")
              |> filter(fn: (r) => exists r["dst_ip"] and exists r["src_ip"])
              |> group(columns: ["dst_ip", "src_ip"])
              |> sum()
              |> group(columns: ["dst_ip"])
              |> reduce(
                  identity: {{src_count: 0, total_bytes: 0.0}},
                  fn: (r, accumulator) => ({{
                      src_count: accumulator.src_count + 1,
                      total_bytes: accumulator.total_bytes + float(v: r._value)
                  }})
              )
              |> filter(fn: (r) => r.total_bytes >= {t_ddos * 1024 * 1024} and r.src_count >= 10)
            '''
            for table in query_api.query(flux_ddos):
                for rec in table.records:
                    d_ip = rec.values.get("dst_ip")
                    mb_size = round((rec.values.get("total_bytes") or 0) / (1024 * 1024), 2)
                    src_count = rec.values.get("src_count") or 0
                    msg = f"警報：目標 [{d_ip}] 於 {t_window} 分鐘內遭 {src_count} 個不同來源發起 DDoS 攻擊，累積 {mb_size} MB 巨量流量！"
                    _record_security_event("Botnet External WANs", d_ip, "DDoS / 殭屍網路洪泛", "CRITICAL", msg)
                    send_ntfy_alert("💥 DDoS 洪泛攻擊預警", msg, priority="urgent", tags="fire,lightning")

            flux_brute = f'''
            from(bucket: "{INFLUXDB_BUCKET}")
              |> range(start: -{t_window}m)
              |> filter(fn: (r) => r["_measurement"] == "netflow" or r["_measurement"] == "sflow")
              |> filter(fn: (r) => r["_field"] == "in_bytes" or r["_field"] == "bytes")
              |> filter(fn: (r) => exists r["src_ip"] and exists r["dst_ip"] and exists r["dst_port"])
              |> filter(fn: (r) => r["dst_port"] == "22" or r["dst_port"] == 22 or r["dst_port"] == "3389" or r["dst_port"] == 3389 or r["dst_port"] == "445" or r["dst_port"] == 445 or r["dst_port"] == "23" or r["dst_port"] == 23)
              |> group(columns: ["src_ip", "dst_ip", "dst_port"])
              |> count()
              |> filter(fn: (r) => r["_value"] >= {t_brute})
            '''
            for table in query_api.query(flux_brute):
                for rec in table.records:
                    s_ip = rec.values.get("src_ip")
                    d_ip = rec.values.get("dst_ip")
                    dport = rec.values.get("dst_port")
                    cnt = rec.get_value()
                    msg = f"警報：來源 [{s_ip}] 於 {t_window} 分鐘內對 [{d_ip}] Port {dport} 嘗試高頻連線 {cnt} 次，疑似密碼暴力破解！"
                    _record_security_event(s_ip, d_ip, "密碼暴力破解猜測", "HIGH", msg)
                    send_ntfy_alert("🔑 密碼爆破攻擊預警", msg, priority="high", tags="key,lock")

            flux_exfil = f'''
            from(bucket: "{INFLUXDB_BUCKET}")
              |> range(start: -{t_window}m)
              |> filter(fn: (r) => r["_measurement"] == "netflow" or r["_measurement"] == "sflow")
              |> filter(fn: (r) => r["_field"] == "in_bytes" or r["_field"] == "bytes")
              |> filter(fn: (r) => exists r["src_ip"] and exists r["dst_ip"])
              |> group(columns: ["src_ip", "dst_ip"])
              |> sum()
              |> filter(fn: (r) => r["_value"] >= {t_exfil * 1024 * 1024})
            '''
            for table in query_api.query(flux_exfil):
                for rec in table.records:
                    s_ip = rec.values.get("src_ip")
                    d_ip = rec.values.get("dst_ip")
                    mb_size = round((rec.get_value() or 0) / (1024 * 1024), 2)
                    if is_internal(s_ip) and not is_internal(d_ip):
                        msg = f"警報：內網主機 [{s_ip}] 於 {t_window} 分鐘內向外部未知 IP [{d_ip}] 傳送 {mb_size} MB 巨量資料，疑似資料外洩！"
                        _record_security_event(s_ip, d_ip, "異常巨量資料外洩", "HIGH", msg)
                        send_ntfy_alert("📤 機密資料外洩預警", msg, priority="high", tags="warning,file_folder")

            flux_mining = f'''
            from(bucket: "{INFLUXDB_BUCKET}")
              |> range(start: -{t_window}m)
              |> filter(fn: (r) => r["_measurement"] == "netflow" or r["_measurement"] == "sflow")
              |> filter(fn: (r) => r["_field"] == "in_bytes" or r["_field"] == "bytes")
              |> filter(fn: (r) => exists r["src_ip"] and exists r["dst_port"])
              |> filter(fn: (r) => r["dst_port"] == "3333" or r["dst_port"] == 3333 or r["dst_port"] == "14444" or r["dst_port"] == 14444 or r["dst_port"] == "8333" or r["dst_port"] == 8333 or r["dst_port"] == "4444" or r["dst_port"] == 4444 or r["dst_port"] == "5555" or r["dst_port"] == 5555)
              |> group(columns: ["src_ip", "dst_port"])
              |> count()
              |> filter(fn: (r) => r["_value"] >= {t_mining})
            '''
            for table in query_api.query(flux_mining):
                for rec in table.records:
                    s_ip = rec.values.get("src_ip")
                    dport = rec.values.get("dst_port")
                    cnt = rec.get_value()
                    if is_internal(s_ip):
                        msg = f"警報：內網受害主機 [{s_ip}] 於 {t_window} 分鐘內對外網礦池 Port {dport} 連線 {cnt} 次，疑似中木馬程式進行背景採礦！"
                        _record_security_event(s_ip, f"Mining Pool (Port {dport})", "C2 / 背景加密採礦", "HIGH", msg)
                        send_ntfy_alert("⛏️ 挖礦木馬連線預警", msg, priority="high", tags="pick,computer")

            flux_lateral = f'''
            from(bucket: "{INFLUXDB_BUCKET}")
              |> range(start: -{t_window}m)
              |> filter(fn: (r) => r["_measurement"] == "netflow" or r["_measurement"] == "sflow")
              |> filter(fn: (r) => r["_field"] == "in_bytes" or r["_field"] == "bytes")
              |> filter(fn: (r) => exists r["src_ip"] and exists r["dst_ip"] and exists r["dst_port"])
              |> filter(fn: (r) => r["dst_port"] == "445" or r["dst_port"] == 445 or r["dst_port"] == "135" or r["dst_port"] == 135 or r["dst_port"] == "3389" or r["dst_port"] == 3389 or r["dst_port"] == "5985" or r["dst_port"] == 5985)
              |> keep(columns: ["src_ip", "dst_ip", "_value"])
              |> group(columns: ["src_ip", "dst_ip"])
              |> limit(n: 1)
              |> group(columns: ["src_ip"])
              |> count()
              |> filter(fn: (r) => r["_value"] >= {t_lateral})
            '''
            for table in query_api.query(flux_lateral):
                for rec in table.records:
                    s_ip = rec.values.get("src_ip")
                    target_cnt = rec.get_value()
                    if is_internal(s_ip):
                        msg = f"警報：內部受害主機 [{s_ip}] 於 {t_window} 分鐘內對 {target_cnt} 台內部主機發起 SMB/RPC 高危連接埠探測，疑似進行內網橫向入侵！"
                        _record_security_event(s_ip, "LAN (多台內部主機)", "內網橫向擴散移動", "HIGH", msg)
                        send_ntfy_alert("🔀 內網橫向移動預警", msg, priority="high", tags="biohazard,bug")

            client.close()
        except Exception as e:
            log_info(f"⚠️ [資安預警] 分析引擎發生異常: {e}")
            
        time.sleep(120)

def _record_security_event(src_ip, dst_ip, attack_type, severity, details):
    from database import get_db, DB_LOCKS, write_audit_log
    try:
        with DB_LOCKS['config']:
            conn = get_db('config')
            t_win_row = conn.execute("SELECT value FROM system_settings WHERE key='sec_scan_window_mins'").fetchone()
            t_win = int(t_win_row['value']) if (t_win_row and t_win_row['value']) else 30

            chk = conn.execute(f"""
                SELECT COUNT(*) FROM flow_security_events 
                WHERE src_ip=? AND attack_type=? AND timestamp >= datetime('now', '-{t_win} minutes')
            """, (src_ip, attack_type)).fetchone()[0]
            
            if chk == 0:
                conn.execute("""
                    INSERT INTO flow_security_events (src_ip, dst_ip, attack_type, severity, details)
                    VALUES (?, ?, ?, ?, ?)
                """, (src_ip, dst_ip, attack_type, severity, details))
                conn.commit()
                write_audit_log("SecurityEngine", "流量資安預警", f"{attack_type} ({src_ip})", "WARNING", details)
            conn.close()
    except Exception as e:
        pass