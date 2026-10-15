package snmp

import (
	"encoding/json"
	"fmt"
	"math"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall" // 🌟 1. 補上 syscall 套件
	"time"

	"github.com/gosnmp/gosnmp"
	"poller/database"
)

// ScanDevice 併發探測核心入口
func ScanDevice(dev database.Device) (database.Device, []database.TrafficRecord, []database.MetricsRecord) {
	brandLow := strings.ToLower(dev.Brand)
	modelLow := strings.ToLower(dev.Model)
	isPA := strings.Contains(brandLow, "palo") || strings.Contains(brandLow, "pan") || strings.Contains(modelLow, "pa-")
	isRuckus := strings.Contains(brandLow, "ruckus") || strings.Contains(brandLow, "foundry")
	isCisco := strings.Contains(brandLow, "cisco")
	isDLink := strings.Contains(brandLow, "d-link")
	isMikroTik := strings.Contains(brandLow, "mikrotik")

	// 🌟 終極穩定版連線設定
	params := &gosnmp.GoSNMP{
		Target:         dev.IP,
		Port:           161,
		Community:      dev.Community,
		Version:        gosnmp.Version2c,
		Timeout:        1200 * time.Millisecond, // 1.2 秒，足夠內網使用
		Retries:        1,                       // 失敗重試 1 次 (總共 2.4 秒的容忍度)
		MaxRepetitions: 15,                      // 🌟 關鍵解藥：對齊 Python 的 15，絕不塞爆老舊設備！
	}

	if dev.SNMPVersion == "v1" {
		params.Version = gosnmp.Version1
	}

	// ========================================================
	// 🌟 1. 執行 Ping 測速並取得延遲 (Latency)
	// ========================================================
	pingOK, latency := fastPing(dev.IP)

	err := params.Connect()
	if err != nil {
		if pingOK {
			dev.Status = "warning"
		} else {
			dev.Status = "down"
		}
		dev.LatencyMs = latency // 🌟 紀錄延遲
		return dev, nil, nil
	}
	defer params.Conn.Close()

	// 測試存活
	result, err := params.Get([]string{"1.3.6.1.2.1.1.1.0"})
	if err != nil || len(result.Variables) == 0 {
		if pingOK {
			dev.Status = "warning"
		} else {
			dev.Status = "down"
		}
		dev.LatencyMs = latency // 🌟 紀錄延遲
		return dev, nil, nil
	}
	dev.Status = "up"
	dev.AlertCount = 0
	dev.LatencyMs = latency // 🌟 紀錄正常連線的延遲

	rawStruct := NewSNMPRawData()
	var trafficRecords []database.TrafficRecord
	var metricsRecords []database.MetricsRecord

	// ========================================================
	// 📡 抓取基礎網路流量與狀態
	// ========================================================
	rawStruct.IfNames = SmartWalk(params, "1.3.6.1.2.1.31.1.1.1.1", "1.3.6.1.2.1.2.2.1.2")
	rawStruct.IfHighSpeeds = SmartWalk(params, "1.3.6.1.2.1.31.1.1.1.15", "")
	rawStruct.IfSpeeds = SmartWalk(params, "1.3.6.1.2.1.2.2.1.5", "")
	rawStruct.IfAliases = SmartWalk(params, "1.3.6.1.2.1.31.1.1.1.18", "")
	rawStruct.AdminStatus = SmartWalk(params, "1.3.6.1.2.1.2.2.1.7", "")
	rawStruct.OperStatus = SmartWalk(params, "1.3.6.1.2.1.2.2.1.8", "")
	
	// ========================================================
	// 🕸️ 拓樸與底層網路狀態深度採集 (LLDP / MAC / ARP)
	// ========================================================
	rawStruct.LLDPSysNames = SmartWalk(params, "1.0.8802.1.1.2.1.4.1.1.9", "")
	rawStruct.LLDPPortIds = SmartWalk(params, "1.0.8802.1.1.2.1.4.1.1.7", "")
	rawStruct.LLDPPortDescrs = SmartWalk(params, "1.0.8802.1.1.2.1.4.1.1.6", "")
	rawStruct.LLDPSysDescrs = SmartWalk(params, "1.0.8802.1.1.2.1.4.1.1.8", "")

	rawStruct.IfMacs = SmartWalk(params, "1.3.6.1.2.1.2.2.1.6", "")
	rawStruct.IfDescrs = SmartWalk(params, "1.3.6.1.2.1.2.2.1.2", "")

	rawStruct.FDBTable = SmartWalk(params, "1.3.6.1.2.1.17.4.3.1.2", "")
	rawStruct.QBridgeFDB = SmartWalk(params, "1.3.6.1.2.1.17.7.1.2.2.1.2", "")
	rawStruct.ARPTable = SmartWalk(params, "1.3.6.1.2.1.4.22.1.2", "")

	rawStruct.SysUpTime = SmartWalk(params, "1.3.6.1.2.1.1.3", "")
	rawStruct.IfInErrors = SmartWalk(params, "1.3.6.1.2.1.2.2.1.14", "")
	rawStruct.IfOutErrors = SmartWalk(params, "1.3.6.1.2.1.2.2.1.20", "")

	inBytesMap := SmartWalk(params, "1.3.6.1.2.1.31.1.1.1.6", "1.3.6.1.2.1.2.2.1.10")
	outBytesMap := SmartWalk(params, "1.3.6.1.2.1.31.1.1.1.10", "1.3.6.1.2.1.2.2.1.16")

	now := time.Now()
	for portIdx, inVal := range inBytesMap {
		outVal := outBytesMap[portIdx]
		if _, ok := rawStruct.IfNames[portIdx]; ok {
			trafficRecords = append(trafficRecords, database.TrafficRecord{
				IP:        dev.IP,
				PortIdx:   portIdx,
				InBytes:   castToInt64(inVal),
				OutBytes:  castToInt64(outVal),
				Timestamp: now,
			})
		}
	}

	// ========================================================
	// 🧠 廠牌特規效能換算 (CPU, Memory, Session)
	// ========================================================
	var cpu, mem, poeW, tempC, sessionUtil float64

	cpuStd := SmartWalk(params, "1.3.6.1.2.1.25.3.3.1.2", "")
	memSize := SmartWalk(params, "1.3.6.1.2.1.25.2.3.1.5", "")
	memUsed := SmartWalk(params, "1.3.6.1.2.1.25.2.3.1.6", "")

	if isPA {
		paSession := SmartWalk(params, "1.3.6.1.4.1.25461.2.1.2.3.3", "")
		for _, v := range paSession {
			sessionUtil = extractFloat(v)
			break
		}
		var keys []int
		for k := range cpuStd {
			if ki, err := strconv.Atoi(k); err == nil {
				keys = append(keys, ki)
			}
		}
		sort.Ints(keys)
		if len(keys) > 1 {
			dpSum := 0.0
			for _, k := range keys[1:] {
				dpSum += extractFloat(cpuStd[strconv.Itoa(k)])
			}
			cpu = dpSum / float64(len(keys)-1)
		}
		rawStruct.PASession = map[string]string{"0": fmt.Sprintf("%d", int(sessionUtil))}
		mCPU := 0.0
		if cpu > 0 {
			mCPU = cpu * 0.8
		}
		rawStruct.PADPCPU = map[string]string{"1": fmt.Sprintf("%d", int(mCPU)), "2": fmt.Sprintf("%d", int(cpu))}

	} else {
		var cpuVals []float64
		var cpuBrand map[string]string
		if isRuckus {
			cpuBrand = SmartWalk(params, "1.3.6.1.4.1.1991.1.1.2.1.52", "")
		} else if isCisco {
			cpuBrand = SmartWalk(params, "1.3.6.1.4.1.9.9.109.1.1.1.1.7", "")
		}
		for _, v := range cpuBrand {
			cpuVals = append(cpuVals, extractFloat(v))
		}
		if len(cpuVals) == 0 {
			for _, v := range cpuStd {
				cpuVals = append(cpuVals, extractFloat(v))
			}
		}
		if len(cpuVals) > 0 {
			sum := 0.0
			for _, v := range cpuVals {
				sum += v
			}
			cpu = sum / float64(len(cpuVals))
		}
	}

	var memBrand map[string]string
	if isRuckus {
		memBrand = SmartWalk(params, "1.3.6.1.4.1.1991.1.1.2.1.53", "")
	}
	for _, v := range memBrand {
		mem = extractFloat(v)
		break
	}

	if mem == 0.0 {
		if isPA {
			if sizeStr, ok := memSize["1"]; ok {
				size := extractFloat(sizeStr)
				if usedStr, ok2 := memUsed["1"]; ok2 && size > 0 {
					used := extractFloat(usedStr)
					mem = (used / size) * 100
				}
			}
		} else {
			var memKeys []int
			for k := range memSize {
				if ki, err := strconv.Atoi(k); err == nil {
					memKeys = append(memKeys, ki)
				}
			}
			sort.Ints(memKeys)
			for _, ki := range memKeys {
				k := strconv.Itoa(ki)
				sizeStr := memSize[k]
				size := extractFloat(sizeStr)
				if usedStr, ok := memUsed[k]; ok && size > 0 {
					used := extractFloat(usedStr)
					mem = (used / size) * 100
					break
				}
			}
		}
	}

	// ========================================================
	// ⚡ PoE 供電瓦數解析
	// ========================================================
	dev.PoEData = "{}" // 預設給予空 JSON，避免寫入 NULL

	if dev.IsPoE == 1 {
		poeStd := SmartWalk(params, "1.3.6.1.2.1.105.1.3.1.1.4", "")
		var poeBrand map[string]string
		if isRuckus {
			poeBrand = SmartWalk(params, "1.3.6.1.4.1.1991.1.1.2.14.2.2.1.6", "")
		} else if isDLink {
			poeBrand = SmartWalk(params, "", "1.3.6.1.4.1.171.10.76.12.22.1.1.9")
		}

		// 🌟 1. 將結果綁定回 rawStruct，讓底層 JSON 保留原始紀錄
		rawStruct.PoEStd = poeStd
		if poeBrand != nil {
			rawStruct.PoEBrand = poeBrand
		}

		sumMW := 0.0
		poeDict := make(map[string]float64) // 🌟 2. 建立用來儲存各 Port 真實瓦數的字典

		// 解析通用 PoE 標準
		for k, v := range poeStd {
			val := extractFloat(v)
			if val >= 500 && val < 95000 && val != 1500 {
				w := val / 1000.0
				poeDict[k] = math.Round(w*10) / 10
				sumMW += val
			} else if val >= 0.5 && val < 500 {
				poeDict[k] = math.Round(val*10) / 10
				poeW += val
			}
		}
		
		// 解析 Ruckus 特規 PoE
		if isRuckus {
			for k, v := range poeBrand {
				val := extractFloat(v)
				if val >= 500 && val < 95000 {
					w := val / 1000.0
					poeDict[k] = math.Round(w*10) / 10
					sumMW += val
				} else if val >= 0.5 && val < 500 {
					poeDict[k] = math.Round(val*10) / 10
					poeW += val
				}
			}
		}
		poeW += sumMW / 1000.0

		// 解析 D-Link 特規 PoE
		if isDLink {
			for k, v := range poeBrand {
				val := extractFloat(v)
				var w float64
				if val > 500 {
					w = val / 1000.0
				} else if val > 95.0 {
					w = val / 10.0
				} else if val >= 0.1 && val <= 95.0 {
					w = val
				}
				if w > 0 {
					poeDict[k] = math.Round(w*10) / 10
					poeW += w
				}
			}
		}

		// 🌟 3. 將字典轉換為 JSON 字串，存入設備大表的 poe_data 欄位供網頁畫圖！
		if len(poeDict) > 0 {
			poeBytes, err := json.Marshal(poeDict)
			if err == nil {
				dev.PoEData = string(poeBytes)
			}
		}
	}

	// ========================================================
	// 🌡️ 硬體溫度感測
	// ========================================================
	if dev.HasSensor == 1 {
		tempStd := SmartWalk(params, "1.3.6.1.2.1.99.1.1.1", "")
		var tempBrand map[string]string
		if isRuckus {
			tempBrand = SmartWalk(params, "1.3.6.1.4.1.1991.1.1.2.13.1.1.4", "")
		} else if isCisco {
			tempBrand = SmartWalk(params, "1.3.6.1.4.1.9.9.13.1.3.1.3", "")
		} else if isMikroTik {
			tempBrand = SmartWalk(params, "1.3.6.1.4.1.14988.1.1.3", "")
		}

		var temps []float64
		for _, v := range tempStd {
			t := extractFloat(v)
			if t > 0 && t < 150 {
				temps = append(temps, t)
			}
		}
		if isRuckus {
			for _, v := range tempBrand {
				t := extractFloat(v) / 2.0
				if t > 0 && t < 150 {
					temps = append(temps, t)
				}
			}
		} else if isCisco {
			for _, v := range tempBrand {
				t := extractFloat(v)
				if t > 0 && t < 150 {
					temps = append(temps, t)
				}
			}
		} else if isMikroTik {
			for k, v := range tempBrand {
				if strings.HasSuffix(k, ".10") || k == "10" {
					t := extractFloat(v) / 10.0
					if t > 0 && t < 150 {
						temps = append(temps, t)
					}
				}
			}
		}
		if len(temps) > 0 {
			maxT := temps[0]
			for _, t := range temps {
				if t > maxT {
					maxT = t
				}
			}
			tempC = maxT
		}
	}

	dev.CPULoad = math.Round(cpu*10) / 10
	dev.MemLoad = math.Round(mem*10) / 10

	metricsRecords = append(metricsRecords, database.MetricsRecord{
		IP:          dev.IP,
		CPU:         dev.CPULoad,
		Memory:      dev.MemLoad,
		PoEW:        math.Round(poeW*10) / 10,
		TempC:       math.Round(tempC*10) / 10,
		SessionUtil: sessionUtil,
		LatencyMs:   latency, // 👈 🌟 加上這行：將延遲寫入時序大表
		Timestamp:   now,
	})

	jsonBytes, err := json.Marshal(rawStruct)

	if err == nil {
		dev.SNMPRaw = string(jsonBytes)
	} else {
		dev.SNMPRaw = "{}"
	}

	return dev, trafficRecords, metricsRecords
}

// 🛡️ 終極穩定版 SmartWalk
func SmartWalk(params *gosnmp.GoSNMP, oidV2 string, oidV1 string) map[string]string {
	results := make(map[string]string)
	targetOID := oidV2

	if params.Version == gosnmp.Version1 && oidV1 != "" {
		targetOID = oidV1
	}

	// 嘗試 1：v2c BulkWalk
	if params.Version != gosnmp.Version1 && targetOID != "" {
		binds, err := params.BulkWalkAll(targetOID)
		if err == nil && len(binds) > 0 {
			for _, pdu := range binds {
				portIdx := extractPortIdx(pdu.Name, targetOID)
				results[portIdx] = parsePDUValue(pdu.Value)
			}
			return results
		}
		// 🌟 關鍵修復：如果 BulkWalk 失敗，不要改變全域 Version 觸發雙倍超時，
		// 直接平滑降級為接下來的標準 WalkAll。
	}

	// 嘗試 2：標準 WalkAll (相容 v1 與不支援 Bulk 的 v2c 設備)
	if targetOID != "" {
		binds, err := params.WalkAll(targetOID)
		if err == nil && len(binds) > 0 {
			for _, pdu := range binds {
				portIdx := extractPortIdx(pdu.Name, targetOID)
				results[portIdx] = parsePDUValue(pdu.Value)
			}
		}
	}
	return results
}

func extractPortIdx(fullOid string, baseOid string) string {
	cleanOid := strings.TrimPrefix(fullOid, ".")
	baseOid = strings.TrimPrefix(baseOid, ".")
	return strings.TrimPrefix(cleanOid, baseOid+".")
}

// 🌟 修正：導入智慧型字串過濾機制
func parsePDUValue(val interface{}) string {
	if val == nil {
		return ""
	}
	switch v := val.(type) {
	case string:
		return safeString([]byte(v))
	case []byte:
		return safeString(v)
	case int, int32, int64, uint, uint32, uint64:
		return fmt.Sprintf("%d", v)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// 🌟 新增：智慧型 MAC 與二進位解碼器
func safeString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	
	isPrintable := true
	for _, c := range b {
		// 允許常見的可列印 ASCII 字元與換行符號
		if c < 32 || c > 126 {
			if c != '\r' && c != '\n' && c != '\t' {
				isPrintable = false
				break
			}
		}
	}
	
	// 如果全是可列印字元，直接回傳純文字
	if isPrintable {
		return string(b)
	}

	// 💡 遇到非列印字元 (例如 MAC 位址)，轉成帶有冒號的 16 進位字串
	// 這樣就能完美對齊 Python 原本用來解析 "00:1A:2B:..." 的正規表達式！
	var hexParts []string
	for _, c := range b {
		hexParts = append(hexParts, fmt.Sprintf("%02X", c))
	}
	return strings.Join(hexParts, ":")
}

func castToInt64(val string) int64 {
	var i int64
	fmt.Sscanf(val, "%d", &i)
	return i
}

func extractFloat(s string) float64 {
	re := regexp.MustCompile(`[-+]?\d*\.\d+|\d+`)
	match := re.FindString(s)
	if match != "" {
		val, _ := strconv.ParseFloat(match, 64)
		return val
	}
	return 0.0
}

// 🌟 升級版 fastPing：避開 Windows BIG5 中文亂碼，使用純 ASCII 符號特徵精準萃取延遲
func fastPing(ip string) (bool, float64) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping", "-n", "1", "-w", "1000", ip)
		// 🌟 2. 強制隱藏 Windows 控制台彈窗，徹底消除白色視窗閃爍
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	} else {
		cmd = exec.Command("ping", "-c", "1", "-W", "1", ip)
	}
	out, _ := cmd.CombinedOutput()
	outputStr := string(out)

	if strings.Contains(strings.ToUpper(outputStr), "TTL=") {
		re := regexp.MustCompile(`(?i)[=<]\s*([0-9\.]+)\s*ms`)
		matches := re.FindStringSubmatch(outputStr)
		if len(matches) > 1 {
			latency, _ := strconv.ParseFloat(matches[1], 64)
			return true, latency
		}
		return true, 1.0
	}
	return false, 999.0
}


