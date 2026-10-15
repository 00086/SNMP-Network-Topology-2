package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync" // 👈 補上這一行！
	"time"

	"poller/database"
	"poller/snmp"
)

const (
	PythonWebhookURL = "http://127.0.0.1:5000/api/internal/reload_cache"
	ConfigDBPath     = "config.db"
	HotDBPath        = "telemetry_hot.db"
)

type ScanResult struct {
	Device  database.Device
	Traffic []database.TrafficRecord
	Metrics []database.MetricsRecord
}

func main() {
	log.Println("🚀 [Go Poller] 網路效能與拓樸並行引擎啟動中...")

	database.InitDatabases(ConfigDBPath, HotDBPath)
	defer database.ConfigDB.Close()
	defer database.HotDB.Close()

	// 1. 常駐 15 秒心跳線程 (防止 Python 誤報)
	go func() {
		for {
			_ = database.UpdateGoHeartbeat()
			time.Sleep(15 * time.Second)
		}
	}()

	// 2. 開啟 9090 Port 專供 Python 發動極速拓樸掃描
	go func() {
		http.HandleFunc("/api/scan_topology", func(w http.ResponseWriter, r *http.Request) {
			res, err := snmp.DiscoverTopology()
			w.Header().Set("Content-Type", "application/json")
			if err != nil {
				w.WriteHeader(500)
				_, _ = w.Write([]byte(fmt.Sprintf(`{"success":false,"error":"%v"}`, err)))
				return
			}
			jsonBytes, _ := json.Marshal(res)
			_, _ = w.Write(jsonBytes)
		})
		_ = http.ListenAndServe("127.0.0.1:9090", nil)
	}()

	var lastPollTime time.Time
	runPollingCycle()
	lastPollTime = time.Now()

	for {
		time.Sleep(5 * time.Second)
		intervalMins, err := database.GetPollingInterval()
		if err != nil {
			intervalMins = 3
		}
		if time.Since(lastPollTime) >= time.Duration(intervalMins)*time.Minute {
			runPollingCycle()
			lastPollTime = time.Now()
		}
	}
}

func runPollingCycle() {
	log.Println("==================================================")
	log.Println("🔍 [Go Poller] 開始新一輪全網設備深度探測...")
	cycleStart := time.Now()

	devices, err := database.GetActiveDevices()
	if err != nil {
		log.Printf("⚠️ 無法讀取設備清單: %v", err)
		return
	}
	if len(devices) == 0 {
		log.Println("💡 目前沒有需要掃描的設備。")
		return
	}

	var wg sync.WaitGroup
	resultChan := make(chan ScanResult, len(devices))
	sem := make(chan struct{}, 40)

	for _, dev := range devices {
		wg.Add(1)
		go func(d database.Device) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			updatedDev, tRecs, mRecs := snmp.ScanDevice(d)
			resultChan <- ScanResult{Device: updatedDev, Traffic: tRecs, Metrics: mRecs}
		}(dev)
	}

	wg.Wait()
	close(resultChan)

	var updatedDevices []database.Device
	var allTraffic []database.TrafficRecord
	var allMetrics []database.MetricsRecord
	successCount := 0

	for res := range resultChan {
		updatedDevices = append(updatedDevices, res.Device)
		allTraffic = append(allTraffic, res.Traffic...)
		allMetrics = append(allMetrics, res.Metrics...)
		if res.Device.Status == "up" {
			successCount++
		}
	}

	if err := database.BatchUpdateDeviceStatus(updatedDevices); err != nil {
		log.Printf("❌ 更新設備狀態大表失敗: %v", err)
	}
	if err := database.BatchInsertTelemetry(allTraffic, allMetrics); err != nil {
		log.Printf("❌ 寫入時序資料庫失敗: %v", err)
	}

	elapsedSec := time.Since(cycleStart).Seconds()
	log.Printf("✅ [Go Poller] 採集完畢 - 輪詢 %d 台，成功 %d 台，全網耗時: %.2fs", len(updatedDevices), successCount, elapsedSec)

	_ = database.UpdateGoHeartbeat()
	triggerPythonCacheReload(len(updatedDevices), successCount, elapsedSec)
}

func triggerPythonCacheReload(total int, success int, elapsed float64) {
	payload := fmt.Sprintf(`{"total":%d,"success":%d,"elapsed":%.2f}`, total, success, elapsed)
	resp, err := http.Post(PythonWebhookURL, "application/json", strings.NewReader(payload))
	if err != nil {
		log.Printf("⚠️ 無法通知 Python 伺服器更新快取: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		log.Println("🧠 [Go Poller] 已成功觸發 Python 記憶體快取熱更新與戰報印出！")
	}
}