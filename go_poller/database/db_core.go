package database

import (
	"database/sql"
	"fmt"
	"log"
	"time" // 👈 補上這一行！

	// 🌟 換成這個！純 Go 編譯的 SQLite，Windows 完全免裝 GCC 就能秒編譯！
	_ "modernc.org/sqlite"
)

var (
	ConfigDB *sql.DB
	HotDB    *sql.DB
)

func InitDatabases(configPath string, hotPath string) {
	var err error

	// 🌟 修復 1：將 busy_timeout 從 5000 (5秒) 大幅拉長到 30000 (30秒)
	configDSN := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(30000)", configPath)
	ConfigDB, err = sql.Open("sqlite", configDSN)
	if err != nil {
		log.Fatalf("❌ 無法開啟 Config DB: %v", err)
	}
	ConfigDB.SetMaxOpenConns(1)
	ConfigDB.SetMaxIdleConns(1) // 🌟 修復 2：限制閒置連線，防止幽靈鎖定

	// 🌟 修復 1：將 busy_timeout 從 5000 (5秒) 大幅拉長到 30000 (30秒)
	hotDSN := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(30000)&_pragma=synchronous(NORMAL)", hotPath)
	HotDB, err = sql.Open("sqlite", hotDSN)
	if err != nil {
		log.Fatalf("❌ 無法開啟 Hot DB: %v", err)
	}
	HotDB.SetMaxOpenConns(1)
	HotDB.SetMaxIdleConns(1) // 🌟 修復 2：限制閒置連線，防止幽靈鎖定

	log.Println("✅ 資料庫連線池初始化完成 (純 Go SQLite 引擎啟動，防死鎖等待機制已強化)")
}

// GetActiveDevices 從資料庫撈取所有需要輪詢的設備
func GetActiveDevices() ([]Device, error) {
	query := `
		SELECT ip, name, level, community, visible, brand, model, 
		       COALESCE(snmp_version, 'v2c'), COALESCE(is_poe, 0), COALESCE(has_sensor, 0), 
		       COALESCE(ssh_user, ''), COALESCE(ssh_pass, '')
		FROM devices 
		WHERE visible = 1
	`
	rows, err := ConfigDB.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []Device
	for rows.Next() {
		var d Device
		err := rows.Scan(
			&d.IP, &d.Name, &d.Level, &d.Community, &d.Visible, &d.Brand, &d.Model,
			&d.SNMPVersion, &d.IsPoE, &d.HasSensor, &d.SSHUser, &d.SSHPass,
		)
		if err != nil {
			log.Printf("⚠️ 讀取設備列時發生錯誤: %v", err)
			continue
		}
		devices = append(devices, d)
	}
	return devices, nil
}

// BatchInsertTelemetry 極速批量寫入時序資料 (利用 Transaction 包裝)
func BatchInsertTelemetry(traffic []TrafficRecord, metrics []MetricsRecord) error {
	// 啟動資料庫交易 (Transaction)，這比 Python 裡的迴圈 INSERT 快上百倍
	tx, err := HotDB.Begin()
	if err != nil {
		return err
	}

	// 1. 準備寫入 Traffic 表的 SQL 語句
	if len(traffic) > 0 {
		trafficStmt, err := tx.Prepare("INSERT INTO traffic_history (ip, port_idx, in_bytes, out_bytes, timestamp) VALUES (?, ?, ?, ?, ?)")
		if err != nil {
			tx.Rollback()
			return err
		}
		defer trafficStmt.Close()

		for _, t := range traffic {
			// 轉換時間格式為 SQLite 認得的字串
			tsStr := t.Timestamp.Format("2006-01-02 15:04:05")
			_, err = trafficStmt.Exec(t.IP, t.PortIdx, t.InBytes, t.OutBytes, tsStr)
			if err != nil {
				log.Printf("⚠️ 寫入流量紀錄失敗 (%s): %v", t.IP, err)
			}
		}
	}

	// 2. 準備寫入 Metrics 表的 SQL 語句
	if len(metrics) > 0 {
		// 🌟 擴充 SQL 語句，加入 latency_ms
		metricsStmt, err := tx.Prepare("INSERT INTO metrics_history (ip, cpu, memory, poe_w, temp_c, session_util, latency_ms, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
		if err != nil {
			tx.Rollback()
			return err
		}
		defer metricsStmt.Close()

		for _, m := range metrics {
			tsStr := m.Timestamp.Format("2006-01-02 15:04:05")
			// 🌟 執行時加入 m.LatencyMs
			_, err = metricsStmt.Exec(m.IP, m.CPU, m.Memory, m.PoEW, m.TempC, m.SessionUtil, m.LatencyMs, tsStr)
			if err != nil {
				log.Printf("⚠️ 寫入效能紀錄失敗 (%s): %v", m.IP, err)
			}
		}
	}

	// 提交交易
	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("提交時序資料交易失敗: %v", err)
	}

	return nil
}

// BatchUpdateDeviceStatus 批量更新設備大表的最新狀態與 JSON 原始資料
func BatchUpdateDeviceStatus(devices []Device) error {
	tx, err := ConfigDB.Begin()
	if err != nil {
		return err
	}

	// 🌟 擴充 SQL 語句，加入 latency_ms=?
	stmt, err := tx.Prepare(`
		UPDATE devices 
		SET status=?, cpu_load=?, mem_load=?, snmp_raw=?, poe_data=?, alert_count=?, last_alert_time=?, latency_ms=?
		WHERE ip=?
	`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()

	for _, d := range devices {
		// 🌟 執行時加入 d.LatencyMs
		_, err = stmt.Exec(d.Status, d.CPULoad, d.MemLoad, d.SNMPRaw, d.PoEData, d.AlertCount, d.LastAlertTime, d.LatencyMs, d.IP)
		if err != nil {
			log.Printf("⚠️ 更新設備狀態失敗 (%s): %v", d.IP, err)
		}
	}

	return tx.Commit()
}

// GetPollingInterval 從 system_settings 動態讀取輪詢間隔 (分鐘)
func GetPollingInterval() (int, error) {
	var valStr string
	// 查詢資料庫中的 polling_interval
	err := ConfigDB.QueryRow("SELECT value FROM system_settings WHERE key='polling_interval'").Scan(&valStr)
	if err != nil {
		return 3, err // 如果資料庫查不到，預設 3 分鐘安全牌
	}

	// 將字串轉為整數
	var mins int
	fmt.Sscanf(valStr, "%d", &mins)
	if mins <= 0 {
		return 3, nil // 防呆：如果設定值異常，一律維持 3 分鐘
	}

	return mins, nil
}

// UpdateGoHeartbeat 更新 Go 引擎專屬心跳時間戳記
func UpdateGoHeartbeat() error {
	nowStr := time.Now().Format("2006-01-02 15:04:05")
	query := `INSERT OR REPLACE INTO system_settings (key, value) VALUES ('go_poller_last_heartbeat', ?)`
	_, err := ConfigDB.Exec(query, nowStr)
	if err != nil {
		log.Printf("⚠️ 更新 Go 心跳時間失敗: %v", err)
		return err
	}
	return nil
}
