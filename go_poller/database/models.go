package database

import "time"

// 🖥️ 設備靜態設定與即時狀態表 (對應 config.db -> devices)
type Device struct {
	IP          string  `db:"ip"`
	Name        string  `db:"name"`
	Level       int     `db:"level"`
	Community   string  `db:"community"`
	Visible     int     `db:"visible"`
	Brand       string  `db:"brand"`
	Model       string  `db:"model"`
	SNMPVersion string  `db:"snmp_version"`
	IsPoE       int     `db:"is_poe"`
	HasSensor   int     `db:"has_sensor"`
	SSHUser     string  `db:"ssh_user"`
	SSHPass     string  `db:"ssh_pass"`
	
	// 以下為回寫時會用到的狀態欄位
	Status        string  `db:"status"`
	AlertCount    int     `db:"alert_count"`
	LastAlertTime string  `db:"last_alert_time"`
	CPULoad       float64 `db:"cpu_load"`
	MemLoad       float64 `db:"mem_load"`
	SNMPRaw       string  `db:"snmp_raw"`
	PoEData       string  `db:"poe_data"`
	LatencyMs     float64 `db:"latency_ms"` // 🌟 新增：延遲欄位
}

// 📈 時序流量記錄表 (對應 telemetry_hot.db -> traffic_history)
type TrafficRecord struct {
	IP        string
	PortIdx   string
	InBytes   int64
	OutBytes  int64
	Timestamp time.Time
}

// 🎛️ 效能指標記錄表 (對應 telemetry_hot.db -> metrics_history)
type MetricsRecord struct {
	IP          string
	CPU         float64
	Memory      float64
	PoEW        float64
	TempC       float64
	SessionUtil float64
	LatencyMs   float64 // 🌟 新增：延遲欄位
	Timestamp   time.Time
}
