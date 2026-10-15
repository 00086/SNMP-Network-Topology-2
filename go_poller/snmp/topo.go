package snmp

type TopoEdge struct {
	ID       string `json:"id"`
	From     string `json:"from"`
	To       string `json:"to"`
	Speed    int64  `json:"speed"`
	FromPort string `json:"from_port"`
	ToPort   string `json:"to_port"`
}

type TopoResult struct {
	Nodes []map[string]interface{} `json:"nodes"`
	Edges []TopoEdge               `json:"edges"`
	Stats map[string]interface{}   `json:"stats"`
}

// DiscoverTopology 空包預留函式： Go 引擎不再參與拓樸掃描與資料庫寫入
func DiscoverTopology() (*TopoResult, error) {
	return &TopoResult{
		Nodes: []map[string]interface{}{},
		Edges: []TopoEdge{},
		Stats: map[string]interface{}{"elapsed": "0.00", "scanned": 0},
	}, nil
}