package snmp // 🌟 這裡必須是 snmp，不能是 database！

// SNMPRawData 嚴謹對應原本 Python 陣列索引的 JSON 結構
type SNMPRawData struct {
	LLDPSysNames   map[string]string `json:"0"`
	LLDPPortIds    map[string]string `json:"1"`
	LLDPPortDescrs map[string]string `json:"2"`
	LLDPSysDescrs  map[string]string `json:"3"`
	IfNames        map[string]string `json:"4"`
	IfHighSpeeds   map[string]string `json:"5"`
	IfSpeeds       map[string]string `json:"6"`
	IfMacs         map[string]string `json:"7"`
	IfDescrs       map[string]string `json:"8"`
	IfAliases      map[string]string `json:"9"`
	FDBTable       map[string]string `json:"10"`
	QBridgeFDB     map[string]string `json:"12"`
	ARPTable       map[string]string `json:"13"`
	PoEStd         map[string]string `json:"18"`
	PoEBrand       map[string]string `json:"19"`
	SysUpTime      map[string]string `json:"22"`
	IfInErrors     map[string]string `json:"23"`
	IfOutErrors    map[string]string `json:"24"`
	AdminStatus    map[string]string `json:"32"`
	OperStatus     map[string]string `json:"62"`
	PASession      map[string]string `json:"57"`
	PADPCPU        map[string]string `json:"58"`
}

// NewSNMPRawData 初始化所有的 map
func NewSNMPRawData() *SNMPRawData {
	return &SNMPRawData{
		LLDPSysNames:   make(map[string]string),
		LLDPPortIds:    make(map[string]string),
		LLDPPortDescrs: make(map[string]string),
		LLDPSysDescrs:  make(map[string]string),
		IfNames:        make(map[string]string),
		IfHighSpeeds:   make(map[string]string),
		IfSpeeds:       make(map[string]string),
		IfMacs:         make(map[string]string),
		IfDescrs:       make(map[string]string),
		IfAliases:      make(map[string]string),
		FDBTable:       make(map[string]string),
		QBridgeFDB:     make(map[string]string),
		ARPTable:       make(map[string]string),
		PoEStd:         make(map[string]string),
		PoEBrand:       make(map[string]string),
		SysUpTime:      make(map[string]string),
		IfInErrors:     make(map[string]string),
		IfOutErrors:    make(map[string]string),
		AdminStatus:    make(map[string]string),
		OperStatus:     make(map[string]string),
		PASession:      make(map[string]string),
		PADPCPU:        make(map[string]string),
	}
}