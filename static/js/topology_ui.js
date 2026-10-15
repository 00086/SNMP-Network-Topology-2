/**
 * =========================================================
 * 拓樸圖介面控制器 (topology_ui.js) - 資安稽核強化版
 * =========================================================
 */

// 💡 全域防呆通報引擎
if (typeof window.logFrontendAction !== 'function') {
    window.logFrontendAction = function(action, target, details) {
        fetch('/api/audit-logs/client', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: action, target: target, details: details, username: 'SystemUser' })
        }).catch(e => console.error(e));
    };
}

// 🌟 網孔設定全域記憶池 (包含 Uplink, MGMT 與記憶 IP)
window.portSettingsCache = [];
window.loadPortSettingsCache = async function() {
    try {
        let res = await fetch('/api/device/ports/cache');
        window.portSettingsCache = await res.json();
    } catch(e) { console.warn("無法載入網孔標註快取", e); }
};
// 網頁載入時預先抓取一次
document.addEventListener("DOMContentLoaded", window.loadPortSettingsCache);

function toggleGrid() { 
    isGridVisible = !isGridVisible; 
    var btnGrid = document.getElementById('btn-grid'); 
    if (isGridVisible) { 
        btnGrid.classList.remove('btn-grid-off'); btnGrid.classList.add('btn-grid-on'); 
    } else { 
        btnGrid.classList.remove('btn-grid-on'); btnGrid.classList.add('btn-grid-off'); 
    } 
    window.logFrontendAction("前端瀏覽軌跡", "切換顯示設定", `管理員將「磁吸網格」顯示狀態切換為：【 ${isGridVisible ? '開啟' : '關閉'} 】。`);
    if (network) network.redraw(); 
}

// 🌟 新增：全域收合/展開按鈕觸發器
function toggleCollapse() {
    isGlobalCollapsed = !isGlobalCollapsed;
    manualCollapseState = {}; // 切換全域時，清除所有單點手動記憶
    
    var btn = document.getElementById('btn-collapse');
    if (isGlobalCollapsed) {
        btn.classList.replace('btn-outline-secondary', 'btn-primary');
        btn.classList.add('text-white');
        btn.innerHTML = '<i class="bi bi-arrows-expand"></i>';
    } else {
        btn.classList.replace('btn-primary', 'btn-outline-secondary');
        btn.classList.remove('text-white');
        btn.innerHTML = '<i class="bi bi-arrows-collapse"></i>';
    }
    
    window.logFrontendAction("前端瀏覽軌跡", "切換顯示設定", `管理員將「L4 設備收合」狀態切換為：【 ${isGlobalCollapsed ? '收合' : '展開'} 】。`);
    
    updateNodeVisibility();
    updateAllLabels();
}

// 🌟 終極完美版：網路電流 BFS 引擎 + 智慧與手動 MGMT 線路過濾
function updateNodeVisibility() {
    if (!nodesDataSet || !cachedTopologyData || !edgesDataSet) return;

    let nodeMap = {};
    cachedTopologyData.nodes.forEach(n => {
        n._hasHiddenChildren = false; 
        nodeMap[n.id] = n;
    });

    let nodeMaxSpeed = {};
    cachedTopologyData.nodes.forEach(n => nodeMaxSpeed[n.id] = 0);
    cachedTopologyData.edges.forEach(e => {
        let speed = parseInt(e.speed) || 1000;
        if (speed > (nodeMaxSpeed[e.from] || 0)) nodeMaxSpeed[e.from] = speed;
        if (speed > (nodeMaxSpeed[e.to] || 0)) nodeMaxSpeed[e.to] = speed;
    });

    let blockers = new Set();
    cachedTopologyData.nodes.forEach(n => {
        if (manualCollapseState[n.id]) blockers.add(n.id);
        else if (isGlobalCollapsed && parseInt(n.level) === 3) blockers.add(n.id);
    });

    // 2. 建立線路地圖 (🌟 擴充：現在連 my_port 和 peer_port 的名字也記錄下來了)
    let adjList = {};
    cachedTopologyData.nodes.forEach(n => adjList[n.id] = []);
    cachedTopologyData.edges.forEach(e => {
        if (adjList[e.from] && adjList[e.to]) {
            let speed = parseInt(e.speed) || 1000;
            adjList[e.from].push({ peer: e.to, speed: speed, my_port: e.from_port, peer_port: e.to_port });
            adjList[e.to].push({ peer: e.from, speed: speed, my_port: e.to_port, peer_port: e.from_port });
        }
    });

    let visibleNodes = new Set();
    let queue = [];
    
    //let minLevel = Math.min(...cachedTopologyData.nodes.map(n => parseInt(n.level) || 99));
    //cachedTopologyData.nodes.forEach(n => {
    //    if (parseInt(n.level) === minLevel) { visibleNodes.add(n.id); queue.push(n.id); }
    //});
	
	// 🌟 修正後：讓 Level <= 3 骨幹交換器全數進入起始佇列，保證 106BONE 與下游樹狀結構永不消失
    cachedTopologyData.nodes.forEach(n => {
        let lvl = parseInt(n.level) || 99;
        if (lvl <= 3) { 
            visibleNodes.add(n.id); 
            queue.push(n.id); 
        }
    });

    while (queue.length > 0) {
        let currId = queue.shift();
        let currNode = nodeMap[currId];
        let currLevel = parseInt(currNode.level) || 99;
        let isCurrBlocker = blockers.has(currId);

        adjList[currId].forEach(edgeInfo => {
            let neighborId = edgeInfo.peer;
            let linkSpeed = edgeInfo.speed;
            let neighborNode = nodeMap[neighborId];
            if (!neighborNode) return;
            let neighborLevel = parseInt(neighborNode.level) || 99;

            let canTraverse = true;
            
            // 🌟 修正：只有當鄰居是嚴格位於下游 (Level 數字更大) 時才阻斷，同 Level 橫向連線直接放行
            if (isCurrBlocker && neighborLevel > currLevel) {
                canTraverse = false; 
            }

            // 🌟 終極特判 1：手動 MGMT 阻斷！(全面採用智慧孔號數字對齊比對，完美適用 Cisco/Aruba 長孔名)
            let isManualMgmt = false;
            if (window.portSettingsCache && window.portSettingsCache.length > 0) {
                let extractNum = function(str) { let m = String(str).match(/\d+(\/\d+)*/g); return m ? m[m.length - 1] : ""; };
                isManualMgmt = window.portSettingsCache.some(p => {
                    if (p.is_manual_mgmt !== 1 && p.is_manual_mgmt !== true) return false;
                    if (p.ip === currId) {
                        let pNum = extractNum(p.port_name);
                        let epArray = String(edgeInfo.my_port).toLowerCase().split(',');
                        for (let ep of epArray) {
                            let cleanEp = ep.trim();
                            if (cleanEp === String(p.port_name).toLowerCase().trim() || (pNum !== "" && extractNum(cleanEp) === pNum)) return true;
                        }
                    }
                    if (p.ip === neighborId) {
                        let pNum = extractNum(p.port_name);
                        let epArray = String(edgeInfo.peer_port).toLowerCase().split(',');
                        for (let ep of epArray) {
                            let cleanEp = ep.trim();
                            if (cleanEp === String(p.port_name).toLowerCase().trim() || (pNum !== "" && extractNum(cleanEp) === pNum)) return true;
                        }
                    }
                    return false;
                });
            }

            // 🌟 終極特判 2：如果被標註為手動 MGMT，或者自動判定為低速管理線路，直接封殺備援電流！
            if (isManualMgmt || (nodeMaxSpeed[neighborId] >= 1000 && linkSpeed < 1000)) {
                canTraverse = false;
            }

            if (canTraverse && !visibleNodes.has(neighborId)) {
                visibleNodes.add(neighborId);
                queue.push(neighborId);
            }
        });
    }

    // 4. 更新節點生死與圖示 (完全不變)
    let nodeUpdates = [];
    cachedTopologyData.nodes.forEach(n => {
        let isVisible = visibleNodes.has(n.id);
        nodeUpdates.push({ id: n.id, hidden: !isVisible });
        
        if (isVisible && blockers.has(n.id)) {
            let hasBlockedEdges = false;
            adjList[n.id].forEach(edgeInfo => {
                let p = nodeMap[edgeInfo.peer];
                if (p && (parseInt(p.level) || 99) >= (parseInt(n.level) || 99)) {
                    hasBlockedEdges = true;
                }
            });
            if (hasBlockedEdges) n._hasHiddenChildren = true;
        }
    });
    nodesDataSet.update(nodeUpdates);

    // 5. 終極線路修剪邏輯 (完全不變)
    let edgeUpdates = [];
    cachedTopologyData.edges.forEach(e => {
        let fromVisible = visibleNodes.has(e.from);
        let toVisible = visibleNodes.has(e.to);
        let edgeHidden = false;

        if (!fromVisible || !toVisible) {
                edgeHidden = true; 
            } else {
                let fromNode = nodeMap[e.from];
                let toNode = nodeMap[e.to];
                let fromLvl = fromNode ? parseInt(fromNode.level) || 99 : 99;
                let toLvl = toNode ? parseInt(toNode.level) || 99 : 99;

                // 🌟 修正：只有當連線是由收合點連向「更下游子節點」時才隱藏線路；橫向同 Level 線路一律保持可見
                if (blockers.has(e.from) && toLvl > fromLvl) { edgeHidden = true; } 
                else if (blockers.has(e.to) && fromLvl > toLvl) { edgeHidden = true; }
            }
		
		// 🌟 新增：如果管理員關閉了 MGMT 顯示，則強制將人工標註的管理線路自畫布隱藏 (同步升級智慧對齊)
        if (!edgeHidden && !isShowMgmtLines) {
            let extractNum = function(str) { let m = String(str).match(/\d+(\/\d+)*/g); return m ? m[m.length - 1] : ""; };
            let isMgmtLinkChecked = window.portSettingsCache.some(p => {
                if (p.is_manual_mgmt !== 1 && p.is_manual_mgmt !== true) return false;
                if (p.ip === e.from) {
                    let pNum = extractNum(p.port_name);
                    let epArray = String(e.from_port).toLowerCase().split(',');
                    for (let ep of epArray) {
                        let cleanEp = ep.trim();
                        if (cleanEp === String(p.port_name).toLowerCase().trim() || (pNum !== "" && extractNum(cleanEp) === pNum)) return true;
                    }
                }
                if (p.ip === e.to) {
                    let pNum = extractNum(p.port_name);
                    let epArray = String(e.to_port).toLowerCase().split(',');
                    for (let ep of epArray) {
                        let cleanEp = ep.trim();
                        if (cleanEp === String(p.port_name).toLowerCase().trim() || (pNum !== "" && extractNum(cleanEp) === pNum)) return true;
                    }
                }
                return false;
            });
            if (isMgmtLinkChecked) {
                edgeHidden = true;
            }
        }
		
        edgeUpdates.push({ id: e.id, hidden: edgeHidden });
    });
    edgesDataSet.update(edgeUpdates);
}

function toggleFlow() { 
    isShowFlow = !isShowFlow; 
    var btn = document.getElementById('btn-show-flow'); 
    if (isShowFlow) { 
        btn.classList.replace('btn-outline-secondary', 'btn-primary'); btn.classList.add('text-white'); 
        if (typeof startFlowAnimation === 'function') startFlowAnimation(); 
    } else { 
        btn.classList.replace('btn-primary', 'btn-outline-secondary'); btn.classList.remove('text-white'); 
        if (network) network.redraw(); 
    } 
    window.logFrontendAction("前端瀏覽軌跡", "切換顯示設定", `管理員將「動態資料流」顯示狀態切換為：【 ${isShowFlow ? '開啟' : '關閉'} 】。`);
}

function toggleShowIP() { 
    isShowIP = !isShowIP; 
    updateSwitchUI('btn-show-ip', isShowIP); 
    updateAllLabels(); 
    window.logFrontendAction("前端瀏覽軌跡", "切換顯示設定", `管理員將設備「IP 顯示」狀態切換為：【 ${isShowIP ? '開啟' : '隱藏'} 】。`);
}

function toggleShowName() { 
    isShowName = !isShowName; 
    updateSwitchUI('btn-show-name', isShowName); 
    updateAllLabels(); 
    window.logFrontendAction("前端瀏覽軌跡", "切換顯示設定", `管理員將設備「名稱顯示」狀態切換為：【 ${isShowName ? '開啟' : '隱藏'} 】。`);
}

function toggleShowLocation() { 
    isShowLocation = !isShowLocation; 
    updateSwitchUI('btn-show-location', isShowLocation); 
    updateAllLabels(); 
    window.logFrontendAction("前端瀏覽軌跡", "切換顯示設定", `管理員將設備「位置顯示」狀態切換為：【 ${isShowLocation ? '開啟' : '隱藏'} 】。`);
}

function updateSwitchUI(id, isShow) { 
    var btn = document.getElementById(id); 
    if (isShow) { 
        btn.classList.replace('btn-outline-secondary', 'btn-secondary'); btn.classList.add('text-white'); 
    } else { 
        btn.classList.replace('btn-secondary', 'btn-outline-secondary'); btn.classList.remove('text-white'); 
    } 
}

// 🌟 新增：獨立控制手動標註 MGMT 管理線路顯隱引擎
function toggleShowMgmtLines() {
    isShowMgmtLines = !isShowMgmtLines;
    updateSwitchUI('btn-show-mgmt', isShowMgmtLines);
    
    // 重新呼叫電力尋路引擎更新畫布線路狀態
    if (typeof updateNodeVisibility === 'function') updateNodeVisibility();
    if (network) network.redraw();
    
    window.logFrontendAction("前端瀏覽軌跡", "切換顯示設定", `管理員將「MGMT 線路顯示」狀態切換為：【 ${isShowMgmtLines ? '開啟' : '隱藏'} 】。`);
}

function toggleDarkMode() {
    isDarkMode = !isDarkMode; 
    var mynetwork = document.getElementById('mynetwork'); 
    var card = document.getElementById('topology-card'); 
    var title = document.getElementById('topology-title'); 
    var btnTheme = document.getElementById('btn-theme');
    
    window.logFrontendAction("前端瀏覽軌跡", "切換顯示設定", `管理員將拓樸圖主題切換為：【 ${isDarkMode ? '深色模式' : '淺色模式'} 】。`);

    if (isDarkMode) { 
        mynetwork.style.backgroundColor = '#1f293a'; 
        card.classList.add('bg-dark', 'border-secondary'); 
        card.style.backgroundColor = '#161e2a'; card.style.borderColor = '#2c3e50'; 
        title.classList.replace('text-secondary', 'text-light'); 
        btnTheme.innerHTML = '<i class="bi bi-sun-fill"></i>'; 
        btnTheme.classList.replace('btn-outline-secondary', 'btn-outline-light'); 
    } else { 
        mynetwork.style.backgroundColor = '#ffffff'; 
        card.classList.remove('bg-dark', 'border-secondary'); 
        card.style.backgroundColor = ''; card.style.borderColor = ''; 
        title.classList.replace('text-light', 'text-secondary'); 
        btnTheme.innerHTML = '<i class="bi bi-moon-stars-fill"></i>'; 
        btnTheme.classList.replace('btn-outline-light', 'btn-outline-secondary'); 
    }
    
    updateAllLabels(); 
    
    if(network) {
        var eUpdates = cachedTopologyData.edges.map(e => {
            var fromNode = cachedTopologyData.nodes.find(node => node.id === e.from); 
            var toNode = cachedTopologyData.nodes.find(node => node.id === e.to);
            var isEdgeDown = (fromNode && fromNode.status === 'down') || (toNode && toNode.status === 'down');
            var isEdgeWarning = !isEdgeDown && ((fromNode && fromNode.status === 'warning') || (toNode && toNode.status === 'warning'));
            var baseColor = getLinkColor(e.speed || 1000, isDarkMode);
            if (isEdgeDown) baseColor = '#dc3545'; 
            else if (isEdgeWarning) baseColor = isDarkMode ? '#ffe066' : '#d39e00';
            
            return { id: e.id, color: { color: baseColor, highlight: isDarkMode ? '#ffffff' : '#333333' } };
        });
        edgesDataSet.update(eUpdates); network.redraw();
    }

    let theme = isDarkMode ? TOPO_COLORS.dark : TOPO_COLORS.light;
    if(document.getElementById('leg-10g-c')) {
        document.getElementById('leg-10g-c').style.backgroundColor = theme.link10G;
        document.getElementById('leg-10g-t').style.color = isDarkMode ? theme.link10G : '#4da6ff';
        document.getElementById('leg-1g-c').style.backgroundColor = theme.link1G;
        document.getElementById('leg-1g-t').style.color = theme.link1G;
    }
}

function initApp() {
    fetch('/api/settings/polling').then(res => res.json()).then(data => { if(data.success && data.interval) { let select = document.getElementById('pollingIntervalSelect'); if (select) select.value = data.interval; } });
    fetch('/api/settings/toposcan').then(res => res.json()).then(data => { if(data.success && data.interval !== undefined) { let select = document.getElementById('topoScanIntervalSelect'); if (select) select.value = data.interval; } });
        
    fetch('/api/topology/fast?t=' + Date.now())
        .then(res => { if (!res.ok) throw Error("伺服器回應異常"); return res.json(); })
        .then(data => {
            if (data.empty || !data.nodes || data.nodes.length === 0) { 
                cachedTopologyData = {nodes: [], edges: []}; activeSlot = null; renderButtons(); 
                if (typeof showToast === 'function') showToast('資料庫目前為空！<br><span style="font-size:0.85rem; font-weight:normal;">請前往右上角「設備管理 (Excel明細)」，使用「網段探索」功能來新增網管設備。</span>', 'warning'); 
            } else {
                cachedTopologyData = data; 
                fetch('/api/topology/slots/status?t=' + Date.now())
                    .then(res => res.json())
                    .then(status => {
                        for (let i = 1; i <= 3; i++) { slotStatus[i] = parseInt(status[i] || status[String(i)] || 0, 10); }
                        let loaded = false; 
                        for (let i = 1; i <= 3; i++) { 
                            if (slotStatus[i] > 0) { manageSlot(i, 'load', true); loaded = true; break; } 
                        }
                        if (!loaded) manageSlot(null, 'reset_view', true); 
                    });
            }
        })
        .catch(err => { console.error(err); cachedTopologyData = {nodes: [], edges: []}; if (typeof showToast === 'function') showToast('無法連線到後端', 'danger'); });
}

function fetchSnmpData() {
    if (!cachedTopologyData || !cachedTopologyData.nodes || cachedTopologyData.nodes.length === 0) {
        return typeof showToast === 'function' ? showToast('資料庫為空！請先到「設備管理」透過「網段探索」加入設備。', 'warning') : alert('資料庫為空');
    }
    
    window.logFrontendAction("手動拓樸掃描", "全網連線拓樸圖", "管理員手動點擊「重新掃描」，發動全網鏈路深度 SNMP 探測與狀態校驗任務。");

    let detailDiv = document.getElementById("detailContent");
    if(detailDiv) detailDiv.innerHTML = '<div class="text-center py-5"><div class="spinner-border text-light"></div><p class="mt-2 text-white-50">正在深度掃描與 Ping 測試中，請稍候...</p></div>';
    
    fetch('/api/topology?t=' + Date.now())
        .then(res => res.json())
        .then(data => {
            if (data.error) throw new Error(data.error);
            cachedTopologyData = data; activeSlot = null; 
            if(typeof renderGraph === 'function') renderGraph(true); 
            updateSlotButtons(); 
            if (typeof showToast === 'function') {
                if (data.stats) {
                    showToast(`掃描任務執行完畢！<br><span style="font-size:0.85rem; font-weight:normal;">⏱️ 總共耗時: <b>${data.stats.elapsed}</b> 秒 <br>📡 主動掃描: <b>${data.stats.scanned}</b> 台設備 <br>➕ 發現新設備: <b>${data.stats.added}</b> 台</span>`, "success"); 
                } else {
                    showToast("系統掃描與驗證完成！", "success");
                }
            }
        })
        .catch(err => { 
            console.error(err); 
            if(detailDiv) detailDiv.innerHTML = `<p class="text-danger">失敗：${err.message}</p>`; 
            if (typeof showToast === 'function') showToast(`掃描失敗：${err.message}`, 'danger'); 
        });
}

function renderButtons() { 
    for (let i = 1; i <= 3; i++) { 
        let btn = document.getElementById(`btn-load-${i}`); if (!btn) continue; 
        let count = parseInt(slotStatus[i] || slotStatus[String(i)] || 0, 10); 
        if (activeSlot === i || activeSlot === String(i)) { 
            btn.style.cssText = 'background-color: #ff9800 !important; border-color: #ff9800 !important; color: #000000 !important;'; btn.title = `當前版面 ${i}`; 
        } else if (count > 0) { 
            btn.style.cssText = 'background-color: #0dcaf0 !important; border-color: #0dcaf0 !important; color: #ffffff !important;'; btn.title = `已有 ${count} 台`; 
        } else { 
            btn.style.cssText = 'background-color: #ffffff !important; border-color: #cccccc !important; color: #6c757d !important;'; btn.title = '尚未儲存'; 
        } 
    } 
}

function updateSlotButtons() { 
    fetch('/api/topology/slots/status?t=' + Date.now()).then(res => res.json()).then(status => { 
        for (let i = 1; i <= 3; i++) { slotStatus[i] = parseInt(status[i] || status[String(i)] || 0, 10); }
        renderButtons(); 
    }); 
}

function manageSlot(slotId, action, silent = false) {
    if (!cachedTopologyData) return;
    
    if (action === 'reset_view') { 
        fetch('/api/topology/positions/reset', { method: 'POST' }).then(res => res.json()).then(result => { 
            if (result.success) { 
                cachedTopologyData.nodes.forEach(n => { delete n.x; delete n.y; }); 
                activeSlot = null; 
                
                // 🌟 重置畫面時，一併解除所有收合狀態，回歸乾淨的預設值
                isGlobalCollapsed = false;
                manualCollapseState = {};
                var btn = document.getElementById('btn-collapse');
                if (btn) {
                    btn.classList.replace('btn-primary', 'btn-outline-secondary');
                    btn.classList.remove('text-white');
                    btn.innerHTML = '<i class="bi bi-arrows-collapse"></i>';
                }

                if(typeof renderGraph === 'function') renderGraph(true); 
                renderButtons(); 
                if (!silent && typeof showToast === 'function') showToast("已還原為預設階層排列", "info"); 
                
                if (!silent) window.logFrontendAction("前端介面操作", "全網拓樸視圖", "管理員點擊「重置畫面」，將所有節點圖元位置還原為預設自動排列。");
            } 
        }); return; 
    }
    if (action === 'clear_current') { 
        if (activeSlot === null) return typeof showToast === 'function' ? showToast("目前並非處於自訂版面，無法清除。", "warning") : alert("無版面可清除"); 
        if(!confirm(`確定要清除 [版面 ${activeSlot}] 的記憶嗎？`)) return; 
        fetch('/api/topology/slots/clear', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ slot: activeSlot }) })
        .then(res => res.json()).then(result => { 
            if (result.success) { 
                window.logFrontendAction("修改設備設定", `清除版面記憶 (${activeSlot})`, `管理員執行清理指令，將儲存於記憶庫之 【自訂版面槽位 ${activeSlot}】 歷史排版數據徹底清除。`);
                updateSlotButtons(); manageSlot(null, 'reset_view', true); 
                if(typeof showToast === 'function') showToast(result.message, "success"); 
            } 
        }); return; 
    }
    if (action === 'clear_all') { 
        if(!confirm('確定要徹底清除 1~3 所有版面記憶嗎？此動作無法復原。')) return; 
        fetch('/api/topology/slots/clear', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ slot: 'all' }) })
        .then(res => res.json()).then(result => { 
            if (result.success) { 
                window.logFrontendAction("修改設備設定", "清除版面記憶 (all)", "管理員執行高階抹除指令，將系統內所有槽位 (1~3) 的歷史拓樸排版資料全數清空。");
                updateSlotButtons(); manageSlot(null, 'reset_view', true); 
                if(typeof showToast === 'function') showToast(result.message, "success"); 
            } 
        }); return; 
    }
    if (action === 'load' && (!cachedTopologyData.nodes || cachedTopologyData.nodes.length === 0)) {
        return typeof showToast === 'function' ? showToast("資料庫為空！請新增設備。", "warning") : alert("資料庫為空"); 
    }
    
    // 💡 儲存版面
    if (action === 'save') { 
        var positions = network.getPositions(); 
        
        // 🌟 核心防呆：Vis.js 不會回傳被「收合隱藏」的節點座標！
        // 必須從快取中把隱藏的 AP 座標手動補齊，否則存檔會遺失！
        cachedTopologyData.nodes.forEach(n => {
            if (!positions[n.id] && n.x !== undefined && n.y !== undefined) {
                positions[n.id] = { x: n.x, y: n.y };
            }
        });

        var currentView = {
            position: network.getViewPosition(),
            scale: network.getScale(),
            // 🌟 記憶當下版面的專屬收合狀態
            isGlobalCollapsed: typeof isGlobalCollapsed !== 'undefined' ? isGlobalCollapsed : false,
            manualCollapseState: typeof manualCollapseState !== 'undefined' ? manualCollapseState : {}
        };

        fetch('/api/topology/slots/save', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ slot: slotId, positions: positions, view: currentView }) })
        .then(res => res.json()).then(res => { 
            if(typeof showToast === 'function') showToast(res.message, res.success ? 'success' : 'danger'); 
            if (res.success) { 
                window.logFrontendAction("修改設備設定", `儲存拓樸版面 ${slotId}`, `管理員調整了節點空間結構，並成功將目前排版座標記憶保存至 【自訂版面槽位 ${slotId}】。`);
                activeSlot = slotId; updateSlotButtons(); 
            } 
        }); 
    } 
    // 💡 讀取版面
    else if (action === 'load') { 
        if (!silent && typeof showToast === 'function') showToast(`正在讀取版面 ${slotId} 與視角記憶...`, 'info');
        fetch('/api/topology/slots/load', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ slot: slotId }) })
        .then(res => res.json()).then(res => { 
            if (res.success) { 
                cachedTopologyData.nodes.forEach(n => { if (res.positions && res.positions[n.id]) { n.x = res.positions[n.id].x; n.y = res.positions[n.id].y; } }); 
                activeSlot = slotId; 
                
                // 🌟 徹底切斷「狀態污染」：讀取時，強制套用該版面專屬的記憶！
                if (res.view) {
                    isGlobalCollapsed = res.view.isGlobalCollapsed === true;
                    manualCollapseState = res.view.manualCollapseState || {};
                } else {
                    // 若舊存檔沒有收合資料，則恢復為全部展開，避免被上一個版面污染！
                    isGlobalCollapsed = false;
                    manualCollapseState = {};
                }

                // 同步更新上方的「全域收合按鈕」UI 外觀
                var btn = document.getElementById('btn-collapse');
                if (btn) {
                    if (isGlobalCollapsed) {
                        btn.classList.replace('btn-outline-secondary', 'btn-primary');
                        btn.classList.add('text-white');
                        btn.innerHTML = '<i class="bi bi-arrows-expand"></i>';
                    } else {
                        btn.classList.replace('btn-primary', 'btn-outline-secondary');
                        btn.classList.remove('text-white');
                        btn.innerHTML = '<i class="bi bi-arrows-collapse"></i>';
                    }
                }

                if(typeof renderGraph === 'function') renderGraph(false); 
                renderButtons(); 

                // 動畫平移
                if (res.view && res.view.position && res.view.scale) {
                    network.moveTo({
                        position: res.view.position,
                        scale: res.view.scale,
                        animation: { duration: 1000, easingFunction: 'easeInOutQuad' }
                    });
                } else {
                    network.fit({ animation: { duration: 1000, easingFunction: 'easeInOutQuad' } });
                }

                if (!silent && typeof showToast === 'function') showToast(`✅ 已還原版面 ${slotId} 與專屬視角`, 'success'); 
                if (!silent) window.logFrontendAction("修改設備設定", `載入拓樸版面 ${slotId}`, `管理員執行讀取指令，自配置庫中成功覆蓋載入 【自訂版面槽位 ${slotId}】 的歷史排版座標。`);
            } else { 
                if (!silent && typeof showToast === 'function') showToast(res.message, 'danger'); 
            } 
        }); 
    }
}

function updatePollingInterval() { 
    let val = document.getElementById('pollingIntervalSelect').value; 
    fetch('/api/settings/polling', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ interval: val }) })
    .then(res => res.json()).then(res => { 
        if (res.success) {
            if(typeof showToast === 'function') showToast(`✅ 背景流量輪詢已更改為每 ${res.interval} 分鐘一次`, 'success'); 
            window.logFrontendAction("修改設定", "流量輪詢間隔", `管理員透過拓樸面板快捷控制項，將全網設備背景計數器輪詢間隔變更為: 【 ${res.interval} 分鐘 】。`);
        }
    }); 
}

function updateTopoScanInterval() { 
    let val = document.getElementById('topoScanIntervalSelect').value; 
    fetch('/api/settings/toposcan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ interval: val }) })
    .then(res => res.json()).then(res => { 
        if (res.success) {
            if(typeof showToast === 'function') showToast(res.interval == 0 ? '✅ 拓樸掃描已改為「僅限手動」' : `✅ 自動拓樸掃描已更改為每 ${res.interval} 分鐘一次`, 'success'); 
            let descStr = res.interval == 0 ? "手動觸發 (0)" : `${res.interval} 分鐘`;
            window.logFrontendAction("修改設定", "自動拓樸間隔", `管理員透過拓樸面板快捷控制項，將自動拓樸背景排程掃描週期變更為: 【 ${descStr} 】。`);
        }
    }); 
}

function isPortUplink(nodeIp, portName) {
    if (!portName) return false;
    let p = String(portName).toLowerCase().trim();
    if (p.includes('vlan') || p.includes('loop') || p.includes('tun') || p.includes('null') || p.includes('cpu') || p.includes('mgmt') || p.includes('management')) return false; 
    if (p.includes('lag') || p.includes('lg') || p.includes('po') || p.includes('trk') || p.includes('bond')) return true;

    if (!cachedTopologyData || !cachedTopologyData.edges) return false;
    let extractNum = function(str) { let m = str.match(/\d+(\/\d+)*/g); return m ? m[m.length - 1] : ""; };
    let pNum = extractNum(p); 
    
    for (let i = 0; i < cachedTopologyData.edges.length; i++) {
        let e = cachedTopologyData.edges[i];
        if (e.from === nodeIp || e.to === nodeIp) {
            let epString = String(e.from === nodeIp ? e.from_port : e.to_port).toLowerCase();
            let epArray = epString.split(',');
            for (let j = 0; j < epArray.length; j++) {
                let ep = epArray[j].trim(); if (!ep) continue;
                if (p === ep) return true; 
                let epNum = extractNum(ep); if (pNum !== "" && epNum !== "" && pNum === epNum) return true; 
            }
        }
    }
    return false;
}

// ========================================================
// 📍 設備名稱/IP 地標閃爍搜尋定位引擎
// ========================================================
let flashingMarker = null;

function findDeviceOnMap() {
    let query = document.getElementById('topo-search-ip').value.trim().toLowerCase();
    if (!query) return;

    if (!nodesDataSet || !network) {
        if(typeof window.showToast === 'function') window.showToast("網路拓樸尚未載入完畢", "warning");
        return;
    }
    
    // 優先精確比對 IP，其次模糊比對 SysName 或 IP
    let allNodes = nodesDataSet.get();
    let target = allNodes.find(n => n.ip === query);
    
    if (!target) {
        target = allNodes.find(n => n.ip.toLowerCase().includes(query) || (n.sysName && n.sysName.toLowerCase().includes(query)));
    }

    if (target) {
        // 1. 鏡頭聚焦並放大節點
        network.focus(target.id, {
            scale: 1.2,
            animation: { duration: 800, easingFunction: 'easeInOutQuad' }
        });
        network.selectNodes([target.id]);

        // 2. 移除現有殘留標記
        if (flashingMarker) {
            flashingMarker.remove();
            flashingMarker = null;
        }

        // 3. 建立 DOM 紅色地標，植入拓樸圖畫布之上
        flashingMarker = document.createElement('div');
        flashingMarker.className = 'map-marker-pin';
        flashingMarker.innerHTML = '<i class="bi bi-geo-alt-fill text-danger" style="filter: drop-shadow(0 0 8px rgba(255,255,255,0.8));"></i>';
        
        let container = document.getElementById('mynetwork'); 
        container.appendChild(flashingMarker);

        // 4. 動態追蹤：每幀更新標記位置 (即使使用者拖曳圖形，地標依然死死跟隨設備左上角)
        let updateMarker = () => {
            if (!flashingMarker) return;
            let canvasPos = network.getPositions([target.id])[target.id];
            if (canvasPos) {
                // 將 Vis.js 畫布座標轉回前端 DOM 絕對座標
                let domPos = network.canvasToDOM(canvasPos);
                // 置於設備左上角 (依據節點大小做微調偏移)
                flashingMarker.style.left = (domPos.x - 30) + 'px';
                flashingMarker.style.top = (domPos.y - 45) + 'px';
            }
            requestAnimationFrame(updateMarker);
        };
        updateMarker();

        // 5. 3 秒後自動消滅標記
        setTimeout(() => {
            if (flashingMarker) {
                flashingMarker.remove();
                flashingMarker = null;
            }
        }, 5000);
        
        document.getElementById('topo-search-ip').value = '';

        if(typeof window.showToast === 'function') window.showToast(`✅ 已為您定位到設備：${target.sysName || target.ip}`, "success");

    } else {
        if(typeof window.showToast === 'function') window.showToast("❌ 找不到符合名稱或 IP 的設備", "danger");
    }
}