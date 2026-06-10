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
    
    // 💡 儲存版面 (同時抓取 Vis.js 物理引擎的視角與縮放比例)
    if (action === 'save') { 
        var positions = network.getPositions(); 
        var currentView = {
            position: network.getViewPosition(),
            scale: network.getScale()
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
    // 💡 讀取版面 (連同視角一起動畫飛過去)
    else if (action === 'load') { 
        if (!silent && typeof showToast === 'function') showToast(`正在讀取版面 ${slotId} 與視角記憶...`, 'info');
        fetch('/api/topology/slots/load', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ slot: slotId }) })
        .then(res => res.json()).then(res => { 
            if (res.success) { 
                cachedTopologyData.nodes.forEach(n => { if (res.positions && res.positions[n.id]) { n.x = res.positions[n.id].x; n.y = res.positions[n.id].y; } }); 
                activeSlot = slotId; 
                if(typeof renderGraph === 'function') renderGraph(false); 
                renderButtons(); 

                // 💡 神奇魔法：如果資料庫有存視角，用滑順的動畫平移過去；沒有的話則還原成預設的 Fit (滿版)
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