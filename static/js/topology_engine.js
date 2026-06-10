/**
 * =========================================================
 * 拓樸圖核心引擎 (topology_engine.js) - 資安大一統版
 * 負責：全域變數宣告、Vis.js 繪圖、座標計算、流量視覺化、匯出功能
 * =========================================================
 */

// ==========================================
// 💡 全域變數宣告區 (自 HTML 完美遷移過來)
// ==========================================
var network = null;
var cachedTopologyData = null; 
var nodesDataSet = null; 
var edgesDataSet = null; 

var LEVEL_HEIGHT = 200; 
var GRID_SIZE = 10; 
var KEY_STEP_Y = 100;

var activeSlot = null; 
var slotStatus = {1: 0, 2: 0, 3: 0}; 
var isGridVisible = true;
var isDarkMode = false;
var isShowIP = true;
var isShowName = true;
var isShowLocation = false; 
var isShowFlow = false; 
var isShowNodeTraffic = false;
var nodeTrafficData = {};
var nodeTrafficIntervalId = null;
var flowAnimationTime = 0;
var animationId = null;

const TOPO_COLORS = {
    light: { link10G: '#0022aa', link1G: '#198754', link100M:'#fd7e14', down: '#dc3545', warning: '#d39e00', highlight:'#333333' },
    dark:  { link10G: '#0dcaf0', link1G: '#2ecc71', link100M:'#fd7e14', down: '#dc3545', warning: '#ffe066', highlight:'#ffffff' }
};

// ==========================================
// 💡 全域防呆通報引擎
// ==========================================
if (typeof window.logFrontendAction !== 'function') {
    window.logFrontendAction = function(action, target, details) {
        fetch('/api/audit-logs/client', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: action, target: target, details: details, username: 'SystemUser' })
        }).catch(e => console.error(e));
    };
}

// ==========================================
// 💡 實體介面推演函數 (自 HTML 完美遷移過來)
// ==========================================
function getPhysicalPortFromFDB(rawData, targetMac) {
    if (!targetMac) return null;
    let macClean = targetMac.replace(/[^a-fA-F0-9]/g, '').toLowerCase();
    let fdbData = rawData[9] || {};
    let qFdbData = rawData[12] || {};
    let bpToIfIndex = rawData[10] || {};
    let ifNames = rawData[4] || {};

    if (qFdbData && Object.keys(qFdbData).length > 0) {
        for (let suffix in qFdbData) {
            let parts = suffix.split('.');
            if (parts.length >= 7) {
                let hex = parts.slice(1).map(n => parseInt(n).toString(16).padStart(2, '0').toLowerCase()).join('');
                if (hex === macClean) {
                    let bPort = String(qFdbData[suffix]);
                    let ifIdx = bpToIfIndex[bPort] !== undefined ? String(bpToIfIndex[bPort]) : bPort;
                    return ifNames[ifIdx] ? String(ifNames[ifIdx]).replace('"', '').replace('\n', ' ').trim() : `Port ${ifIdx}`;
                }
            }
        }
    }
    if (fdbData && Object.keys(fdbData).length > 0) {
        for (let suffix in fdbData) {
            let hex = suffix.split('.').map(n => parseInt(n).toString(16).padStart(2, '0').toLowerCase()).join('');
            if (hex === macClean) {
                let bPort = String(fdbData[suffix]);
                let ifIdx = bpToIfIndex[bPort] !== undefined ? String(bpToIfIndex[bPort]) : bPort;
                return ifNames[ifIdx] ? String(ifNames[ifIdx]).replace('"', '').replace('\n', ' ').trim() : `Port ${ifIdx}`;
            }
        }
    }
    return null;
}

// ==========================================
// 💡 匯出引擎 (HTML空白修復 / SVG / PNG / 完美還原 PDF)
// ==========================================
function exportHTML() {
    if (!network || !nodesDataSet) return;
    if (typeof showToast === 'function') showToast("🌐 正在封裝互動式圖表，請稍候...", "info");
    window.logFrontendAction("前端介面操作", "匯出拓樸資料", "管理員執行了【匯出 HTML (離線互動版)】，下載當前全網拓樸架構報表。");
    
    var positions = network.getPositions();
    var exportNodes = nodesDataSet.get().map(n => {
        let nCopy = Object.assign({}, n);
        if (positions[n.id]) { nCopy.x = positions[n.id].x; nCopy.y = positions[n.id].y; }
        return nCopy;
    });
    var exportEdges = edgesDataSet.get();

    // 🌟 修復 HTML 空白：安全字串轉換，防止 JSON 內的引號與標籤截斷 HTML
    var safeNodes = JSON.stringify(exportNodes).replace(/</g, '\\u003c');
    var safeEdges = JSON.stringify(exportEdges).replace(/</g, '\\u003c');
    var bgColor = isDarkMode ? '#1f293a' : '#ffffff';
    var fontColor = isDarkMode ? '#ffffff' : '#000000';

    var htmlContent = `<!DOCTYPE html>
<html><head>
<meta charset="utf-8"><title>網路拓樸圖 - 離線互動版</title>
<script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"><\/script>
<style>body,html{margin:0;padding:0;width:100%;height:100%;background-color:${bgColor};overflow:hidden;} #mynetwork{width:100vw;height:100vh;outline:none;}</style>
</head><body><div id="mynetwork"></div>
<script>
    var nodes = new vis.DataSet(${safeNodes});
    var edges = new vis.DataSet(${safeEdges});
    var container = document.getElementById('mynetwork');
    var data = { nodes: nodes, edges: edges };
    var options = {
        physics: { enabled: false }, // 🌟 關閉物理引擎，防止節點亂飛導致畫面空白
        edges: { smooth: { type: 'cubicBezier', forceDirection: 'vertical', roundness: 0.5 }, width: 2 },
        nodes: { shape: 'box', margin: 5, font: { face: '"Microsoft JhengHei", Arial', size: 14, bold: true, color: '${fontColor}' } },
        interaction: { dragNodes: true, hover: true, navigationButtons: true }
    };
    new vis.Network(container, data, options);
<\/script>
</body></html>`;

    var blob = new Blob([htmlContent], { type: "text/html;charset=utf-8" });
    var url = window.URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url; a.download = `Topology_Export_${new Date().toISOString().slice(0,10)}.html`;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
}

function getHighResImageData(callback) {
    var container = document.getElementById('mynetwork');
    var oldWidth = container.style.width;
    var oldHeight = container.style.height;

    var oldGrid = isGridVisible; var oldFlow = isShowFlow;
    isGridVisible = false; isShowFlow = false;

    container.style.width = '3840px'; container.style.height = '2160px';
    network.redraw(); network.fit(); 

    setTimeout(() => {
        try {
            var canvas = container.getElementsByTagName("canvas")[0];
            var dataURL = canvas.toDataURL("image/png", 1.0);

            container.style.width = oldWidth || '100%'; container.style.height = oldHeight || 'calc(100vh - 130px)';
            isGridVisible = oldGrid; isShowFlow = oldFlow;
            network.redraw(); network.fit();

            callback(dataURL);
        } catch (e) {
            console.error(e);
            container.style.width = oldWidth || '100%'; container.style.height = oldHeight || 'calc(100vh - 130px)';
            network.redraw(); network.fit();
        }
    }, 1000); 
}

function exportPNG() {
    if (!network) return;
    if (typeof showToast === 'function') showToast("📸 正在渲染 4K 超高畫質圖片，請稍候...", "info");
    window.logFrontendAction("前端介面操作", "匯出拓樸資料", "管理員執行了【匯出 4K 高畫質 PNG】圖檔功能。");

    getHighResImageData(function(dataURL) {
        var link = document.createElement("a");
        link.download = `Topology_4K_${new Date().toISOString().slice(0,10)}.png`;
        link.href = dataURL; link.click();
        if (typeof showToast === 'function') showToast("✅ 4K 高畫質 PNG 已成功下載！", "success");
    });
}

// ==========================================
// 🌟 產出 4K PDF 報表 (正宗回歸：前端動態生成獨立報告分頁 + 呼叫原生 window.print())
// ==========================================
function exportPDF() {
    if (!network || !nodesDataSet || !edgesDataSet) return;
    if (typeof showToast === 'function') showToast("📄 正在擷取 4K 拓樸快照並編排資產數據，請稍候...", "info");
    
    // 🎤 資安稽核埋點：完整記錄
    if (typeof window.logFrontendAction === 'function') {
        window.logFrontendAction(
            "前端介面操作", 
            "匯出拓樸資料", 
            "管理員執行了【產出 PDF 資安稽核報表】功能，系統正在開啟獨立稽核報告分頁。"
        );
    }

    // 🚀 1. 呼叫全網最穩定的 4K 高畫質擷取引擎，獲取 100% 成功的拓樸圖 Base64 快照
    getHighResImageData(function(dataURL) {
        try {
            // 2. 繞過後台錯亂的路由，直接開一個全新的乾淨瀏覽器空白分頁
            var reportWindow = window.open("", "_blank");
            if (!reportWindow) {
                if (typeof showToast === 'function') showToast("⚠️ 彈出式視窗被瀏覽器封鎖，請允許快顯視窗。", "danger");
                return;
            }

            // 3. 讀取即時數據，組裝設備資產清單明細表格
            let nodeRows = '';
            let sortedNodes = nodesDataSet.get().sort((a, b) => {
                return String(a.ip).localeCompare(String(b.ip), undefined, {numeric: true, sensitivity: 'base'});
            });
            sortedNodes.forEach(n => {
                nodeRows += `<tr>
                    <td><strong>${n.ip}</strong></td>
                    <td>${n.sysName || ''}</td>
                    <td>${n.brand || ''}</td>
                    <td>${n.model || ''}</td>
                    <td class="text-center">L${n.level || '-'}</td>
                    <td>${n.location || ''}</td>
                </tr>`;
            });

            // 4. 組裝實體線路對接紀錄表格
            let edgeRows = '';
            edgesDataSet.get().forEach(e => {
                let speedStr = e.speed >= 10000 ? (e.speed/1000)+'G' : (e.speed >= 1000 ? (e.speed/1000)+'G' : e.speed+'M');
                edgeRows += `<tr>
                    <td>${e.from} <span class="text-secondary">(${e.from_port || ''})</span></td>
                    <td class="text-center fw-bold text-success">${speedStr}</td>
                    <td>${e.to} <span class="text-secondary">(${e.to_port || ''})</span></td>
                </tr>`;
            });

            let nowStr = new Date().toLocaleString('zh-TW', {hour12: false});

            // 5. 100% 還原您最原始的 report.html 排版架構與 A4 橫向列印樣式
            var reportHtmlContent = `<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <title>網路拓樸與資產稽核報告</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { font-family: "Microsoft JhengHei", Arial, sans-serif; background-color: #f8f9fa; color: #333; padding: 20px; }
        .page-container {
            max-width: 297mm; margin: 0 auto; background: white;
            padding: 20mm 15mm; box-shadow: 0 0 10px rgba(0,0,0,0.1); border-radius: 8px;
        }
        .report-header { border-bottom: 3px solid #2c3e50; padding-bottom: 10px; margin-bottom: 20px; }
        .report-header h2 { color: #2c3e50; font-weight: bold; margin: 0; }
        .timestamp { color: #7f8c8d; font-size: 0.95rem; margin-top: 5px; }
        
        .section-title { font-size: 1.2rem; font-weight: bold; color: #2980b9; margin-top: 30px; margin-bottom: 15px; border-left: 4px solid #2980b9; padding-left: 10px; }
        
        #topo-image { width: 100%; max-height: 550px; object-fit: contain; border: 1px solid #dee2e6; border-radius: 5px; margin-bottom: 20px; }
        
        .table th { background-color: #2c3e50 !important; color: white !important; font-size: 0.85rem; padding: 8px; }
        .table td { font-size: 0.85rem; padding: 8px; vertical-align: middle; }
        
        @media print {
            body { background: white; margin: 0; padding: 0; font-size: 10pt; }
            .page-container { box-shadow: none; padding: 0; width: 100%; max-width: none; }
            @page { size: A4 landscape; margin: 15mm; } 
            #topo-image { max-width: 100%; max-height: 140mm; object-fit: contain; page-break-inside: avoid; border: none; }
            .section-title { page-break-after: avoid; }
            table { page-break-inside: auto; }
            tr { page-break-inside: avoid; page-break-after: auto; }
        }
    </style>
</head>
<body>

<div class="page-container">
    <div class="report-header">
        <h2>網路拓樸與資產稽核報告</h2>
        <div class="timestamp">報表生成時間：${nowStr}</div>
    </div>

    <div class="section-title">一、 實體架構拓樸圖 (4K 高畫質擷取)</div>
    <div class="text-center">
        <img id="topo-image" src="${dataURL}" alt="拓樸圖載入中...">
    </div>

    <div class="section-title" style="page-break-before: always;">二、 網路設備資產明細清單</div>
    <table class="table table-bordered table-sm">
        <thead>
            <tr>
                <th width="15%">IP 位址</th>
                <th width="20%">設備名稱</th>
                <th width="15%">廠牌</th>
                <th width="20%">型號</th>
                <th width="10%" class="text-center">層級</th>
                <th width="20%">所在位置</th>
            </tr>
        </thead>
        <tbody>${nodeRows}</tbody>
    </table>

    <div class="section-title">三、 實體線路對接紀錄</div>
    <table class="table table-bordered table-sm table-striped">
        <thead>
            <tr>
                <th width="38%">本機端設備 (Port)</th>
                <th width="14%" class="text-center">協定速率</th>
                <th width="48%">遠端對接設備 (Port)</th>
            </tr>
        </thead>
        <tbody>${edgeRows}</tbody>
    </table>
</div>

<script>
    // 💡 關鍵保險：讓瀏覽器在「看得見」的新分頁中，等 4K 圖檔完全載入完畢，立刻彈出原生列印對話框！
    var img = document.getElementById('topo-image');
    function doPrint() {
        setTimeout(function() {
            window.print();
        }, 500);
    }
    if (img.complete) {
        doPrint();
    } else {
        img.onload = doPrint;
    }
<\/script>
</body>
</html>`;

            // 6. 將完美的網頁內容直接打入新分頁中渲染
            reportWindow.document.open();
            reportWindow.document.write(reportHtmlContent);
            reportWindow.document.close();

            if (typeof showToast === 'function') showToast("✅ PDF 稽核資產報表分頁已成功開啟！", "success");
        } catch (e) {
            console.error("報表產生失敗:", e);
        }
    });
}

function exportSVG() {
    if (!network || !nodesDataSet) return;
    if (typeof showToast === 'function') showToast("📐 正在計算向量節點座標，請稍候...", "info");
    window.logFrontendAction("前端介面操作", "匯出拓樸資料", "管理員執行了【匯出純淨向量 SVG】圖檔功能。");
    
    var pos = network.getPositions();
    var minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    
    for (var id in pos) {
        if (pos[id].x < minX) minX = pos[id].x; if (pos[id].x > maxX) maxX = pos[id].x;
        if (pos[id].y < minY) minY = pos[id].y; if (pos[id].y > maxY) maxY = pos[id].y;
    }
    
    var padding = 200; minX -= padding; minY -= padding;
    var width = maxX - minX + padding * 2; var height = maxY - minY + padding * 2;
    var bgColor = isDarkMode ? '#1f293a' : '#ffffff';
    
    var svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="${minX} ${minY} ${width} ${height}">`;
    svg += `<rect x="${minX}" y="${minY}" width="${width}" height="${height}" fill="${bgColor}" />`;
    
    edgesDataSet.get().forEach(e => {
        var p1 = pos[e.from]; var p2 = pos[e.to];
        if (p1 && p2) {
            var color = e.color ? (e.color.color || e.color) : '#6c757d';
            var strokeWidth = e.width || 2;
            var dash = (e.dashes && Array.isArray(e.dashes)) ? `stroke-dasharray="${e.dashes.join(',')}"` : '';
            var cx = p1.x, cy = p1.y + (p2.y - p1.y) * 0.5;
            var dx = p2.x, dy = p1.y + (p2.y - p1.y) * 0.5;
            svg += `<path d="M ${p1.x} ${p1.y} C ${cx} ${cy}, ${dx} ${dy}, ${p2.x} ${p2.y}" fill="transparent" stroke="${color}" stroke-width="${strokeWidth}" ${dash} />`;
        }
    });
    
    nodesDataSet.get().forEach(n => {
        var p = pos[n.id];
        if (p) {
            var lines = n.label.split('\n'); var maxW = 0;
            lines.forEach(l => { var w = l.length * 10; if (w > maxW) maxW = w; });
            var boxW = n._lastW || (maxW + 20); var boxH = n._lastH || (lines.length * 16 + 10);
            var rx = p.x - boxW / 2; var ry = p.y - boxH / 2;
            var fill = n.color ? (n.color.background || '#e0e0e0') : '#e0e0e0';
            var stroke = n.color ? (n.color.border || '#6c757d') : '#6c757d';
            var textColor = n.font ? (n.font.color || '#111') : '#111';
            
            svg += `<rect x="${rx}" y="${ry}" width="${boxW}" height="${boxH}" rx="5" ry="5" fill="${fill}" stroke="${stroke}" stroke-width="2" />`;
            
            var ty = ry + 16;
            lines.forEach(l => {
                let cleanL = l.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
                svg += `<text x="${p.x}" y="${ty}" font-family="Microsoft JhengHei, Arial, sans-serif" font-size="14px" font-weight="bold" fill="${textColor}" text-anchor="middle">${cleanL}</text>`;
                ty += 16;
            });
        }
    });
    
    svg += `</svg>`;
    var blob = new Blob([svg], { type: "image/svg+xml;charset=utf-8" });
    var url = window.URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url; a.download = `Topology_${new Date().toISOString().slice(0,10)}.svg`;
    document.body.appendChild(a); a.click(); document.body.removeChild(a); window.URL.revokeObjectURL(url);
}

// ==========================================
// 💡 網格背景產生器
// ==========================================
function createGridPattern(isDark) { 
    var c = document.createElement('canvas'); 
    c.width = GRID_SIZE; 
    c.height = GRID_SIZE; 
    var ctx = c.getContext('2d'); 
    ctx.fillStyle = isDark ? "rgba(255, 255, 255, 0.15)" : "rgba(0, 0, 0, 0.15)"; 
    ctx.fillRect(4, 4, 2, 2); 
    return c; 
}
var patternLight = createGridPattern(false); 
var patternDark = createGridPattern(true);

function getLinkColor(speed, isDark) { 
    let theme = isDark ? TOPO_COLORS.dark : TOPO_COLORS.light;
    if (speed >= 10000) return theme.link10G; 
    if (speed >= 1000) return theme.link1G; 
    return theme.link100M; 
}

// ==========================================
// 💡 【核心】繪製拓樸圖
// ==========================================
function renderGraph(forceHierarchical = null) {
    if (!cachedTopologyData || cachedTopologyData.nodes.length === 0) return;
    if (network !== null) { network.destroy(); }

    var mappedEdges = cachedTopologyData.edges.map(e => {
        let newEdge = Object.assign({}, e);
        var fromNode = cachedTopologyData.nodes.find(node => node.id === e.from);
        var toNode = cachedTopologyData.nodes.find(node => node.id === e.to);
        var isEdgeDown = (fromNode && fromNode.status === 'down') || (toNode && toNode.status === 'down');
        var isEdgeWarning = !isEdgeDown && ((fromNode && fromNode.status === 'warning') || (toNode && toNode.status === 'warning'));
        
        let theme = isDarkMode ? TOPO_COLORS.dark : TOPO_COLORS.light;
        var baseColor = getLinkColor(e.speed || 1000, isDarkMode);

        if (isEdgeDown) baseColor = theme.down;
        else if (isEdgeWarning) baseColor = theme.warning;

        newEdge.color = { color: baseColor, highlight: theme.highlight };
        if (isEdgeDown) newEdge.dashes = [5, 5]; 
        else if (isEdgeWarning) newEdge.dashes = [10, 5]; 
        delete newEdge.arrows; 
        return newEdge;
    });

    var mappedNodes = cachedTopologyData.nodes.map(n => Object.assign({}, n));

    nodesDataSet = new vis.DataSet(mappedNodes);
    edgesDataSet = new vis.DataSet(mappedEdges); 
    
    var container = document.getElementById('mynetwork');
    var visData = { nodes: nodesDataSet, edges: edgesDataSet };
    
    var hasSavedPositions = cachedTopologyData.nodes.some(n => n.x != null && n.y != null);
    if (forceHierarchical === true) hasSavedPositions = false; 
    if (forceHierarchical === false) hasSavedPositions = true; 

    var options = {
        layout: { 
            hierarchical: hasSavedPositions ? false : { 
                direction: 'UD', sortMethod: 'directed', levelSeparation: LEVEL_HEIGHT, 
                nodeSpacing: 350, treeSpacing: 500, parentCentralization: true 
            } 
        },
        physics: { enabled: false },
        edges: { smooth: { type: 'cubicBezier', forceDirection: 'vertical', roundness: 0.5 }, arrows: { to: { enabled: true, scaleFactor: 0.6 }, from: { enabled: true, scaleFactor: 0.6 } }, width: 2 },
        nodes: { shape: 'box', margin: { top: 3, right: 3, bottom: 3, left: 3 } }, 
        interaction: { dragNodes: true, hover: true, multiselect: true }
    };
    
    network = new vis.Network(container, visData, options);
    updateAllLabels(); 

    network.on("afterDrawing", function(ctx) {
        if (isGridVisible) {
            var viewPos = network.getViewPosition(); 
            var scale = network.getScale();
            var clientWidth = network.canvas.frame.canvas.clientWidth; 
            var clientHeight = network.canvas.frame.canvas.clientHeight;
            var worldWidth = clientWidth / scale; 
            var worldHeight = clientHeight / scale;
            var startX = viewPos.x - worldWidth / 2; 
            var startY = viewPos.y - worldHeight / 2;
            var pattern = ctx.createPattern(isDarkMode ? patternDark : patternLight, 'repeat');
            ctx.save(); 
            ctx.globalCompositeOperation = "destination-over"; 
            ctx.fillStyle = pattern; 
            ctx.fillRect(startX, startY, worldWidth, worldHeight); 
            ctx.restore();
        }

        if (isShowNodeTraffic) {
            ctx.save(); ctx.textAlign = 'left'; ctx.textBaseline = 'top';
            var pos = network.getPositions();
            
            cachedTopologyData.nodes.forEach(n => {
                let p = pos[n.id];
                if (p && nodeTrafficData[n.ip]) {
                    let myLvl = parseInt(n.level);
                    let edgePorts = new Set(), uplinkPorts = new Set(), downlinkPorts = new Set();
                    cachedTopologyData.edges.forEach(e => {
                        if (e.from === n.id || e.to === n.id) {
                            let peerId = (e.from === n.id) ? e.to : e.from;
                            let myPortStr = (e.from === n.id) ? e.from_port : e.to_port;
                            let peerNode = cachedTopologyData.nodes.find(peer => peer.id === peerId);
                            if (myPortStr) {
                                myPortStr.split(',').forEach(pt => {
                                    let cleanPt = String(pt).replace('"', '').replace('\n', ' ').trim().toLowerCase();
                                    edgePorts.add(cleanPt);
                                    if (peerNode && parseInt(peerNode.level) < myLvl) uplinkPorts.add(cleanPt);
                                    if (peerNode && parseInt(peerNode.level) > myLvl) downlinkPorts.add(cleanPt);
                                });
                            }
                        }
                    });
                    
                    let txBps = 0, rxBps = 0, downTxBps = 0, downRxBps = 0;
                    let portData = nodeTrafficData[n.ip];
                    let rawData = {}; try { rawData = JSON.parse(n.snmp_raw || "{}"); } catch(e){}
                    let ifNames = rawData[4] || {};
                    let extractNum = function(str) { let m = str.match(/\d+(\/\d+)*/g); return m ? m[m.length - 1] : ""; };

                    // 💡 [新增] 準備 Fallback 變數，用於記錄該設備流量最大的實體埠
                    let maxPortTx = 0, maxPortRx = 0, maxPortTotal = 0;

                    for (let pIdx in portData) {
                        let portName = ifNames[pIdx] ? String(ifNames[pIdx]).replace('"', '').replace('\n', ' ').trim().toLowerCase() : `port ${pIdx}`;
                        let pNum = extractNum(portName);
                        let isTarget = false, isDownlink = false;
                        
                        // 判斷是否為虛擬/邏輯埠 (過濾掉 vlan, loopback, cpu, mgmt 等)
                        let isLogical = portName.includes('vlan') || portName.includes('loop') || portName.includes('tun') || portName.includes('null') || portName.includes('cpu') || portName.includes('mgmt');
                        
                        downlinkPorts.forEach(dp => {
                            if (portName === dp || portName.includes(dp) || dp.includes(portName)) isDownlink = true;
                            let dpNum = extractNum(dp); if (pNum !== "" && dpNum !== "" && pNum === dpNum) isDownlink = true;
                        });

                        if (myLvl === 1) {
                            if (!isDownlink && !isLogical) isTarget = true;
                        } else {
                            let targetPorts = uplinkPorts.size > 0 ? uplinkPorts : edgePorts;
                            targetPorts.forEach(tp => {
                                if (portName === tp || portName.includes(tp) || tp.includes(portName)) isTarget = true;
                                let tpNum = extractNum(tp); if (pNum !== "" && tpNum !== "" && pNum === tpNum) isTarget = true;
                            });
                        }
                        
                        if (isTarget) { txBps += portData[pIdx].out_bps; rxBps += portData[pIdx].in_bps; }
                        if (isDownlink) { downTxBps += portData[pIdx].out_bps; downRxBps += portData[pIdx].in_bps; }
                        
                        // 💡 [新增] 紀錄單一實體埠的最大流量 (防呆 Fallback)
                        if (!isLogical) {
                            let pTotal = portData[pIdx].out_bps + portData[pIdx].in_bps;
                            if (pTotal > maxPortTotal) {
                                maxPortTotal = pTotal;
                                maxPortTx = portData[pIdx].out_bps;
                                maxPortRx = portData[pIdx].in_bps;
                            }
                        }
                    }

                    // 💡 [終極防呆補償] 
                    // 如果是 L2~L6 設備，但因為 LLDP 未知埠口 (例如 Fortinet 沒給 Port 名稱) 導致匹配失敗 (流量為0)，
                    // 我們就自動抓取該設備「流量最大」的那個實體孔 (通常就是 Uplink 骨幹) 作為標籤代表！
                    if (myLvl !== 1 && txBps === 0 && rxBps === 0 && maxPortTotal > 0) {
                        txBps = maxPortTx;
                        rxBps = maxPortRx;
                    }

                    let drawBox = (inVal, outVal, position) => {
                        let strIn = `▼ IN: ${formatBps(inVal)}`; let strOut = `▲ OUT: ${formatBps(outVal)}`;
                        ctx.font = 'bold 11px "Microsoft JhengHei", Arial, sans-serif';
                        let maxW = Math.max(ctx.measureText(strIn).width, ctx.measureText(strOut).width);
                        let w = n._lastW || 150; let h = n._lastH || 60;
                        let boxX = p.x; let boxY = (position === 'top') ? (p.y - h/2 - 45) : (p.y + h/2 + 10);
                        
                        ctx.fillStyle = 'rgba(0, 0, 0, 0.75)'; ctx.beginPath(); ctx.rect(boxX - maxW/2 - 8, boxY, maxW + 16, 34); ctx.fill();
                        ctx.strokeStyle = '#444'; ctx.lineWidth = 1; ctx.stroke();
                        ctx.fillStyle = '#20c997'; ctx.fillText(strIn, boxX - maxW/2, boxY + 4);
                        ctx.fillStyle = '#0dcaf0'; ctx.fillText(strOut, boxX - maxW/2, boxY + 18);
                    };

                    if (myLvl === 1) {
                        if (txBps > 0 || rxBps > 0) drawBox(rxBps, txBps, 'top');
                        if (downTxBps > 0 || downRxBps > 0) drawBox(downRxBps, downTxBps, 'bottom'); 
                    } else {
                        if (txBps > 0 || rxBps > 0) drawBox(rxBps, txBps, 'bottom');
                    }
                }
            });
            ctx.restore();
        }

        if (!isShowFlow) return;
        var pos = network.getPositions();
        ctx.save();
        edgesDataSet.get().forEach(e => {
            var p0 = pos[e.from]; var p3 = pos[e.to]; 
            if (!p0 || !p3) return;
            var fromNode = cachedTopologyData.nodes.find(node => node.id === e.from);
            var toNode = cachedTopologyData.nodes.find(node => node.id === e.to);
            if ((fromNode && fromNode.status === 'down') || (toNode && toNode.status === 'down')) return;
            var p1 = { x: p0.x, y: p0.y + (p3.y - p0.y) * 0.5 }; var p2 = { x: p3.x, y: p0.y + (p3.y - p0.y) * 0.5 };
            var dotColor = e.color && e.color.color ? e.color.color : '#007bff';
            for (var i = 0; i < 3; i++) {
                var cycle = (flowAnimationTime + i * 0.333) % 2; 
                var t = 0.18 + ((cycle < 1 ? cycle : 2 - cycle) * 0.64);
                var pt = getBezierPoint(t, p0, p1, p2, p3);
                ctx.beginPath(); ctx.arc(pt.x, pt.y, 3.5, 0, 2 * Math.PI); ctx.fillStyle = dotColor; ctx.shadowColor = dotColor; ctx.shadowBlur = 6; ctx.fill();
            }
        });
        ctx.restore();
    });

    if (!hasSavedPositions) {
        network.once("afterDrawing", function() {
            setTimeout(() => {
                var pos = network.getPositions(); var updates = [];
                for (var id in pos) { updates.push({id: id, x: pos[id].x, y: pos[id].y}); }
                nodesDataSet.update(updates); network.setOptions({ layout: { hierarchical: { enabled: false } } }); 
            }, 300);
        });
    }

    network.on("dragEnd", function (params) {
        if (params.nodes.length > 0) {
            var positions = network.getPositions(params.nodes);
            params.nodes.forEach(nodeId => {
                var currentPos = positions[nodeId]; if (!currentPos) return;
                var snappedX = Math.round(currentPos.x / GRID_SIZE) * GRID_SIZE;
                var snappedY = Math.round(currentPos.y / LEVEL_HEIGHT) * LEVEL_HEIGHT; 
                network.moveNode(nodeId, snappedX, snappedY);
                var node = cachedTopologyData.nodes.find(n => n.id === nodeId);
                if(node) { node.x = snappedX; node.y = snappedY; }
            });
        }
    });

    if(typeof bindLeftClickEvent === 'function') bindLeftClickEvent();
    if(typeof bindRightClickEvent === 'function') bindRightClickEvent();
} 

function buildNodeLabel(node) { 
    var parts = []; parts.push(node.brand || 'Unknown'); 
    if (node.model) parts.push(node.model); 
    if (isShowIP && node.ip) parts.push(`(${node.ip})`); 
    if (isShowName && node.sysName) parts.push(`[${node.sysName}]`); 
    if (isShowLocation) parts.push(`📍 ${node.location ? node.location.trim() : '未設定'}`); 
    if (node.status === 'down') parts.push('🔴 徹底斷線'); else if (node.status === 'warning') parts.push('⚠️ SNMP異常'); 
    return parts.join('\n'); 
}

function updateAllLabels() {
    if (!nodesDataSet || !cachedTopologyData) return;
    var dummyCanvas = document.createElement('canvas'); var ctx = dummyCanvas.getContext('2d'); 
    ctx.font = 'bold 14px "Microsoft JhengHei", Arial, sans-serif';
    var positions = network ? network.getPositions() : {}; var updates = [];
    
    cachedTopologyData.nodes.forEach(n => { 
        let isDown = n.status === 'down'; let isWarning = n.status === 'warning'; 
        let bgColor = isDown ? '#dc3545' : (isWarning ? '#ffe066' : (n.color || '#e0e0e0')); let fColor = isDown ? '#ffffff' : '#111111';
        let labelText = buildNodeLabel(n); let lines = labelText.split('\n'); let maxTextW = 0;
        
        lines.forEach(l => { let m = ctx.measureText(l); if(m.width > maxTextW) maxTextW = m.width; });
        let rawW = maxTextW + 10; let rawH = lines.length * 16 + 10; 
        let w10 = Math.ceil(rawW / 10) * 10; let h10 = Math.ceil(rawH / 10) * 10;
        
        let nodeUpdate = { 
            id: n.id, label: labelText, 
            color: { background: bgColor, border: isDown ? '#842029' : (isWarning ? '#cca300' : '#6c757d'), highlight: { background: bgColor, border: '#000000' } }, 
            font: { color: fColor, face: '"Microsoft JhengHei", Arial, sans-serif', size: 14, bold: true, align: 'center' }, 
            widthConstraint: { minimum: w10, maximum: w10 }, heightConstraint: { minimum: h10, valign: 'middle' }, shape: 'box' 
        }; 
        
        if (network && positions[n.id]) { 
            let currentPos = positions[n.id]; let oldW = n._lastW; let oldH = n._lastH; 
            if (oldW && oldH && (oldW !== w10 || oldH !== h10)) { 
                let newX = currentPos.x + (w10 - oldW) / 2; let newY = currentPos.y + (h10 - oldH) / 2; 
                n.x = newX; n.y = newY; nodeUpdate.x = newX; nodeUpdate.y = newY; 
            } 
        }
        n._lastW = w10; n._lastH = h10; updates.push(nodeUpdate);
    });
    nodesDataSet.update(updates);
}

function alignNodes() {
    window.logFrontendAction("前端介面操作", "變更拓樸版面", "管理員執行了【強制依層級對齊Y軸】功能，重新整理了畫面節點。");
    if (!network || !cachedTopologyData || cachedTopologyData.nodes.length === 0) return;
    var positions = network.getPositions(); var updates = []; 
    var minLevel = Math.min(...cachedTopologyData.nodes.map(n => parseInt(n.level)));
    var topLevelNodes = cachedTopologyData.nodes.filter(n => parseInt(n.level) === minLevel); var baseY = 0;
    
    if (topLevelNodes.length > 0 && positions[topLevelNodes[0].id]) { 
        var refY = positions[topLevelNodes[0].id].y; 
        baseY = refY - ((minLevel - 1) * LEVEL_HEIGHT); baseY = Math.round(baseY / LEVEL_HEIGHT) * LEVEL_HEIGHT; 
    }
    
    cachedTopologyData.nodes.forEach(n => { 
        if (positions[n.id]) { 
            var lvl = parseInt(n.level) || 3; var targetY = baseY + ((lvl - 1) * LEVEL_HEIGHT); var targetX = Math.round(positions[n.id].x / GRID_SIZE) * GRID_SIZE; 
            updates.push({ id: n.id, x: targetX, y: targetY }); n.x = targetX; n.y = targetY; 
        } 
    });
    
    nodesDataSet.update(updates); updates.forEach(u => network.moveNode(u.id, u.x, u.y)); 
    if (typeof showToast === 'function') showToast("✅ 已依據設備層級完美對齊 Y 軸！", "success");
}

function getBezierPoint(t, p0, p1, p2, p3) { 
    var cx = 3 * (p1.x - p0.x); var bx = 3 * (p2.x - p1.x) - cx; var ax = p3.x - p0.x - cx - bx; 
    var cy = 3 * (p1.y - p0.y); var by = 3 * (p2.y - p1.y) - cy; var ay = p3.y - p0.y - cy - by; 
    var tSquared = t * t; var tCubed = tSquared * t; 
    return { x: (ax * tCubed) + (bx * tSquared) + (cx * t) + p0.x, y: (ay * tCubed) + (by * tSquared) + (cy * t) + p0.y }; 
}

function startFlowAnimation() { 
    if (animationId) { cancelAnimationFrame(animationId); animationId = null; } 
    function animate() { flowAnimationTime += 0.015; if (isShowFlow && network) { network.redraw(); } animationId = requestAnimationFrame(animate); } 
    animate(); 
}

function startDynamicEdges() {
    function updateEdgeColors() {
        if (typeof edgesDataSet === 'undefined' || typeof nodesDataSet === 'undefined') return;
        fetch('/api/traffic_summary').then(res => res.json()).then(data => {
            if (!data.success) return;
            let traffic = data.data; let edgesToUpdate = [];
            edgesDataSet.forEach(edge => {
                let fromNode = nodesDataSet.get(edge.from); let toNode = nodesDataSet.get(edge.to);
                if (!fromNode || !toNode) return;
                let getBps = (node, portNamesStr) => {
                    if (!node || !traffic[node.ip]) return 0;
                    let bps = 0;
                    try {
                        let raw = JSON.parse(node.snmp_raw); let ifNames = raw[4] || {}; let pNames = portNamesStr.split(',').map(s => s.trim().toLowerCase());
                        Object.keys(ifNames).forEach(idx => {
                            let name = ifNames[idx].replace(/"/g, '').toLowerCase();
                            if (pNames.includes(name)) { let t = traffic[node.ip][idx]; if (t) bps += Math.max(t.in_bps, t.out_bps); }
                        });
                    } catch(e) {}
                    return bps;
                };
                let maxBps = Math.max(getBps(fromNode, edge.from_port), getBps(toNode, edge.to_port));
                let speedMbps = edge.speed || 1000; let speedBps = speedMbps * 1000000; let util = maxBps / speedBps;
                let baseColor = getLinkColor(speedMbps, isDarkMode);
                let width = 2; let dashes = false; let finalColor = baseColor;

                if (util > 0.8) { finalColor = '#dc3545'; width = 6; dashes = [10, 5]; } 
                else if (util > 0.5) { width = 5; dashes = [5, 5]; } 
                else if (util > 0.1) { width = 3.5; } 
                else if (maxBps > 0) { width = 2; } 
                else { width = 1.5; }
                edgesToUpdate.push({ id: edge.id, color: { color: finalColor, highlight: finalColor, hover: finalColor }, width: width, dashes: dashes });
            });
            edgesDataSet.update(edgesToUpdate);
        });
    }
    setTimeout(updateEdgeColors, 2000); setInterval(updateEdgeColors, 30000);
}

document.addEventListener('keydown', function(e) {
    if (!network || !cachedTopologyData) return;
    var selectedNodes = network.getSelectedNodes();
    if (selectedNodes.length === 0) return;
    if (['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight'].includes(e.key)) {
        e.preventDefault(); var positions = network.getPositions(selectedNodes);
        selectedNodes.forEach(nodeId => {
            var pos = positions[nodeId]; if (!pos) return;
            var newX = pos.x; var newY = pos.y;
            if (e.key === 'ArrowUp') newY -= KEY_STEP_Y; else if (e.key === 'ArrowDown') newY += KEY_STEP_Y;
            else if (e.key === 'ArrowLeft') newX -= (e.shiftKey ? 50 : GRID_SIZE); else if (e.key === 'ArrowRight') newX += (e.shiftKey ? 50 : GRID_SIZE);
            network.moveNode(nodeId, newX, newY);
            var node = cachedTopologyData.nodes.find(n => n.id === nodeId); if (node) { node.x = newX; node.y = newY; }
        });
    }
});