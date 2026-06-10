/**
 * =========================================================
 * 全域共用工具庫 (utils.js)
 * =========================================================
 */

// 💡 1. 智慧解碼器：將 16 進位字串翻譯成 UTF-8 中文 (用在 Alias)
function decodeHexIfNeeded(str) {
    if (!str) return "";
    let clean = String(str).replace(/"/g, '').trim();
    if (/^([0-9a-fA-F]{2}:)+[0-9a-fA-F]{2}$/.test(clean)) {
        try {
            let bytes = new Uint8Array(clean.split(':').map(h => parseInt(h, 16)));
            let decoded = new TextDecoder('utf-8', {fatal: true}).decode(bytes);
            if (!/[\x00-\x08\x0B\x0C\x0E-\x1F]/.test(decoded)) return decoded;
        } catch(e) { }
    }
    return clean;
}

// 💡 2. 流量格式化工具：將 bps 自動轉為 Kbps, Mbps, Gbps
function formatBps(bits) {
    if (bits >= 1000000000) return (bits / 1000000000).toFixed(1) + ' Gbps';
    if (bits >= 1000000) return (bits / 1000000).toFixed(1) + ' Mbps';
    if (bits >= 1000) return (bits / 1000).toFixed(1) + ' Kbps';
    return bits + ' bps';
}

// 💡 3. 自訂時間選單切換器：控制隱藏/顯示自訂日期框
function toggleCustomTimeDiv(selectId, customDivId) {
    let val = document.getElementById(selectId).value;
    let div = document.getElementById(customDivId);
    if (!div) return;
    if (val === 'custom') {
        div.classList.replace('d-none', 'd-flex');
    } else {
        div.classList.replace('d-flex', 'd-none');
    }
}

// 💡 4. API 時間查詢字串產生器：自動防呆並組裝 Start/End
function buildTimeQueryString(selectId, startId, endId) {
    let range = document.getElementById(selectId).value;
    if (range === 'custom') {
        let start = document.getElementById(startId).value;
        let end = document.getElementById(endId).value;
        if (!start || !end) {
            alert("⚠️ 請完整選擇自訂的「開始」與「結束」時間！");
            return null; // 驗證失敗
        }
        return `range=custom&start=${start}&end=${end}`;
    }
    return `range=${range}`;
}

// 💡 5. 通用 PoE 瓦數解析工具：從 SNMP 字典抓取供電量
function getPoePowerForPort(rawData, targetPortIdx) {
    if (!rawData) return null;
    let maxPower = 0;
    
    [18, 19, 20].forEach(idx => {
        let dict = rawData[idx];
        if (dict) {
            Object.keys(dict).forEach(key => {
                let suffix = key.split('.').pop();
                if (suffix === String(targetPortIdx)) {
                    let mw = parseInt(dict[key]);
                    if (!isNaN(mw) && mw > 500 && mw < 95000 && mw !== 1500) {
                        let w = parseFloat((mw / 1000).toFixed(1));
                        if (w > maxPower) maxPower = w;
                    }
                }
            });
        }
    });

    let dlinkDict = rawData[21];
    if (dlinkDict) {
        Object.keys(dlinkDict).forEach(key => {
            let suffix = key.split('.').pop();
            if (suffix === String(targetPortIdx)) {
                let w = parseFloat(dlinkDict[key]);
                if (!isNaN(w) && w > 0.5 && w < 95.0) {
                    if (w > maxPower) maxPower = w;
                }
            }
        });
    }
    return maxPower > 0 ? maxPower : null;
}

// 💡 6. 字串清理工具：去除多餘引號與換行符號
function cleanStr(str) { 
    if(!str) return "";
    return String(str).replace(/"/g, '').replace(/<br\s*\/?>/gi, ' ').replace(/\n/g, ' ').replace(/\r/g, ' ').trim(); 
}

// 💡 7. 全域吐司訊息彈窗 (Toast)
function showToast(message, type = 'success') {
    const toastContainer = document.getElementById('toastPlacement');
    if (!toastContainer) return; // 防呆，若當前頁面沒有 toast 容器則不動作
    const toastId = 'toast-' + Date.now();
    let bgColor = type === 'danger' ? 'bg-danger' : (type === 'warning' ? 'bg-warning text-dark' : 'bg-success');
    let icon = type === 'danger' ? 'bi-x-circle-fill' : 'bi-check-circle-fill';
    if (type === 'warning') icon = 'bi-exclamation-triangle-fill';
    if (type === 'info') { bgColor = 'bg-info text-dark'; icon = 'bi-info-circle-fill'; }

    const toastHTML = `<div id="${toastId}" class="toast align-items-center text-white ${bgColor} border-0 mb-2 shadow-sm" role="alert"><div class="d-flex"><div class="toast-body fw-bold" style="font-size:0.9rem;"><i class="bi ${icon} me-2"></i>${message}</div><button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button></div></div>`;
    toastContainer.insertAdjacentHTML('beforeend', toastHTML);
    new bootstrap.Toast(document.getElementById(toastId)).show();
}