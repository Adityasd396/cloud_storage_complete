// Share Page Logic
let shareToken = null;
let shareData = null;

window.addEventListener('load', () => {
    // Extract token from URL path (e.g., /xxxxxxxxxxxxxxx)
    const path = window.location.pathname;
    shareToken = path.split('/').pop();

    if (!shareToken || shareToken === 'share.html') {
        // Fallback to query param for backward compatibility
        const urlParams = new URLSearchParams(window.location.search);
        shareToken = urlParams.get('token');
    }

    if (!shareToken) {
        showError('No share token provided');
        return;
    }

    loadShareInfo();
});

async function loadShareInfo(password = '') {
    showLoading(true);
    try {
        const response = await fetch(`${API_URL}/shares/info/${shareToken}`, {
            method: password ? 'POST' : 'GET',
            headers: {
                'Content-Type': 'application/json'
            },
            body: password ? JSON.stringify({ password }) : null
        });

        const data = await response.json();

        if (response.ok) {
            shareData = data;
            renderShareContent();
        } else if (response.status === 401 && data.password_required) {
            showPasswordSection();
            if (password) {
                showNotification(data.message, 'error');
            }
        } else {
            showError(data.message || 'Failed to load shared file');
        }
    } catch (error) {
        showError('An error occurred while loading the file');
        console.error('Error:', error);
    } finally {
        showLoading(false);
    }
}

function renderShareContent() {
    document.getElementById('passwordSection').style.display = 'none';
    document.getElementById('contentSection').style.display = 'block';
    document.getElementById('errorSection').style.display = 'none';

    document.getElementById('fileName').textContent = shareData.filename;
    document.getElementById('fileSize').textContent = formatFileSize(shareData.size);
    document.getElementById('fileType').textContent = shareData.type || 'Unknown';
    document.getElementById('fileDate').textContent = new Date(shareData.uploaded_at).toLocaleString();
    
    const expiresDate = new Date(shareData.expires_at);
    document.getElementById('fileExpires').textContent = expiresDate.toLocaleString();

    renderPreview();
}

function renderPreview() {
    const previewContainer = document.getElementById('previewContainer');
    const fileType = getFileType(shareData.filename);
    const downloadUrl = `${API_URL}/shares/download/${shareToken}`;
    const password = document.getElementById('sharePasswordInput').value;
    
    // Add password to preview URL if present
    const previewUrl = `${downloadUrl}?preview=true${password ? '&p=' + encodeURIComponent(password) : ''}`;
    
    console.log(`DEBUG: File Type: ${fileType}`);
    console.log(`DEBUG: Preview URL: ${previewUrl}`);
    console.log(`DEBUG: MIME Type: ${shareData.type}`);
    
    if (fileType === 'image') {
        previewContainer.innerHTML = `
            <div style="text-align: center; width: 100%;">
                <img id="previewImage" src="" 
                     style="max-width: 100%; max-height: 500px; object-fit: contain; display: none;" 
                     alt="${shareData.filename}">
                <div id="imageLoader">
                    <div class="loading-spinner"></div>
                    <p>Loading image...</p>
                </div>
            </div>
        `;
        
        fetchPreviewBlob(previewUrl, 'previewImage', 'imageLoader');
    } else if (fileType === 'video') {
        // Use direct URL for video streaming instead of blob fetching
        previewContainer.innerHTML = `
            <div style="text-align: center; width: 100%; background: #000; overflow: hidden; position: relative;">
                <video id="previewVideo" controls autoplay muted playsinline 
                       style="max-width: 100%; max-height: 600px; width: 100%; display: block; margin: 0 auto;" 
                       poster="">
                    <source src="${previewUrl}" type="${shareData.type || 'video/mp4'}">
                    Your browser does not support video playback.
                </video>
                <div id="videoError" style="display: none; position: absolute; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.8); color: white; flex-direction: column; justify-content: center; align-items: center; z-index: 10;">
                    <div style="font-size: 40px; margin-bottom: 10px;">❌</div>
                    <p>Video playback error. Try downloading the file instead.</p>
                </div>
            </div>
        `;
        
        const video = document.getElementById('previewVideo');
        video.onerror = (e) => {
            console.error('Video load error:', e);
            const errorDiv = document.getElementById('videoError');
            errorDiv.style.display = 'flex';
            // Also try to show a more descriptive message
            const p = errorDiv.querySelector('p');
            if (video.error) {
                switch (video.error.code) {
                    case 1: p.textContent = 'Playback aborted.'; break;
                    case 2: p.textContent = 'Network error.'; break;
                    case 3: p.textContent = 'Decoding error.'; break;
                    case 4: p.textContent = 'Video format not supported.'; break;
                }
            }
        };
    } else if (fileType === 'audio') {
        // Use direct URL for audio streaming
        previewContainer.innerHTML = `
            <div style="text-align: center; padding: 40px; width: 100%;">
                <div style="font-size: 48px; margin-bottom: 16px;">🎵</div>
                <audio id="previewAudio" controls style="width: 100%; max-width: 500px;">
                    <source src="${previewUrl}" type="${shareData.type || 'audio/mpeg'}">
                    Your browser does not support audio playback.
                </audio>
            </div>
        `;
    } else {
        previewContainer.innerHTML = `
            <div style="text-align: center; padding: 40px; color: var(--text-light);">
                <div class="preview-icon">${getFileIcon(shareData.filename)}</div>
                <p>Preview not available for this file type.</p>
            </div>
        `;
    }
}

async function fetchPreviewBlob(url, elementId, loaderId) {
    const password = document.getElementById('sharePasswordInput').value;
    
    try {
        const response = await fetch(url, {
            method: password ? 'POST' : 'GET',
            headers: {
                'Content-Type': 'application/json'
            },
            body: password ? JSON.stringify({ password }) : null
        });

        if (!response.ok) throw new Error('Failed to fetch preview');

        const blob = await response.blob();
        const blobUrl = URL.createObjectURL(blob);
        const element = document.getElementById(elementId);
        const loader = document.getElementById(loaderId);

        if (element.tagName === 'IMG') {
            element.onload = () => {
                loader.style.display = 'none';
                element.style.display = 'block';
            };
            element.src = blobUrl;
        } else {
            element.src = blobUrl;
            loader.style.display = 'none';
        }
    } catch (error) {
        console.error('Preview error:', error);
        document.getElementById('previewContainer').innerHTML = `
            <div style="text-align: center; padding: 40px; color: var(--text-light);">
                <div style="font-size: 48px; margin-bottom: 16px;">⚠️</div>
                <p>Failed to load preview</p>
            </div>
        `;
    }
}

async function downloadSharedFile() {
    const password = document.getElementById('sharePasswordInput').value;
    const downloadUrl = `${API_URL}/shares/download/${shareToken}`;

    try {
        if (password) {
            // ... (keep password logic)
            const response = await fetch(downloadUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ password })
            });

            if (!response.ok) {
                const data = await response.json();
                showNotification(data.message || 'Download failed', 'error');
                return;
            }

            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = shareData.filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
        } else {
            // FOR NON-PASSWORD FILES: Use a safer download method
            showNotification('Preparing download...', 'info');
            
            // First, do a quick HEAD request to see if the file exists and is accessible
            // This prevents "site unavailable" errors in a new tab if the server returns 404/500
            try {
                const checkResponse = await fetch(downloadUrl, { method: 'HEAD' });
                if (!checkResponse.ok) {
                    const errorMsg = checkResponse.status === 404 ? 'File not found on server' : 'Server error during download';
                    showNotification(errorMsg, 'error');
                    return;
                }
            } catch (e) {
                console.warn('Pre-download check failed, proceeding anyway:', e);
            }

            const a = document.createElement('a');
            a.href = downloadUrl;
            a.style.display = 'none';
            a.target = '_blank';
            a.download = shareData.filename;
            document.body.appendChild(a);
            a.click();
            
            setTimeout(() => {
                document.body.removeChild(a);
            }, 100);
        }
        showNotification('Download started', 'success');
    } catch (error) {
        console.error('Download error:', error);
        showNotification('Download error occurred', 'error');
    }
}

let countdownInterval = null;

function startDownloadCountdown() {
    const downloadBtn = document.getElementById('downloadBtn');
    const downloadBtnText = document.getElementById('downloadBtnText');
    const countdownDisplay = document.getElementById('countdownDisplay');
    
    if (countdownInterval) return;

    let timeLeft = 15;
    downloadBtn.disabled = true;
    downloadBtnText.textContent = 'Preparing Download...';
    countdownDisplay.style.display = 'inline-block';
    countdownDisplay.textContent = timeLeft;

    countdownInterval = setInterval(() => {
        timeLeft -= 1;
        countdownDisplay.textContent = timeLeft;

        if (timeLeft <= 0) {
            clearInterval(countdownInterval);
            countdownInterval = null;
            downloadBtn.disabled = false;
            downloadBtnText.textContent = '⬇️ Download File';
            countdownDisplay.style.display = 'none';
            downloadSharedFile();
        }
    }, 1000);
}

function verifyPassword() {
    const password = document.getElementById('sharePasswordInput').value;
    if (!password) {
        showNotification('Please enter a password', 'error');
        return;
    }
    loadShareInfo(password);
}

function showPasswordSection() {
    document.getElementById('passwordSection').style.display = 'block';
    document.getElementById('contentSection').style.display = 'none';
    document.getElementById('errorSection').style.display = 'none';
}

function showError(message) {
    document.getElementById('passwordSection').style.display = 'none';
    document.getElementById('contentSection').style.display = 'none';
    document.getElementById('errorSection').style.display = 'block';
    document.getElementById('errorMessage').textContent = message;
}

function showLoading(show) {
    document.getElementById('loadingState').style.display = show ? 'block' : 'none';
}
