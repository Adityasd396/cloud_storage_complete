// File Management Functions

function setupUploadArea() {
    const uploadArea = document.getElementById('uploadArea');
    const fileInput = document.getElementById('fileInput');
    
    uploadArea.addEventListener('click', () => fileInput.click());
    
    uploadArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadArea.classList.add('drag');
    });
    
    uploadArea.addEventListener('dragleave', () => {
        uploadArea.classList.remove('drag');
    });
    
    uploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadArea.classList.remove('drag');
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            fileInput.files = files;
            handleFileSelect({ target: { files: files } });
        }
    });
}

function handleFileSelect(event) {
    const files = event.target.files;
    if (files.length > 0) {
        const file = files[0];
        document.getElementById('uploadBtn').style.display = 'block';
        document.querySelector('.upload-text').innerHTML = `Selected: <strong>${file.name}</strong> (${formatFileSize(file.size)})`;
    }
}

async function uploadFile() {
    const fileInput = document.getElementById('fileInput');
    if (!fileInput.files.length) {
        showNotification('Please select a file', 'error');
        return;
    }

    const file = fileInput.files[0];
    const formData = new FormData();
    formData.append('file', file);
    
    // Add folder_id if we're in a folder
    if (currentFolderId) {
        formData.append('folder_id', currentFolderId);
    }

    const uploadBtn = document.getElementById('uploadBtn');
    const progressContainer = document.getElementById('progressContainer');
    const progressFill = document.getElementById('progressFill');
    const progressText = document.getElementById('progressText');

    uploadBtn.disabled = true;
    uploadBtn.textContent = 'Uploading...';
    progressContainer.style.display = 'block';

    try {
        const xhr = new XMLHttpRequest();
        
        // Progress tracking
        xhr.upload.addEventListener('progress', (e) => {
            if (e.lengthComputable) {
                const percentComplete = (e.loaded / e.total) * 100;
                progressFill.style.width = percentComplete + '%';
                progressText.textContent = `Uploading... ${Math.round(percentComplete)}%`;
            }
        });

        xhr.addEventListener('load', () => {
            if (xhr.status === 201) {
                showNotification('File uploaded successfully!', 'success');
                fileInput.value = '';
                uploadBtn.style.display = 'none';
                uploadBtn.textContent = 'Upload File';
                progressContainer.style.display = 'none';
                progressFill.style.width = '0%';
                document.querySelector('.upload-text').innerHTML = 'Drag and drop or <strong>click to browse</strong>';
                loadFiles();
                loadStats();
            } else {
                const response = JSON.parse(xhr.responseText);
                showNotification(response.message || 'Upload failed', 'error');
            }
            uploadBtn.disabled = false;
        });

        xhr.addEventListener('error', () => {
            showNotification('Upload error. Please try again.', 'error');
            uploadBtn.disabled = false;
            uploadBtn.textContent = 'Upload File';
            progressContainer.style.display = 'none';
        });

        xhr.open('POST', `${API_URL}/files/upload`);
        xhr.setRequestHeader('Authorization', `Bearer ${token}`);
        xhr.send(formData);
        
    } catch (error) {
        showNotification('Upload error. Please try again.', 'error');
        uploadBtn.disabled = false;
        uploadBtn.textContent = 'Upload File';
        progressContainer.style.display = 'none';
    }
}

async function loadFiles() {
    try {
        const response = await fetch(`${API_URL}/files?folder_id=${currentFolderId || ''}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        const data = await response.json();
        allFiles = data.files || [];
        
        renderFiles();
    } catch (error) {
        console.error('Error loading files:', error);
    }
}

function renderFiles() {
    const filesList = document.getElementById('filesList');
    const filteredFiles = filterFilesByType(allFiles);

    if (filteredFiles.length === 0) {
        filesList.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">📁</div>
                <p>${allFiles.length === 0 ? 'No files yet. Upload your first file!' : 'No files match the current filter.'}</p>
            </div>
        `;
        return;
    }

    filesList.innerHTML = filteredFiles.map(file => {
        const fileIcon = getFileIcon(file.filename);
        const uploadDate = new Date(file.uploaded_at).toLocaleDateString();
        
        return `
            <div class="file-item" data-filename="${file.filename.toLowerCase()}" data-type="${getFileType(file.filename)}">
                <div class="file-info">
                    <div class="file-icon">${fileIcon}</div>
                    <div class="file-details">
                        <div class="file-name">${file.filename}</div>
                        <div class="file-meta">${formatFileSize(file.size)} • ${uploadDate}</div>
                    </div>
                </div>
                <div class="file-actions">
                    <button class="icon-btn" onclick="openPreviewModal(${file.id}, '${file.filename.replace(/'/g, "\\'")}', '${file.type}')">Preview</button>
                    <button class="icon-btn" onclick="autoShareFile(${file.id})">Share</button>
                    <button class="icon-btn" onclick="downloadFile(${file.id}, '${file.filename.replace(/'/g, "\\'")}')">Download</button>
                    <button class="icon-btn" onclick="deleteFile(${file.id}, '${file.filename.replace(/'/g, "\\'")}')">Delete</button>
                </div>
            </div>
        `;
    }).join('');
}

function filterFilesByType(files) {
    if (currentFileTypeFilter === 'all') {
        return files;
    }
    return files.filter(file => getFileType(file.filename) === currentFileTypeFilter);
}

function filterByType(type) {
    currentFileTypeFilter = type;
    
    // Update active tab
    document.querySelectorAll('.file-type-tab').forEach(tab => {
        tab.classList.remove('active');
    });
    event.target.classList.add('active');
    
    renderFiles();
}

function filterFiles() {
    const query = document.getElementById('searchInput').value.toLowerCase();
    const items = document.querySelectorAll('.file-item');
    
    items.forEach(item => {
        const filename = item.dataset.filename;
        item.style.display = filename.includes(query) ? 'flex' : 'none';
    });
}

async function downloadFile(fileId, filename) {
    try {
        const response = await fetch(`${API_URL}/files/${fileId}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!response.ok) {
            showNotification('Download failed', 'error');
            return;
        }

        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
        showNotification('Download started', 'success');
    } catch (error) {
        showNotification('Download error', 'error');
    }
}

async function deleteFile(fileId, filename) {
    if (!confirm(`Are you sure you want to delete "${filename}"?`)) {
        return;
    }

    try {
        const response = await fetch(`${API_URL}/files/${fileId}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (response.ok) {
            showNotification('File deleted successfully', 'success');
            loadFiles();
            loadStats();
        } else {
            const data = await response.json();
            showNotification(data.message || 'Delete failed', 'error');
        }
    } catch (error) {
        showNotification('Delete error', 'error');
    }
}

function openPreviewModal(fileId, filename, mimeType) {
    const modal = document.getElementById('previewModal');
    const previewTitle = document.getElementById('previewTitle');
    const previewContent = document.getElementById('previewContent');
    
    modal.classList.add('active');
    previewTitle.textContent = filename;
    
    const fileType = getFileType(filename);
    const fileUrl = `${API_URL}/files/${fileId}`;
    
    // Create temporary token for preview (using existing auth)
    const authHeader = `Bearer ${token}`;
    
    if (fileType === 'image') {
        previewContent.innerHTML = `
            <div style="text-align: center;">
                <img id="previewImage" src="" 
                     style="max-width: 100%; max-height: 500px; object-fit: contain; display: none;" 
                     alt="${filename}">
                <div id="imageLoader">Loading image...</div>
            </div>
        `;
        
        // Fetch image with auth
        fetch(fileUrl, {
            headers: { 'Authorization': authHeader }
        })
        .then(response => {
            if (!response.ok) throw new Error('Image not found');
            return response.blob();
        })
        .then(blob => {
            const imgUrl = URL.createObjectURL(blob);
            const img = document.getElementById('previewImage');
            const loader = document.getElementById('imageLoader');
            img.onload = function() {
                loader.style.display = 'none';
                img.style.display = 'block';
            };
            img.src = imgUrl;
        })
        .catch(err => {
            previewContent.innerHTML = `
                <div style="text-align: center; padding: 40px; color: var(--text-light);">
                    <div style="font-size: 48px; margin-bottom: 16px;">⚠️</div>
                    <p>Failed to load image</p>
                </div>
            `;
        });
    } else if (fileType === 'video') {
        // Use direct URL for video streaming (HttpOnly cookie will handle auth)
        previewContent.innerHTML = `
            <div style="text-align: center; background: #000; border-radius: 8px; overflow: hidden;">
                <video id="previewVideo" controls autoplay playsinline style="max-width: 100%; max-height: 500px; width: 100%;">
                    <source src="${fileUrl}" type="${mimeType || 'video/mp4'}">
                    Your browser does not support video playback.
                </video>
            </div>
        `;
    } else if (fileType === 'audio') {
        // Use direct URL for audio streaming (HttpOnly cookie will handle auth)
        previewContent.innerHTML = `
            <div style="text-align: center; padding: 40px; background: #f8f9fa; border-radius: 8px;">
                <div style="font-size: 48px; margin-bottom: 16px;">🎵</div>
                <audio id="previewAudio" controls autoplay style="width: 100%; max-width: 500px;">
                    <source src="${fileUrl}" type="${mimeType || 'audio/mpeg'}">
                    Your browser does not support audio playback.
                </audio>
            </div>
        `;
    } else if (fileType === 'document' && filename.toLowerCase().endsWith('.txt')) {
        previewContent.innerHTML = `<div id="textLoader" style="text-align: center; padding: 40px;">Loading text...</div>`;
        
        fetch(fileUrl, {
            headers: { 'Authorization': authHeader }
        })
        .then(response => response.text())
        .then(text => {
            previewContent.innerHTML = `
                <div style="background: var(--bg); padding: 20px; border-radius: 8px; max-height: 500px; overflow-y: auto; text-align: left;">
                    <pre style="white-space: pre-wrap; word-wrap: break-word; font-family: monospace; font-size: 13px; margin: 0;">${text}</pre>
                </div>
            `;
        })
        .catch(err => {
            previewContent.innerHTML = `
                <div style="text-align: center; padding: 40px; color: var(--text-light);">
                    <div style="font-size: 48px; margin-bottom: 16px;">⚠️</div>
                    <p>Failed to load text file</p>
                </div>
            `;
        });
    } else {
        previewContent.innerHTML = `
            <div style="text-align: center; padding: 40px; color: var(--text-light);">
                <div style="font-size: 48px; margin-bottom: 16px;">${getFileIcon(filename)}</div>
                <p>Preview not available for this file type.</p>
                <p style="margin-top: 8px; font-size: 14px;">Click download to view the file.</p>
                <button class="btn btn-primary" style="margin-top: 20px; width: auto;" 
                        onclick="closePreviewModal(); downloadFile(${fileId}, '${filename.replace(/'/g, "\\'")}')">
                    Download File
                </button>
            </div>
        `;
    }
}

function closePreviewModal() {
    document.getElementById('previewModal').classList.remove('active');
}