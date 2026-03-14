// File Sharing Functions

async function autoShareFile(fileId) {
    try {
        const response = await fetch(`${API_URL}/shares/create`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
                file_id: fileId
            })
        });

        const data = await response.json();

        if (response.ok) {
            copyToClipboard(data.share.url);
            showNotification('Share link copied to clipboard!', 'success');
            loadShares();
            loadStats();
        } else {
            showNotification(data.message || 'Failed to create share link', 'error');
        }
    } catch (error) {
        console.error('Auto-share error:', error);
        showNotification('Failed to create share link: ' + error.message, 'error');
    }
}

function openShareModal(fileId) {
    selectedFileId = fileId;
    document.getElementById('shareModal').classList.add('active');
}

function closeModal() {
    document.getElementById('shareModal').classList.remove('active');
    document.getElementById('sharePassword').value = '';
    document.getElementById('shareExpiry').value = '24';
}

async function createShare() {
    const password = document.getElementById('sharePassword').value;
    const expiry_hours = parseInt(document.getElementById('shareExpiry').value);

    if (expiry_hours < 1) {
        showNotification('Expiry must be at least 1 hour', 'error');
        return;
    }

    if (!selectedFileId) {
        showNotification('No file selected', 'error');
        return;
    }

    try {
        const response = await fetch(`${API_URL}/shares/create`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
                file_id: selectedFileId,
                password,
                expiry_hours
            })
        });

        const data = await response.json();

        if (response.ok) {
            showNotification('Share link created successfully!', 'success');
            closeModal();
            loadShares();
            loadStats();
        } else {
            showNotification(data.message || 'Failed to create share link', 'error');
        }
    } catch (error) {
        console.error('Share creation error:', error);
        showNotification('Failed to create share link: ' + error.message, 'error');
    }
}

async function loadShares() {
    try {
        const response = await fetch(`${API_URL}/shares`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        const data = await response.json();
        const sharesList = document.getElementById('sharesList');

        if (!data.shares || data.shares.length === 0) {
            sharesList.innerHTML = `
                <div class="empty-state">
                    <div class="empty-icon">🔗</div>
                    <p>No shared links yet. Create one from the Files tab!</p>
                </div>
            `;
            return;
        }

        sharesList.innerHTML = data.shares.map(share => {
            const expiresDate = new Date(share.expires_at);
            const now = new Date();
            const isExpired = expiresDate < now;
            const expiresText = isExpired ? 
                '<span style="color: var(--error);">Expired</span>' : 
                expiresDate.toLocaleDateString() + ' ' + expiresDate.toLocaleTimeString();
            
            return `
                <div class="share-item">
                    <div class="share-header">
                        <div>
                            <div class="share-title">${share.filename}</div>
                            <div class="share-expires">
                                Expires: ${expiresText} •
                                Views: ${share.access_count}
                            </div>
                        </div>
                    </div>
                    <div class="share-url">
                        <a href="${share.url}" target="_blank">${share.url}</a>
                    </div>
                    <div class="share-actions">
                        <button class="btn btn-secondary" onclick="copyToClipboard('${share.url}')" ${isExpired ? 'disabled' : ''}>
                            Copy Link
                        </button>
                        <button class="btn btn-danger" onclick="deleteShare('${share.id}')">
                            Delete
                        </button>
                    </div>
                </div>
            `;
        }).join('');
    } catch (error) {
        console.error('Error loading shares:', error);
    }
}

async function deleteShare(shareId) {
    if (!confirm('Are you sure you want to delete this share link?')) {
        return;
    }

    try {
        const response = await fetch(`${API_URL}/shares/${shareId}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${token}` }
        });

        const data = await response.json();

        if (response.ok) {
            showNotification('Share deleted successfully', 'success');
            loadShares();
            loadStats();
        } else {
            showNotification(data.message || 'Failed to delete share', 'error');
        }
    } catch (error) {
        showNotification('Error deleting share', 'error');
    }
}