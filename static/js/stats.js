// Statistics and Settings Functions

async function loadStats() {
    try {
        const response = await fetch(`${API_URL}/stats`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        const data = await response.json();

        // Update dashboard stats
        document.getElementById('totalFiles').textContent = data.total_files;
        document.getElementById('storageUsed').textContent = formatFileSize(data.total_size);
        document.getElementById('totalShares').textContent = data.total_shares;
        document.getElementById('totalViews').textContent = data.total_views;
    } catch (error) {
        console.error('Error loading stats:', error);
    }
}

async function loadSettings() {
    document.getElementById('settingUsername').textContent = currentUser.username || '-';
    document.getElementById('settingEmail').textContent = currentUser.email || '-';
    document.getElementById('userName').textContent = currentUser.username || 'User';

    try {
        const response = await fetch(`${API_URL}/stats`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        const data = await response.json();

        document.getElementById('settingTotalFiles').textContent = data.total_files;
        document.getElementById('settingStorageUsed').textContent = formatFileSize(data.total_size);
    } catch (error) {
        console.error('Error loading settings:', error);
    }
}
