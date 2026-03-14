// Global Variables
const API_URL = window.location.origin + '/api';
let token = localStorage.getItem('token');
let currentUser = JSON.parse(localStorage.getItem('user') || '{}');
let selectedFileId = null;
let resetToken = null;
let currentFolderId = null;
let allFiles = [];
let allFolders = [];
let currentFileTypeFilter = 'all';
let folderHistory = [];

// Initialize Application
window.addEventListener('load', async () => {
    // Skip main app initialization if on share page or using a share token
    const path = window.location.pathname.replace(/^\//, '');
    if (path.includes('share.html') || path.length === 12) {
        return;
    }

    // Check for persistent session via cookie
    try {
        const authResponse = await fetch(`${API_URL}/auth/me`);
        if (authResponse.ok) {
            const authData = await authResponse.json();
            currentUser = authData.user;
            // Also update token from localStorage if it exists (for Bearer header fallback)
            token = localStorage.getItem('token');
            showAppPage();
            loadAppData();
            setupUploadArea();
            return;
        }
    } catch (e) {
        console.error('Auth check failed:', e);
    }

    const urlParams = new URLSearchParams(window.location.search);
    const urlResetToken = urlParams.get('token');
    
    if (urlResetToken) {
        resetToken = urlResetToken;
        showAuthPage();
        switchAuthPage('resetPasswordPage');
        return;
    }

    if (token) {
        // Fallback to localStorage token if cookie check failed but token exists
        showAppPage();
        loadAppData();
    } else {
        showAuthPage();
    }
    setupUploadArea();
});

function loadAppData() {
    if (currentUser.is_admin) {
        document.getElementById('adminNavBtn').style.display = 'block';
    } else {
        document.getElementById('adminNavBtn').style.display = 'none';
    }
    
    loadStats();
    loadFolders();
    loadFiles();
    loadShares();
    loadSettings();
}

// Navigation Functions
function toggleMobileMenu() {
    const navButtons = document.getElementById('navButtons');
    navButtons.classList.toggle('active');
}

function switchAuthPage(pageId) {
    document.querySelectorAll('#authPages > div').forEach(p => p.style.display = 'none');
    document.getElementById(pageId).style.display = 'flex';
}

function switchPage(pageId, event) {
    if (pageId === 'adminPage' && !currentUser.is_admin) {
        showNotification('Access denied. Admin privileges required.', 'error');
        return;
    }
    
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.getElementById(pageId).classList.add('active');
    document.querySelectorAll('.nav-btn').forEach(btn => btn.classList.remove('active'));
    if (event && event.target) event.target.classList.add('active');

    if (window.innerWidth <= 768) {
        document.getElementById('navButtons').classList.remove('active');
    }

    if (pageId === 'adminPage' && currentUser.is_admin) {
        loadAdminData();
    } else if (pageId === 'filesPage') {
        loadFolders();
        loadFiles();
    }
}

function showAppPage() {
    document.getElementById('authPages').style.display = 'none';
    document.getElementById('appContainer').style.display = 'block';
    document.getElementById('userName').textContent = currentUser.username || 'User';
    
    if (currentUser.is_admin) {
        document.getElementById('adminNavBtn').style.display = 'block';
    } else {
        document.getElementById('adminNavBtn').style.display = 'none';
    }
}

function showAuthPage() {
    document.getElementById('authPages').style.display = 'block';
    document.getElementById('appContainer').style.display = 'none';
}

// Utility Functions
function showNotification(message, type = 'success') {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.innerHTML = `<span>${message}</span>`;
    document.body.appendChild(notification);
    setTimeout(() => notification.remove(), 3000);
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
}

function getFileIcon(filename) {
    const ext = filename.split('.').pop().toLowerCase();
    const iconMap = {
        'pdf': '📄',
        'doc': '📝', 'docx': '📝',
        'xls': '📊', 'xlsx': '📊',
        'ppt': '📽️', 'pptx': '📽️',
        'jpg': '🖼️', 'jpeg': '🖼️', 'png': '🖼️', 'gif': '🖼️', 'webp': '🖼️',
        'mp4': '🎬', 'mov': '🎬', 'avi': '🎬',
        'mp3': '🎵', 'wav': '🎵',
        'zip': '📦', 'rar': '📦', '7z': '📦',
        'txt': '📃',
        'html': '🌐', 'css': '🎨', 'js': '⚙️',
        'py': '🐍', 'java': '☕',
    };
    return iconMap[ext] || '📄';
}

function getFileType(filename) {
    const ext = filename.split('.').pop().toLowerCase();
    if (['jpg', 'jpeg', 'png', 'gif', 'webp'].includes(ext)) return 'image';
    if (['pdf', 'doc', 'docx', 'txt', 'xls', 'xlsx', 'ppt', 'pptx'].includes(ext)) return 'document';
    if (['mp4', 'mov', 'avi', 'mkv'].includes(ext)) return 'video';
    if (['mp3', 'wav', 'ogg'].includes(ext)) return 'audio';
    if (['zip', 'rar', '7z', 'tar', 'gz'].includes(ext)) return 'archive';
    return 'other';
}

function copyToClipboard(text) {
    if (!text) return;
    
    // Check if the Clipboard API is available and in a secure context
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(() => {
            showNotification('Link copied to clipboard!', 'success');
        }).catch(err => {
            console.error('Clipboard API error:', err);
            fallbackCopyTextToClipboard(text);
        });
    } else {
        // Fallback for non-secure contexts (HTTP) or unsupported browsers
        fallbackCopyTextToClipboard(text);
    }
}

function fallbackCopyTextToClipboard(text) {
    const textArea = document.createElement("textarea");
    textArea.value = text;
    
    // Ensure the textarea is off-screen
    textArea.style.position = "fixed";
    textArea.style.left = "-9999px";
    textArea.style.top = "0";
    document.body.appendChild(textArea);
    
    textArea.focus();
    textArea.select();
    
    try {
        const successful = document.execCommand('copy');
        if (successful) {
            showNotification('Link copied to clipboard!', 'success');
        } else {
            showNotification('Failed to copy link. Please manually copy: ' + text, 'error');
            console.error('execCommand copy was unsuccessful');
        }
    } catch (err) {
        console.error('Fallback copy error:', err);
        showNotification('Failed to copy link. Please manually copy: ' + text, 'error');
    }
    
    document.body.removeChild(textArea);
}

// Close modal when clicking outside
window.onclick = function(event) {
    if (event.target.classList.contains('modal')) {
        event.target.classList.remove('active');
    }
}
