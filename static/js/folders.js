// Folder Management Functions

async function loadFolders() {
    try {
        const response = await fetch(`${API_URL}/folders?parent_id=${currentFolderId || ''}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        const data = await response.json();
        allFolders = data.folders || [];
        
        renderBreadcrumb();
        renderFolders();
    } catch (error) {
        console.error('Error loading folders:', error);
    }
}

function renderBreadcrumb() {
    const breadcrumb = document.getElementById('breadcrumb');
    let breadcrumbHTML = '<span class="breadcrumb-item' + (currentFolderId === null ? ' active' : '') + '" onclick="navigateToFolder(null)">📁 Root</span>';
    
    if (folderHistory.length > 0) {
        folderHistory.forEach((folder, index) => {
            const isLast = index === folderHistory.length - 1;
            breadcrumbHTML += ' <span>›</span> ';
            breadcrumbHTML += `<span class="breadcrumb-item${isLast ? ' active' : ''}" onclick="navigateToFolderFromHistory(${index})">${folder.name}</span>`;
        });
    }
    
    breadcrumb.innerHTML = breadcrumbHTML;
}

function renderFolders() {
    const foldersSection = document.getElementById('foldersSection');
    
    if (allFolders.length === 0) {
        foldersSection.innerHTML = '';
        return;
    }
    
    foldersSection.innerHTML = allFolders.map(folder => `
        <div class="folder-item">
            <span class="folder-icon" onclick="navigateToFolder(${folder.id}, '${folder.name.replace(/'/g, "\\'")}')">📁</span>
            <span class="folder-name" onclick="navigateToFolder(${folder.id}, '${folder.name.replace(/'/g, "\\'")}')"> ${folder.name}</span>
            <div class="folder-actions">
                <button class="icon-btn" onclick="openRenameFolderModal(${folder.id}, '${folder.name.replace(/'/g, "\\'")}')">Rename</button>
                <button class="icon-btn" onclick="deleteFolder(${folder.id}, '${folder.name.replace(/'/g, "\\'")}')">Delete</button>
            </div>
        </div>
    `).join('');
}

function navigateToFolder(folderId, folderName = null) {
    if (folderId === null) {
        // Navigate to root
        currentFolderId = null;
        folderHistory = [];
    } else {
        // Navigate into folder
        if (folderName) {
            folderHistory.push({ id: folderId, name: folderName });
        }
        currentFolderId = folderId;
    }
    
    loadFolders();
    loadFiles();
}

function navigateToFolderFromHistory(index) {
    if (index === -1) {
        navigateToFolder(null);
        return;
    }
    
    // Navigate to a folder in history
    const folder = folderHistory[index];
    folderHistory = folderHistory.slice(0, index + 1);
    currentFolderId = folder.id;
    
    loadFolders();
    loadFiles();
}

function openCreateFolderModal() {
    document.getElementById('createFolderModal').classList.add('active');
    document.getElementById('folderName').focus();
}

function closeCreateFolderModal() {
    document.getElementById('createFolderModal').classList.remove('active');
    document.getElementById('folderName').value = '';
}

async function handleCreateFolder() {
    const folderName = document.getElementById('folderName').value.trim();
    
    if (!folderName) {
        showNotification('Please enter a folder name', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_URL}/folders/create`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
                name: folderName,
                parent_id: currentFolderId
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showNotification('Folder created successfully!', 'success');
            closeCreateFolderModal();
            loadFolders();
        } else {
            showNotification(data.message || 'Failed to create folder', 'error');
        }
    } catch (error) {
        showNotification('Error creating folder', 'error');
    }
}

function openRenameFolderModal(folderId, currentName) {
    const modal = document.getElementById('renameFolderModal');
    if (!modal) {
        // Create modal if it doesn't exist
        const modalHTML = `
            <div id="renameFolderModal" class="modal active">
                <div class="modal-content">
                    <div class="modal-header">Rename Folder</div>
                    <div class="form-group">
                        <label>New Folder Name</label>
                        <input type="text" id="renameFolderInput" value="${currentName}">
                    </div>
                    <div class="modal-footer">
                        <button class="btn btn-primary" onclick="handleRenameFolder(${folderId})">Rename</button>
                        <button class="btn btn-secondary" onclick="closeRenameFolderModal()">Cancel</button>
                    </div>
                </div>
            </div>
        `;
        document.body.insertAdjacentHTML('beforeend', modalHTML);
    } else {
        modal.classList.add('active');
        document.getElementById('renameFolderInput').value = currentName;
        document.getElementById('renameFolderInput').dataset.folderId = folderId;
    }
    
    // Store folderId for rename
    window.renameFolderId = folderId;
}

function closeRenameFolderModal() {
    const modal = document.getElementById('renameFolderModal');
    if (modal) {
        modal.classList.remove('active');
    }
}

async function handleRenameFolder(folderId = null) {
    const newName = document.getElementById('renameFolderInput').value.trim();
    const targetFolderId = folderId || window.renameFolderId;
    
    if (!newName) {
        showNotification('Please enter a folder name', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_URL}/folders/${targetFolderId}/rename`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ name: newName })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showNotification('Folder renamed successfully!', 'success');
            closeRenameFolderModal();
            loadFolders();
        } else {
            showNotification(data.message || 'Failed to rename folder', 'error');
        }
    } catch (error) {
        showNotification('Error renaming folder', 'error');
    }
}

async function deleteFolder(folderId, folderName) {
    if (!confirm(`Are you sure you want to delete folder "${folderName}"?`)) {
        return;
    }
    
    try {
        const response = await fetch(`${API_URL}/folders/${folderId}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showNotification('Folder deleted successfully', 'success');
            loadFolders();
        } else {
            showNotification(data.message || 'Failed to delete folder', 'error');
        }
    } catch (error) {
        showNotification('Error deleting folder', 'error');
    }
}
