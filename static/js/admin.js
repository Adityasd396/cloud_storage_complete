// Admin Panel Functions

async function loadAdminData() {
    if (!currentUser.is_admin) {
        showNotification('Access denied. Admin privileges required.', 'error');
        switchPage('dashboardPage', null);
        return;
    }
    
    await loadAdminStats();
    await loadAdminUsers();
    await loadAdminFiles();
    await loadBlockedCountries();
}

async function loadAdminStats() {
    try {
        const response = await fetch(`${API_URL}/admin/stats`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        const data = await response.json();

        document.getElementById('adminTotalUsers').textContent = data.total_users;
        document.getElementById('adminOnlineUsers').textContent = data.online_users;
        document.getElementById('adminTotalStorage').textContent = formatFileSize(data.total_storage);
        document.getElementById('adminTotalShares').textContent = data.total_shares;
        
        // Update registration toggle
        document.getElementById('regToggle').checked = data.registrations_enabled;
    } catch (error) {
        console.error('Error loading admin stats:', error);
    }
}

async function loadAdminUsers() {
    try {
        const response = await fetch(`${API_URL}/admin/users`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        const data = await response.json();
        const usersList = document.getElementById('adminUsersList');

        if (!data.users || data.users.length === 0) {
            usersList.innerHTML = `
                <div class="empty-state">
                    <div class="empty-icon">👥</div>
                    <p>No users found</p>
                </div>
            `;
            return;
        }

        usersList.innerHTML = '';
        data.users.forEach(user => {
            const lastSeen = user.last_seen ? new Date(user.last_seen) : null;
            const isOnline = lastSeen && (new Date() - lastSeen < 5 * 60 * 1000);
            
            const userItem = document.createElement('div');
            userItem.className = 'user-item';
            if (user.is_blocked) userItem.style.borderLeft = '4px solid var(--error)';
            
            // Create user info using safe DOM methods
            const userDetails = document.createElement('div');
            userDetails.className = 'user-details';
            
            const userName = document.createElement('div');
            userName.className = 'user-name';
            userName.textContent = user.username + ' ';
            
            if (user.is_admin) {
                const adminBadge = document.createElement('span');
                adminBadge.className = 'admin-badge';
                adminBadge.textContent = 'ADMIN';
                userName.appendChild(adminBadge);
            }
            
            if (isOnline) {
                const onlineTag = document.createElement('span');
                onlineTag.style.color = 'var(--success)';
                onlineTag.style.fontSize = '10px';
                onlineTag.style.marginLeft = '5px';
                onlineTag.textContent = '● Online';
                userName.appendChild(onlineTag);
            }
            
            if (user.is_blocked) {
                const blockedTag = document.createElement('span');
                blockedTag.style.color = 'var(--error)';
                blockedTag.style.fontSize = '10px';
                blockedTag.style.marginLeft = '5px';
                blockedTag.textContent = '[BLOCKED]';
                userName.appendChild(blockedTag);
            }
            
            const userMeta = document.createElement('div');
            userMeta.className = 'user-meta';
            userMeta.textContent = `${user.email} • ${user.file_count} files • ${formatFileSize(user.total_size)} • Joined ${new Date(user.created_at).toLocaleDateString()}`;
            
            userDetails.appendChild(userName);
            userDetails.appendChild(userMeta);
            
            const userActions = document.createElement('div');
            userActions.className = 'user-actions';
            
            if (user.id !== currentUser.id) {
                const blockBtn = document.createElement('button');
                blockBtn.className = 'icon-btn';
                blockBtn.textContent = user.is_blocked ? 'Unblock' : 'Block';
                blockBtn.onclick = () => toggleUserBlock(user.id, user.is_blocked);
                
                const adminBtn = document.createElement('button');
                adminBtn.className = 'icon-btn';
                adminBtn.textContent = user.is_admin ? 'Remove Admin' : 'Make Admin';
                adminBtn.onclick = () => toggleAdminStatus(user.id, user.is_admin);
                
                const deleteBtn = document.createElement('button');
                deleteBtn.className = 'icon-btn';
                deleteBtn.style.color = 'var(--error)';
                deleteBtn.textContent = 'Delete';
                deleteBtn.onclick = () => deleteUser(user.id, user.username);
                
                userActions.appendChild(blockBtn);
                userActions.appendChild(adminBtn);
                userActions.appendChild(deleteBtn);
            } else {
                const currentTag = document.createElement('span');
                currentTag.style.color = 'var(--text-light)';
                currentTag.style.fontSize = '13px';
                currentTag.textContent = 'Current User';
                userActions.appendChild(currentTag);
            }
            
            userItem.appendChild(userDetails);
            userItem.appendChild(userActions);
            usersList.appendChild(userItem);
        });
    } catch (error) {
        console.error('Error loading admin users:', error);
    }
}

async function toggleRegistrations() {
    const enabled = document.getElementById('regToggle').checked;
    try {
        const response = await fetch(`${API_URL}/admin/settings/registrations`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ enabled })
        });
        
        if (response.ok) {
            showNotification(`Registrations ${enabled ? 'enabled' : 'disabled'} successfully`, 'success');
        } else {
            showNotification('Failed to update registration status', 'error');
            document.getElementById('regToggle').checked = !enabled;
        }
    } catch (error) {
        showNotification('Error updating registration status', 'error');
        document.getElementById('regToggle').checked = !enabled;
    }
}

async function loadBlockedCountries() {
    try {
        const response = await fetch(`${API_URL}/admin/settings/blocked-countries`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const data = await response.json();
        document.getElementById('blockedCountries').value = data.countries || '';
    } catch (error) {
        console.error('Error loading blocked countries:', error);
    }
}

async function updateBlockedCountries() {
    const countries = document.getElementById('blockedCountries').value;
    try {
        const response = await fetch(`${API_URL}/admin/settings/blocked-countries`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ countries })
        });
        
        if (response.ok) {
            showNotification('Blocked countries updated successfully', 'success');
        } else {
            showNotification('Failed to update blocked countries', 'error');
        }
    } catch (error) {
        showNotification('Error updating blocked countries', 'error');
    }
}

async function toggleUserBlock(userId, isCurrentlyBlocked) {
    const action = isCurrentlyBlocked ? 'unblock' : 'block';
    if (!confirm(`Are you sure you want to ${action} this user?`)) return;

    try {
        const response = await fetch(`${API_URL}/admin/users/${userId}/block`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ block: !isCurrentlyBlocked })
        });

        if (response.ok) {
            showNotification(`User ${action}ed successfully`, 'success');
            loadAdminUsers();
        } else {
            const data = await response.json();
            showNotification(data.message || `Failed to ${action} user`, 'error');
        }
    } catch (error) {
        showNotification(`Error ${action}ing user`, 'error');
    }
}

async function loadAdminFiles() {
    try {
        const response = await fetch(`${API_URL}/admin/files`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        const data = await response.json();
        const filesBody = document.getElementById('adminFilesBody');

        if (!data.files || data.files.length === 0) {
            filesBody.innerHTML = `
                <tr>
                    <td colspan="5" style="text-align: center; padding: 40px; color: var(--text-light);">No files found</td>
                </tr>
            `;
            return;
        }

        filesBody.innerHTML = data.files.map(file => `
            <tr>
                <td>${file.filename}</td>
                <td>${file.username}</td>
                <td>${formatFileSize(file.size)}</td>
                <td>${new Date(file.uploaded_at).toLocaleDateString()}</td>
                <td>
                    <button class="icon-btn" style="color: var(--error); padding: 6px 12px;" 
                        onclick="adminDeleteFile(${file.id}, '${file.filename.replace(/'/g, "\\'")}')">Delete</button>
                </td>
            </tr>
        `).join('');
    } catch (error) {
        console.error('Error loading admin files:', error);
    }
}

async function toggleAdminStatus(userId, isCurrentlyAdmin) {
    const action = isCurrentlyAdmin ? 'remove admin privileges from' : 'grant admin privileges to';
    if (!confirm(`Are you sure you want to ${action} this user?`)) return;

    try {
        const response = await fetch(`${API_URL}/admin/users/${userId}/toggle-admin`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (response.ok) {
            showNotification('Admin status updated successfully', 'success');
            loadAdminUsers();
        } else {
            const data = await response.json();
            showNotification(data.message || 'Failed to update admin status', 'error');
        }
    } catch (error) {
        showNotification('Error updating admin status', 'error');
    }
}

async function deleteUser(userId, username) {
    if (!confirm(`Are you sure you want to delete user "${username}"? This will also delete all their files and shares.`)) return;

    try {
        const response = await fetch(`${API_URL}/admin/users/${userId}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (response.ok) {
            showNotification('User deleted successfully', 'success');
            loadAdminData();
        } else {
            const data = await response.json();
            showNotification(data.message || 'Failed to delete user', 'error');
        }
    } catch (error) {
        showNotification('Error deleting user', 'error');
    }
}

async function adminDeleteFile(fileId, filename) {
    if (!confirm(`Are you sure you want to delete "${filename}"?`)) return;

    try {
        const response = await fetch(`${API_URL}/admin/files/${fileId}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (response.ok) {
            showNotification('File deleted successfully', 'success');
            loadAdminData();
        } else {
            const data = await response.json();
            showNotification(data.message || 'Failed to delete file', 'error');
        }
    } catch (error) {
        showNotification('Error deleting file', 'error');
    }
}

function openAddUserModal() {
    document.getElementById('addUserModal').classList.add('active');
}

function closeAddUserModal() {
    document.getElementById('addUserModal').classList.remove('active');
    document.getElementById('addUserName').value = '';
    document.getElementById('addUserEmail').value = '';
    document.getElementById('addUserPassword').value = '';
    document.getElementById('addUserIsAdmin').checked = false;
}

async function handleAddUser() {
    const username = document.getElementById('addUserName').value;
    const email = document.getElementById('addUserEmail').value;
    const password = document.getElementById('addUserPassword').value;
    const isAdmin = document.getElementById('addUserIsAdmin').checked;

    if (!username || !email || !password) {
        showNotification('Please fill all required fields', 'error');
        return;
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        showNotification('Please enter a valid email address', 'error');
        return;
    }

    if (password.length < 6) {
        showNotification('Password must be at least 6 characters', 'error');
        return;
    }

    try {
        const response = await fetch(`${API_URL}/admin/users/create`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
                username,
                email,
                password,
                is_admin: isAdmin
            })
        });

        const data = await response.json();

        if (response.ok) {
            showNotification(`User "${username}" created successfully!`, 'success');
            closeAddUserModal();
            loadAdminUsers();
        } else {
            showNotification(data.message || 'Failed to create user', 'error');
        }
    } catch (error) {
        showNotification('Error creating user', 'error');
    }
}
