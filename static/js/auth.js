// Authentication Functions

async function handleLogin() {
    const email = document.getElementById('loginEmail').value;
    const password = document.getElementById('loginPassword').value;
    
    if (!email || !password) {
        showNotification('Please fill all fields', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_URL}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            showNotification(data.message, 'error');
            return;
        }
        
        localStorage.setItem('token', data.token);
        localStorage.setItem('user', JSON.stringify(data.user));
        token = data.token;
        currentUser = data.user;
        
        showNotification('Login successful!', 'success');
        setTimeout(() => {
            showAppPage();
            loadStats();
            loadFolders();
            loadFiles();
            loadShares();
            loadSettings();
            
            if (currentUser.is_admin) {
                document.getElementById('adminNavBtn').style.display = 'block';
            } else {
                document.getElementById('adminNavBtn').style.display = 'none';
            }
        }, 500);
    } catch (error) {
        showNotification('Login failed. Please try again.', 'error');
    }
}

async function handleSignup() {
    const username = document.getElementById('signupUsername').value;
    const email = document.getElementById('signupEmail').value;
    const password = document.getElementById('signupPassword').value;
    const confirm = document.getElementById('signupConfirm').value;

    if (!username || !email || !password || !confirm) {
        showNotification('Please fill all fields', 'error');
        return;
    }
    
    if (password !== confirm) {
        showNotification('Passwords do not match', 'error');
        return;
    }
    
    if (password.length < 6) {
        showNotification('Password must be at least 6 characters', 'error');
        return;
    }

    try {
        const response = await fetch(`${API_URL}/auth/signup`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, email, password })
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            showNotification(data.message, 'error');
            return;
        }
        
        showNotification('Account created! Please login.', 'success');
        setTimeout(() => switchAuthPage('loginPage'), 1000);
    } catch (error) {
        showNotification('Signup failed. Please try again.', 'error');
    }
}

async function handleLogout() {
    if (confirm('Are you sure you want to logout?')) {
        try {
            await fetch(`${API_URL}/auth/logout`, { method: 'POST' });
        } catch (e) {
            console.error('Logout error:', e);
        }
        
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        token = null;
        currentUser = {};
        currentFolderId = null;
        folderHistory = [];
        
        showNotification('Logged out successfully', 'success');
        setTimeout(() => {
            showAuthPage();
            switchAuthPage('loginPage');
        }, 500);
    }
}

function openForgotPasswordModal() {
    document.getElementById('forgotPasswordModal').classList.add('active');
}

function closeForgotPasswordModal() {
    document.getElementById('forgotPasswordModal').classList.remove('active');
    document.getElementById('forgotEmail').value = '';
}

async function handleForgotPassword() {
    const email = document.getElementById('forgotEmail').value;

    if (!email) {
        showNotification('Please enter your email address', 'error');
        return;
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        showNotification('Please enter a valid email address', 'error');
        return;
    }

    try {
        const response = await fetch(`${API_URL}/auth/forgot-password`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showNotification('Password reset instructions sent to your email!', 'success');
            closeForgotPasswordModal();
        } else {
            showNotification(data.message || 'Failed to send reset email', 'error');
        }
    } catch (error) {
        showNotification('Failed to send reset link. Please try again.', 'error');
    }
}

async function handleResetPassword() {
    const newPassword = document.getElementById('resetNewPassword').value;
    const confirmPassword = document.getElementById('resetConfirmPassword').value;

    if (!newPassword || !confirmPassword) {
        showNotification('Please fill all fields', 'error');
        return;
    }

    if (newPassword !== confirmPassword) {
        showNotification('Passwords do not match', 'error');
        return;
    }

    if (newPassword.length < 6) {
        showNotification('Password must be at least 6 characters', 'error');
        return;
    }

    try {
        const response = await fetch(`${API_URL}/auth/reset-password`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                token: resetToken,
                password: newPassword 
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showNotification('Password reset successfully! Please login.', 'success');
            setTimeout(() => {
                window.history.replaceState({}, document.title, '/');
                switchAuthPage('loginPage');
            }, 1500);
        } else {
            showNotification(data.message || 'Failed to reset password', 'error');
        }
    } catch (error) {
        showNotification('Failed to reset password. Please try again.', 'error');
    }
}

function openChangePasswordModal() {
    document.getElementById('changePasswordModal').classList.add('active');
}

function closePasswordModal() {
    document.getElementById('changePasswordModal').classList.remove('active');
    document.getElementById('currentPassword').value = '';
    document.getElementById('newPassword').value = '';
    document.getElementById('confirmNewPassword').value = '';
}

async function changePassword() {
    const current = document.getElementById('currentPassword').value;
    const newPass = document.getElementById('newPassword').value;
    const confirm = document.getElementById('confirmNewPassword').value;

    if (!current || !newPass || !confirm) {
        showNotification('Please fill all fields', 'error');
        return;
    }

    if (newPass !== confirm) {
        showNotification('New passwords do not match', 'error');
        return;
    }

    if (newPass.length < 6) {
        showNotification('Password must be at least 6 characters', 'error');
        return;
    }

    try {
        const response = await fetch(`${API_URL}/auth/change-password`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
                current_password: current,
                new_password: newPass
            })
        });

        const data = await response.json();

        if (response.ok) {
            showNotification('Password changed successfully!', 'success');
            closePasswordModal();
        } else {
            showNotification(data.message || 'Failed to change password', 'error');
        }
    } catch (error) {
        showNotification('Error changing password', 'error');
    }
}
