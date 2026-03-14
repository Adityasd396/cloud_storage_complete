from flask import Flask, request, jsonify, send_file, send_from_directory, Response, stream_with_context
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import jwt
import datetime
from functools import wraps
import sqlite3
from dotenv import load_dotenv
from io import BytesIO
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import mimetypes

load_dotenv()

app = Flask(__name__, static_folder='static', static_url_path='')

def log_error(message, error=None):
    """Log errors to a file for production debugging"""
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    error_msg = f"[{timestamp}] {message}"
    if error:
        error_msg += f" | Error: {str(error)}"
    print(error_msg) # Still print to console
    try:
        with open('app.log', 'a') as f:
            f.write(error_msg + '\n')
            if error and hasattr(error, '__traceback__'):
                import traceback
                traceback.print_report(file=f)
    except:
        pass # If we can't write to log file, just ignore

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY') or secrets.token_hex(32)

# Encryption Master Key - CRITICAL for production
# We use SECRET_KEY as a secondary fallback to ensure consistency across restarts if ENCRYPTION_KEY is missing
_raw_key = os.getenv('ENCRYPTION_KEY') or os.getenv('SECRET_KEY')
if not _raw_key:
    # This should only happen on first run if no .env exists
    log_error("CRITICAL: No ENCRYPTION_KEY found. Generating a random one. Files will be lost on restart!")
    app.config['ENCRYPTION_KEY'] = secrets.token_bytes(32)
else:
    # Ensure key is exactly 32 bytes for AES-256
    if isinstance(_raw_key, str):
        _raw_key = _raw_key.encode()
    app.config['ENCRYPTION_KEY'] = _raw_key.ljust(32, b'\0')[:32]

# Constants for chunked encryption
CHUNK_SIZE = 128 * 1024 # Increased to 128KB for better production performance
IV_SIZE = 16

def get_mimetype(filename):
    """Accurately detect mimetype from filename"""
    mtype, _ = mimetypes.guess_type(filename)
    if not mtype:
        # Fallback for common types if guess fails
        ext = filename.split('.')[-1].lower()
        fallbacks = {
            'mp4': 'video/mp4',
            'mkv': 'video/x-matroska',
            'mov': 'video/quicktime',
            'webm': 'video/webm',
            'avi': 'video/x-msvideo',
            'm4v': 'video/x-m4v',
            'mp3': 'audio/mpeg',
            'wav': 'audio/wav',
            'ogg': 'audio/ogg'
        }
        return fallbacks.get(ext, 'application/octet-stream')
    return mtype

def encrypt_chunk(chunk, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(chunk) + encryptor.finalize()

def decrypt_chunk(chunk, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(chunk) + decryptor.finalize()

# Make upload folder absolute to prevent issues in production
_upload_folder = os.getenv('UPLOAD_FOLDER', 'uploads')
if not os.path.isabs(_upload_folder):
    _upload_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), _upload_folder)
app.config['UPLOAD_FOLDER'] = _upload_folder
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024 * 1024  # 100GB max
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx', 'zip', 'rar', 'mp4', 'mov', 'avi', 'mp3', 'wav', 'mkv', 'webm', 'm4v', 'ogg', 'mp3'}

# Email Configuration
EMAIL_HOST = os.getenv('EMAIL_HOST', 'smtp.gmail.com')
EMAIL_PORT = int(os.getenv('EMAIL_PORT', 587))
EMAIL_USER = os.getenv('EMAIL_USER', '')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD', '')
EMAIL_FROM = os.getenv('EMAIL_FROM', 'noreply@cloudstorage.com')

# SQLite Database
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cloud_storage.db')

# Initialize CORS
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

# Create upload folder
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Rate Limiting
login_attempts = {}

@app.after_request
def add_security_headers(response):
    """Add security headers to every response"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    # Simplified CSP for local dev compatibility - Added blob: and data: for images/videos
    # Added connect-src for API calls
    # Added * for media-src and video-src as a fallback for some browsers
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: *; video-src 'self' data: blob: *; media-src 'self' data: blob: *; connect-src 'self' *;"
    # Allow range requests headers to be exposed
    response.headers['Access-Control-Expose-Headers'] = 'Content-Range, Accept-Ranges, Content-Length, Accept'
    # Allow credentials for CORS
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response

@app.before_request
def check_country_block():
    """Check if the request is from a blocked country"""
    # Skip check for static files, share links, and admin routes
    # Added check to allow anyone with a share token to access the link
    path = request.path.lstrip('/')
    if '.' in request.path or request.path.startswith('/api/admin') or request.path.startswith('/api/shares/info') or request.path.startswith('/api/shares/download'):
        return
    
    # Check if the path is a potential share token (12 characters)
    if len(path) == 12:
        return

    # Skip for root and static files
    if not path or path == 'index.html' or path == 'share.html':
        return

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT value FROM settings WHERE key = 'blocked_countries'")
        row = cursor.fetchone()
        blocked_countries = row[0].split(',') if row and row[0] else []
    except:
        blocked_countries = []
    finally:
        cursor.close()
        conn.close()
    
    if not blocked_countries:
        return
        
    # Get country from header (common in production like Cloudflare or specialized proxies)
    country = request.headers.get('CF-IPCountry') or request.headers.get('X-Country-Code')
    
    if country and country.upper() in [c.strip() for c in blocked_countries]:
        return jsonify({'message': f'Access from your country ({country}) is blocked by administrator.'}), 403

def get_db_connection():
    """Create SQLite database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_database():
    """Initialize SQLite database tables"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("PRAGMA foreign_keys = ON")
        cursor = conn.cursor()
        
        # Create users table with is_admin, is_blocked, and last_seen
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                is_admin INTEGER DEFAULT 0,
                is_blocked INTEGER DEFAULT 0,
                last_seen TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        print("✓ Users table created")

        # Create settings table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        ''')
        # Insert default settings if not exist
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('registrations_enabled', 'true')")
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('blocked_countries', '')")
        print("✓ Settings table created")
        
        # Create folders table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS folders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                parent_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (parent_id) REFERENCES folders(id) ON DELETE CASCADE
            )
        ''')
        print("✓ Folders table created")
        
        # Create files table with encryption support
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                folder_id INTEGER,
                filename TEXT NOT NULL,
                stored_filename TEXT NOT NULL,
                size INTEGER NOT NULL,
                type TEXT,
                path TEXT NOT NULL,
                is_encrypted INTEGER DEFAULT 0,
                iv TEXT,
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE SET NULL
            )
        ''')
        
        # Add columns if they don't exist (migration for existing DB)
        try:
            cursor.execute('ALTER TABLE files ADD COLUMN is_encrypted INTEGER DEFAULT 0')
        except: pass
        try:
            cursor.execute('ALTER TABLE files ADD COLUMN iv TEXT')
        except: pass
        
        print("✓ Files table created")
        
        # Create shares table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS shares (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                file_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                token TEXT NOT NULL,
                password TEXT,
                expires_at TIMESTAMP,
                access_count INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
            )
        ''')
        print("✓ Shares table created")
        
        # Create password reset tokens table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT NOT NULL UNIQUE,
                expires_at TIMESTAMP NOT NULL,
                used INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')
        print("✓ Password reset tokens table created")
        
        conn.commit()
        
        # Create default admin user if not exists
        cursor.execute('SELECT id FROM users WHERE email = ?', ('admin@cloudstorage.com',))
        if not cursor.fetchone():
            cursor.execute(
                'INSERT INTO users (username, email, password, is_admin) VALUES (?, ?, ?, ?)',
                ('Admin', 'admin@cloudstorage.com', generate_password_hash('admin123'), 1)
            )
            conn.commit()
            print("✓ Default admin user created (email: admin@cloudstorage.com, password: admin123)")
        
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        print(f"ERROR - Database initialization failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def token_required(f):
    """Decorator to verify JWT token from cookie or header"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('auth_token') or request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        try:
            if token and token.startswith('Bearer '):
                token = token.split(' ')[1]
            
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user_id = data['user_id']
            
            # Check if user is blocked and update last_seen
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT is_blocked FROM users WHERE id = ?', (current_user_id,))
            user = cursor.fetchone()
            if not user:
                cursor.close()
                conn.close()
                return jsonify({'message': 'User not found'}), 404
            
            if user[0]:
                cursor.close()
                conn.close()
                return jsonify({'message': 'Your account has been blocked by an administrator.'}), 403
            
            # Update last_seen
            cursor.execute('UPDATE users SET last_seen = ? WHERE id = ?', (datetime.datetime.now().isoformat(), current_user_id))
            conn.commit()
            cursor.close()
            conn.close()
            
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid'}), 401
        except Exception as e:
            print(f"Token validation error: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({'message': f'Server error: {str(e)}'}), 500
        
        return f(current_user_id, *args, **kwargs)
    return decorated

def admin_required(f):
    """Decorator to verify admin access"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        try:
            token = token.split(' ')[1] if ' ' in token else token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user_id = data['user_id']
            
            # Check if user is admin
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT is_admin FROM users WHERE id = ?', (current_user_id,))
            user = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if not user or not user[0]:
                return jsonify({'message': 'Admin access required'}), 403
                
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid'}), 401
        except Exception as e:
            print(f"Admin validation error: {e}")
            return jsonify({'message': f'Server error: {str(e)}'}), 500
        
        return f(current_user_id, *args, **kwargs)
    return decorated

# AUTH ROUTES
@app.route('/api/auth/me', methods=['GET'])
@token_required
def get_current_user(current_user_id):
    """Get current user information from token"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('SELECT id, username, email, is_admin FROM users WHERE id = ?', (current_user_id,))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        return jsonify({
            'user': {
                'id': user[0],
                'username': user[1],
                'email': user[2],
                'is_admin': bool(user[3])
            }
        }), 200
    except Exception as e:
        print(f"Auth me error: {e}")
        return jsonify({'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/auth/signup', methods=['POST'])
def signup():
    """User registration"""
    data = request.get_json()
    
    if not data or not data.get('email') or not data.get('password') or not data.get('username'):
        return jsonify({'message': 'Missing required fields'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Check if registrations are enabled
        cursor.execute("SELECT value FROM settings WHERE key = 'registrations_enabled'")
        reg_enabled = cursor.fetchone()
        if reg_enabled and reg_enabled[0] == 'false':
            return jsonify({'message': 'New registrations are currently disabled by administrator.'}), 403

        cursor.execute('SELECT id FROM users WHERE email = ?', (data['email'],))
        if cursor.fetchone():
            return jsonify({'message': 'Email already exists'}), 400
        
        cursor.execute(
            'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
            (data['username'], data['email'], generate_password_hash(data['password']))
        )
        conn.commit()
        
        return jsonify({'message': 'User created successfully'}), 201
    except Exception as e:
        conn.rollback()
        print(f"Signup error: {e}")
        return jsonify({'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/auth/login', methods=['POST'])
def login():
    """User login"""
    data = request.get_json()
    
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Missing email or password'}), 400
    
    # Basic Rate Limiting
    ip = request.remote_addr
    now = datetime.datetime.now()
    
    if ip in login_attempts:
        attempts, last_time = login_attempts[ip]
        # Reset attempts if more than 15 minutes passed
        if (now - last_time).total_seconds() > 900:
            login_attempts[ip] = [0, now]
        elif attempts >= 5:
            return jsonify({'message': 'Too many login attempts. Please try again in 15 minutes.'}), 429
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('SELECT id, username, email, password, is_admin, is_blocked FROM users WHERE email = ?', (data['email'],))
        user = cursor.fetchone()
        
        if not user or not check_password_hash(user[3], data['password']):
            # Increment failed attempts
            if ip not in login_attempts:
                login_attempts[ip] = [1, now]
            else:
                login_attempts[ip][0] += 1
                login_attempts[ip][1] = now
            return jsonify({'message': 'Invalid credentials'}), 401
        
        if user[5]:  # is_blocked
            return jsonify({'message': 'Your account has been blocked.'}), 403

        # Successful login - reset attempts
        if ip in login_attempts:
            del login_attempts[ip]
        
        token = jwt.encode({
            'user_id': user[0],
            'email': user[2],
            'is_admin': user[4],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=365)
        }, app.config['SECRET_KEY'], algorithm='HS256')
        
        response = jsonify({
            'message': 'Login successful',
            'token': token,
            'user': {
                'id': user[0],
                'username': user[1],
                'email': user[2],
                'is_admin': bool(user[4])
            }
        })
        
        # Set HttpOnly cookie for persistent login (1 year)
        response.set_cookie(
            'auth_token', 
            token, 
            httponly=True, 
            secure=False, # Set to True if using HTTPS
            samesite='Lax',
            max_age=365 * 24 * 60 * 60 # 1 year
        )
        
        return response, 200
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/auth/change-password', methods=['POST'])
@token_required
def change_password(current_user_id):
    """Change password for logged-in user"""
    data = request.get_json()
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    if not current_password or not new_password:
        return jsonify({'message': 'Current and new passwords are required'}), 400
    
    if len(new_password) < 6:
        return jsonify({'message': 'New password must be at least 6 characters'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('SELECT password FROM users WHERE id = ?', (current_user_id,))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        if not check_password_hash(user[0], current_password):
            return jsonify({'message': 'Current password is incorrect'}), 401
        
        new_password_hash = generate_password_hash(new_password)
        cursor.execute('UPDATE users SET password = ? WHERE id = ?', (new_password_hash, current_user_id))
        conn.commit()
        
        return jsonify({'message': 'Password changed successfully'}), 200
    except Exception as e:
        conn.rollback()
        print(f"Change password error: {e}")
        return jsonify({'message': 'Failed to change password'}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    """User logout - clear cookie"""
    response = jsonify({'message': 'Logged out successfully'})
    response.delete_cookie('auth_token')
    return response, 200

# FOLDER ROUTES
@app.route('/api/folders', methods=['GET'])
@token_required
def list_folders(current_user_id):
    """List user's folders"""
    parent_id = request.args.get('parent_id', None)
    if parent_id == '':
        parent_id = None
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        if parent_id is None:
            cursor.execute('''
                SELECT id, name, parent_id, created_at 
                FROM folders 
                WHERE user_id = ? AND parent_id IS NULL
                ORDER BY name
            ''', (current_user_id,))
        else:
            cursor.execute('''
                SELECT id, name, parent_id, created_at 
                FROM folders 
                WHERE user_id = ? AND parent_id = ?
                ORDER BY name
            ''', (current_user_id, parent_id))
        
        folders = cursor.fetchall()
        
        folder_list = [{
            'id': f[0],
            'name': f[1],
            'parent_id': f[2],
            'created_at': f[3]
        } for f in folders]
        
        return jsonify({
            'folders': folder_list,
            'total_folders': len(folder_list)
        }), 200
    except Exception as e:
        print(f"List folders error: {e}")
        return jsonify({'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/folders/create', methods=['POST'])
@token_required
def create_folder(current_user_id):
    """Create a new folder"""
    data = request.get_json()
    folder_name = data.get('name')
    parent_id = data.get('parent_id')
    
    if not folder_name:
        return jsonify({'message': 'Folder name is required'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Check if parent folder belongs to user
        if parent_id:
            cursor.execute('SELECT id FROM folders WHERE id = ? AND user_id = ?', (parent_id, current_user_id))
            if not cursor.fetchone():
                return jsonify({'message': 'Invalid parent folder'}), 403

        # Check if folder with same name exists in same location
        if parent_id:
            cursor.execute('''
                SELECT id FROM folders 
                WHERE user_id = ? AND name = ? AND parent_id = ?
            ''', (current_user_id, folder_name, parent_id))
        else:
            cursor.execute('''
                SELECT id FROM folders 
                WHERE user_id = ? AND name = ? AND parent_id IS NULL
            ''', (current_user_id, folder_name))
        
        if cursor.fetchone():
            return jsonify({'message': 'Folder with this name already exists'}), 400
        
        cursor.execute(
            'INSERT INTO folders (user_id, name, parent_id) VALUES (?, ?, ?)',
            (current_user_id, folder_name, parent_id)
        )
        conn.commit()
        folder_id = cursor.lastrowid
        
        return jsonify({
            'message': 'Folder created successfully',
            'folder': {
                'id': folder_id,
                'name': folder_name,
                'parent_id': parent_id
            }
        }), 201
    except Exception as e:
        conn.rollback()
        print(f"Create folder error: {e}")
        return jsonify({'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/folders/<int:folder_id>', methods=['DELETE'])
@token_required
def delete_folder(current_user_id, folder_id):
    """Delete a folder"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Verify folder belongs to user
        cursor.execute('SELECT id FROM folders WHERE id = ? AND user_id = ?', 
                      (folder_id, current_user_id))
        if not cursor.fetchone():
            return jsonify({'message': 'Folder not found'}), 404
        
        # Check if folder has subfolders
        cursor.execute('SELECT COUNT(*) FROM folders WHERE parent_id = ?', (folder_id,))
        subfolder_count = cursor.fetchone()[0]
        
        # Check if folder has files
        cursor.execute('SELECT COUNT(*) FROM files WHERE folder_id = ?', (folder_id,))
        file_count = cursor.fetchone()[0]
        
        if subfolder_count > 0 or file_count > 0:
            return jsonify({
                'message': 'Cannot delete folder. It contains files or subfolders.'
            }), 400
        
        cursor.execute('DELETE FROM folders WHERE id = ?', (folder_id,))
        conn.commit()
        
        return jsonify({'message': 'Folder deleted successfully'}), 200
    except Exception as e:
        conn.rollback()
        print(f"Delete folder error: {e}")
        return jsonify({'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/folders/<int:folder_id>/rename', methods=['PUT'])
@token_required
def rename_folder(current_user_id, folder_id):
    """Rename a folder"""
    data = request.get_json()
    new_name = data.get('name')
    
    if not new_name:
        return jsonify({'message': 'New name is required'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Verify folder belongs to user
        cursor.execute('SELECT parent_id FROM folders WHERE id = ? AND user_id = ?', 
                      (folder_id, current_user_id))
        folder = cursor.fetchone()
        
        if not folder:
            return jsonify({'message': 'Folder not found'}), 404
        
        parent_id = folder[0]
        
        # Check if new name conflicts with existing folder
        if parent_id:
            cursor.execute('''
                SELECT id FROM folders 
                WHERE user_id = ? AND name = ? AND parent_id = ? AND id != ?
            ''', (current_user_id, new_name, parent_id, folder_id))
        else:
            cursor.execute('''
                SELECT id FROM folders 
                WHERE user_id = ? AND name = ? AND parent_id IS NULL AND id != ?
            ''', (current_user_id, new_name, folder_id))
        
        if cursor.fetchone():
            return jsonify({'message': 'Folder with this name already exists'}), 400
        
        cursor.execute('UPDATE folders SET name = ? WHERE id = ?', (new_name, folder_id))
        conn.commit()
        
        return jsonify({'message': 'Folder renamed successfully'}), 200
    except Exception as e:
        conn.rollback()
        print(f"Rename folder error: {e}")
        return jsonify({'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# FILE ROUTES
@app.route('/api/files/upload', methods=['POST'])
@token_required
def upload_file(current_user_id):
    """Upload a file"""
    if 'file' not in request.files:
        return jsonify({'message': 'No file provided'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'message': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'message': 'File type not allowed'}), 400
    
    folder_id = request.form.get('folder_id')
    if folder_id == '':
        folder_id = None
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Check if folder belongs to user
        if folder_id:
            cursor.execute('SELECT id FROM folders WHERE id = ? AND user_id = ?', (folder_id, current_user_id))
            if not cursor.fetchone():
                return jsonify({'message': 'Invalid folder ID'}), 403

        filename = secure_filename(file.filename)
        timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S_')
        stored_filename = timestamp + filename
        
        user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(current_user_id))
        os.makedirs(user_folder, exist_ok=True)
        
        filepath = os.path.join(user_folder, stored_filename)
        # Ensure filepath is absolute for DB storage
        filepath = os.path.abspath(filepath)
        
        log_error(f"UPLOADING: {filename} to {filepath}")
        
        # Encryption Setup
        iv = secrets.token_bytes(IV_SIZE)
        iv_base64 = base64.b64encode(iv).decode()
        
        # Save file with encryption in chunks using a persistent encryptor
        file.seek(0) # Reset file pointer
        file_size = 0
        cipher = Cipher(algorithms.AES(app.config['ENCRYPTION_KEY']), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        try:
            with open(filepath, 'wb') as f:
                while True:
                    chunk = file.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    encrypted_chunk = encryptor.update(chunk)
                    f.write(encrypted_chunk)
                    file_size += len(chunk)
                f.write(encryptor.finalize())
            log_error(f"UPLOAD SUCCESS: {filepath} ({file_size} bytes)")
        except Exception as e:
            log_error(f"UPLOAD FAILED writing to disk: {filepath}", e)
            raise e

        cursor.execute(
            'INSERT INTO files (user_id, folder_id, filename, stored_filename, size, type, path, is_encrypted, iv) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (current_user_id, folder_id if folder_id else None, file.filename, stored_filename, file_size, file.content_type, filepath, 1, iv_base64)
        )
        conn.commit()
        file_id = cursor.lastrowid
        
        return jsonify({
            'message': 'File uploaded successfully',
            'file': {
                'id': file_id,
                'user_id': current_user_id,
                'folder_id': folder_id,
                'filename': file.filename,
                'stored_filename': stored_filename,
                'size': file_size,
                'type': file.content_type
            }
        }), 201
    except Exception as e:
        conn.rollback()
        print(f"Upload error: {e}")
        return jsonify({'message': f'Upload failed: {str(e)}'}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/files', methods=['GET'])
@token_required
def list_files(current_user_id):
    """List user's files"""
    folder_id = request.args.get('folder_id', None)
    if folder_id == '':
        folder_id = None
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        if folder_id is None:
            cursor.execute('''
                SELECT id, user_id, filename, stored_filename, size, type, uploaded_at, path, folder_id 
                FROM files 
                WHERE user_id = ? AND folder_id IS NULL
                ORDER BY uploaded_at DESC
            ''', (current_user_id,))
        else:
            cursor.execute('''
                SELECT id, user_id, filename, stored_filename, size, type, uploaded_at, path, folder_id 
                FROM files 
                WHERE user_id = ? AND folder_id = ?
                ORDER BY uploaded_at DESC
            ''', (current_user_id, folder_id))
        
        files = cursor.fetchall()
        
        user_files = [{
            'id': f[0],
            'user_id': f[1],
            'filename': f[2],
            'stored_filename': f[3],
            'size': f[4],
            'type': f[5],
            'uploaded_at': f[6],
            'path': f[7],
            'folder_id': f[8]
        } for f in files]
        
        total_size = sum(f['size'] for f in user_files)
        
        return jsonify({
            'files': user_files,
            'total_files': len(user_files),
            'total_size': total_size
        }), 200
    except Exception as e:
        print(f"List files error: {e}")
        return jsonify({'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/files/<int:file_id>', methods=['GET'])
@token_required
def download_file(current_user_id, file_id):
    """Download or preview a file"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            SELECT stored_filename, filename, path, type, is_encrypted, iv, size 
            FROM files 
            WHERE id = ? AND user_id = ?
        ''', (file_id, current_user_id))
        file_info = cursor.fetchone()
        
        if not file_info:
            log_error(f"Download failed: File ID {file_id} not found for user {current_user_id}")
            return jsonify({'message': 'File not found'}), 404
        
        stored_filename = file_info[0]
        original_filename = file_info[1]
        stored_path_db = file_info[2]
        is_encrypted = bool(file_info[4])
        iv_base64 = file_info[5]
        file_size = file_info[6]
        
        # Professional MIME detection
        file_type = get_mimetype(original_filename)
        
        is_preview = request.args.get('preview') == 'true'
        
        # Robust path resolution
        potential_paths = [
            stored_path_db,
            os.path.join(app.config['UPLOAD_FOLDER'], str(current_user_id), stored_filename),
            os.path.join(app.config['UPLOAD_FOLDER'], stored_filename),
            os.path.abspath(stored_path_db) if not os.path.isabs(stored_path_db) else None,
            os.path.join(os.getcwd(), stored_filename),
            os.path.join(os.getcwd(), 'uploads', stored_filename),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads', stored_filename)
        ]
        
        actual_path = None
        log_error(f"FINDING FILE: {stored_filename}")
        for i, p in enumerate(potential_paths):
            if p:
                abs_p = os.path.abspath(p)
                exists = os.path.exists(abs_p)
                log_error(f"Path Check {i+1}: {abs_p} | Exists: {exists}")
                if exists and os.path.isfile(abs_p):
                    actual_path = abs_p
                    break
        
        if not actual_path:
            # Recursive search as last resort
            log_error(f"NOT FOUND in standard locations. Starting emergency recursive search in {app.config['UPLOAD_FOLDER']}...")
            for root, dirs, files in os.walk(app.config['UPLOAD_FOLDER']):
                if stored_filename in files:
                    actual_path = os.path.join(root, stored_filename)
                    log_error(f"EMERGENCY FIND: {actual_path}")
                    break
        
        if not actual_path:
            log_error(f"Download failed: File {stored_filename} NOT FOUND on server at any location")
            return jsonify({'message': 'File not found on server'}), 404
        
        if is_encrypted and iv_base64:
            iv = base64.b64decode(iv_base64)
            # Logged in user download/preview
            return stream_decrypted_file(actual_path, app.config['ENCRYPTION_KEY'], iv, original_filename, file_type, file_size, as_attachment=not is_preview)
        
        try:
            return send_file(
                actual_path,
                as_attachment=not is_preview,
                download_name=original_filename,
                mimetype=file_type,
                conditional=True
            )
        except Exception as e:
            log_error(f"send_file failed for {actual_path}", e)
            return jsonify({'message': f'Cannot serve file: {str(e)}'}), 500
            
    except Exception as e:
        log_error("Download exception", e)
        return jsonify({'message': f'Download failed: {str(e)}'}), 500
    finally:
        cursor.close()
        conn.close()

def stream_decrypted_file(path, key, iv, filename, mimetype, total_size, as_attachment=True):
    """Stream a decrypted file with professional-grade Range support and diagnostics"""
    range_header = request.headers.get('Range', None)
    
    start = 0
    end = total_size - 1
    
    if range_header:
        # Robust Range parsing for browser compatibility
        try:
            # Format: bytes=start-end or bytes=start- or bytes=-end
            r = range_header.replace('bytes=', '').strip()
            if r.startswith('-'):
                # Handle "-500" (last 500 bytes)
                start = max(0, total_size - int(r[1:]))
            else:
                parts = r.split('-')
                if parts[0]: start = int(parts[0])
                if len(parts) > 1 and parts[1]: 
                    end = int(parts[1])
        except Exception as e:
            log_error(f"Range parsing error for {filename}: {e} (Header: {range_header})")
        
    # Boundary validation
    start = max(0, start)
    end = min(total_size - 1, end)
    if start > end: start = end

    content_length = end - start + 1
    status_code = 206 if range_header else 200
    
    log_error(f"STREAM DOCTOR: {'(RANGE) ' if range_header else ''}{filename} | Status: {status_code} | Range: {start}-{end}/{total_size} | MIME: {mimetype}")
    
    # Pre-flight check: Verify file exists and is readable before returning response
    if not os.path.exists(path):
        log_error(f"STREAM DOCTOR PRE-FLIGHT FAIL: File missing at {path}")
        return jsonify({'message': 'File not found on disk'}), 404
        
    try:
        with open(path, 'rb') as test_f:
            test_f.seek(start)
            if not test_f.read(1) and content_length > 0:
                log_error(f"STREAM DOCTOR PRE-FLIGHT FAIL: Cannot read byte at {start}")
                return jsonify({'message': 'File unreadable'}), 500
    except Exception as e:
        log_error(f"STREAM DOCTOR PRE-FLIGHT ERROR: {e}")
        return jsonify({'message': f'File access error: {str(e)}'}), 500

    def generate():
        try:
            with open(path, 'rb') as f:
                # Calculate counter offset for AES-CTR (16-byte blocks)
                iv_int = int.from_bytes(iv, byteorder='big')
                block_index = start // 16
                new_iv_int = (iv_int + block_index) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
                new_iv = new_iv_int.to_bytes(16, byteorder='big')
                
                cipher = Cipher(algorithms.AES(key), modes.CTR(new_iv), backend=default_backend())
                decryptor = cipher.decryptor()
                
                # Seek to the start of the required block
                f.seek(block_index * 16)
                
                # Skip within the first block if the request isn't block-aligned
                skip_in_block = start % 16
                remaining_to_send = content_length
                
                # Stream in chunks
                is_first_chunk = True
                while remaining_to_send > 0:
                    read_len = min(CHUNK_SIZE, remaining_to_send + (skip_in_block if is_first_chunk else 0))
                    chunk = f.read(read_len)
                    if not chunk: break
                    
                    decrypted = decryptor.update(chunk)
                    
                    if is_first_chunk:
                        # Extract the requested part of the first block
                        chunk_to_yield = decrypted[skip_in_block:]
                        is_first_chunk = False
                    else:
                        chunk_to_yield = decrypted
                    
                    # Ensure we don't send more than the requested range
                    if len(chunk_to_yield) > remaining_to_send:
                        chunk_to_yield = chunk_to_yield[:remaining_to_send]
                    
                    yield chunk_to_yield
                    remaining_to_send -= len(chunk_to_yield)
                
                yield decryptor.finalize()
        except Exception as e:
            log_error(f"STREAM DOCTOR ERROR for {filename}", e)

    response = Response(
        stream_with_context(generate()),
        status_code,
        mimetype=mimetype
    )
    
    # Production-grade headers
    response.headers['Accept-Ranges'] = 'bytes'
    response.headers['Content-Length'] = str(content_length)
    if range_header:
        response.headers['Content-Range'] = f'bytes {start}-{end}/{total_size}'
    
    if as_attachment:
        # Clean filename for headers
        safe_filename = filename.encode('ascii', 'ignore').decode('ascii')
        response.headers['Content-Disposition'] = f'attachment; filename="{safe_filename}"'
    else:
        # For inline streaming (video/audio), some browsers prefer no disposition or just 'inline'
        response.headers['Content-Disposition'] = 'inline'
    
    # Security and Performance Headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.headers['X-Accel-Buffering'] = 'no' # Disable Nginx buffering for smooth streaming
    
    return response

@app.route('/api/files/<int:file_id>', methods=['DELETE'])
@token_required
def delete_file(current_user_id, file_id):
    """Delete a file"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('SELECT path, stored_filename FROM files WHERE id = ? AND user_id = ?', 
                      (file_id, current_user_id))
        file_info = cursor.fetchone()
        
        if not file_info:
            return jsonify({'message': 'File not found'}), 404
        
        file_path = file_info[0]
        stored_filename = file_info[1]
        
        if os.path.exists(file_path):
            os.remove(file_path)
        else:
            user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(current_user_id))
            fallback_path = os.path.join(user_folder, stored_filename)
            if os.path.exists(fallback_path):
                os.remove(fallback_path)
        
        cursor.execute('DELETE FROM shares WHERE file_id = ?', (file_id,))
        cursor.execute('DELETE FROM files WHERE id = ?', (file_id,))
        conn.commit()
        
        return jsonify({'message': 'File deleted successfully'}), 200
    except Exception as e:
        conn.rollback()
        print(f"Delete error: {e}")
        return jsonify({'message': f'Delete failed: {str(e)}'}), 500
    finally:
        cursor.close()
        conn.close()

def generate_short_token(length=12):
    """Generate a short unique token for sharing"""
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))

@app.route('/<token>')
def serve_share_page(token):
    """Serve share.html for a given share token"""
    # Check if it's a valid token (not a static file or api route)
    if token.startswith('api') or '.' in token:
        return send_from_directory(app.static_folder, token)
    
    # Check if the token is 12 characters (our standard length)
    if len(token) != 12:
        return send_from_directory(app.static_folder, 'index.html')
        
    # Verify token exists in database before serving
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT id FROM shares WHERE token = ?', (token,))
        share = cursor.fetchone()
    except Exception as e:
        print(f"DEBUG: Database error in serve_share_page: {e}")
        share = None
    finally:
        cursor.close()
        conn.close()
    
    if share:
        return send_from_directory(app.static_folder, 'share.html')
    
    # If it's a 12-char token but not in DB, show a dedicated error or share page
    # Instead of index.html, let's show share.html which will then handle the 404 nicely via API
    return send_from_directory(app.static_folder, 'share.html')

# SHARING ROUTES
@app.route('/api/shares/create', methods=['POST'])
@token_required
def create_share(current_user_id):
    """Create a shareable link"""
    data = request.get_json(silent=True) or {}
    file_id = data.get('file_id')
    password = data.get('password', '')
    
    log_error(f"CREATE SHARE REQUEST: UserID={current_user_id}, FileID={file_id}")
    
    if not file_id:
        return jsonify({'message': 'File ID is required'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Check if file exists and belongs to user
        cursor.execute('SELECT filename FROM files WHERE id = ? AND user_id = ?', 
                      (file_id, current_user_id))
        file_info = cursor.fetchone()
        
        if not file_info:
            log_error(f"Create share failed: File {file_id} not found for user {current_user_id}")
            return jsonify({'message': 'File not found'}), 404
        
        # Check if a share link already exists for this file without a password
        cursor.execute('''
            SELECT token, expires_at FROM shares 
            WHERE user_id = ? AND file_id = ? AND password IS NULL
            ORDER BY created_at DESC LIMIT 1
        ''', (current_user_id, file_id))
        existing_share = cursor.fetchone()
        
        if existing_share and not password:
            try:
                exp_date = datetime.datetime.fromisoformat(existing_share[1])
                if exp_date > datetime.datetime.now():
                    share_token = existing_share[0]
                    expires_at = exp_date
                    base_url = request.host_url.rstrip('/')
                    share_url = f"{base_url}/{share_token}"
                    log_error(f"Using existing share link: {share_token}")
                    return jsonify({
                        'message': 'Using existing share link',
                        'share': {
                            'url': share_url,
                            'token': share_token,
                            'expires_at': expires_at.isoformat()
                        }
                    }), 200
            except Exception as e:
                log_error(f"Existing share date parse error: {e}")

        # Generate a short token
        share_token = generate_short_token(12)
        
        # Ensure token uniqueness
        max_retries = 10
        retries = 0
        while retries < max_retries:
            cursor.execute('SELECT id FROM shares WHERE token = ?', (share_token,))
            if not cursor.fetchone():
                break
            share_token = generate_short_token(12)
            retries += 1
        
        if retries >= max_retries:
            log_error("Failed to generate unique share token after multiple attempts")
            return jsonify({'message': 'Token generation failed'}), 500
        
        expires_at = datetime.datetime.now() + datetime.timedelta(days=365*10)
        password_hash = generate_password_hash(password) if password else None
        
        log_error(f"Inserting share into DB: Token={share_token}")
        cursor.execute(
            'INSERT INTO shares (user_id, file_id, filename, token, password, expires_at) VALUES (?, ?, ?, ?, ?, ?)',
            (current_user_id, file_id, file_info[0], share_token, password_hash, expires_at.isoformat())
        )
        conn.commit()
        
        base_url = request.host_url.rstrip('/')
        share_url = f"{base_url}/{share_token}"
        
        log_error(f"Share link created successfully: {share_token}")
        return jsonify({
            'message': 'Share link created',
            'share': {
                'id': cursor.lastrowid,
                'url': share_url,
                'token': share_token,
                'expires_at': expires_at.isoformat()
            }
        }), 201
    except sqlite3.Error as e:
        conn.rollback()
        log_error("Database error during share creation", e)
        return jsonify({'message': f'Database error: {str(e)}'}), 500
    except Exception as e:
        conn.rollback()
        log_error("Unexpected error during share creation", e)
        return jsonify({'message': f'Server error: {str(e)}'}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/shares', methods=['GET'])
@token_required
def list_shares(current_user_id):
    """List user's shared links"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            SELECT id, file_id, filename, token, expires_at, access_count 
            FROM shares 
            WHERE user_id = ? 
            ORDER BY created_at DESC
        ''', (current_user_id,))
        shares = cursor.fetchall()
        
        base_url = request.host_url.rstrip('/')
        user_shares = [{
            'id': s[0],
            'file_id': s[1],
            'filename': s[2],
            'token': s[3],
            'url': f"{base_url}/{s[3]}",
            'expires_at': s[4],
            'access_count': s[5]
        } for s in shares]
        
        return jsonify({
            'shares': user_shares,
            'total_shares': len(user_shares)
        }), 200
    except Exception as e:
        print(f"List shares error: {e}")
        return jsonify({'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/shares/info/<token>', methods=['GET', 'POST'])
def get_share_info(token):
    """Get shared file info without downloading"""
    password = None
    if request.method == 'POST':
        try:
            data = request.get_json(silent=True) or {}
            password = data.get('password', '')
        except:
            password = ''
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('SELECT file_id, password, expires_at FROM shares WHERE token = ?', 
                      (token,))
        share = cursor.fetchone()
        
        if not share:
            return jsonify({'message': 'Share not found or expired'}), 404
        
        file_id = share[0]
        expires_at = share[2]
        
        # Check if share has expired
        if expires_at:
            try:
                exp_date = datetime.datetime.fromisoformat(expires_at)
                if exp_date < datetime.datetime.now():
                    return jsonify({'message': 'Link has expired'}), 401
            except:
                pass
        
        # Check if password is required and if it matches
        password_required = bool(share[1])
        if password_required:
            if not password or not check_password_hash(share[1], password):
                return jsonify({
                    'message': 'Password required' if not password else 'Invalid password',
                    'password_required': True
                }), 401
        
        cursor.execute('SELECT filename, size, type, uploaded_at FROM files WHERE id = ?', (file_id,))
        file_info = cursor.fetchone()
        
        if not file_info:
            return jsonify({'message': 'File not found'}), 404
            
        filename = file_info[0]
        file_type = file_info[2] or 'application/octet-stream'
        
        # Correct MIME type if it's vague
        if not file_info[2] or file_info[2] == 'application/octet-stream':
            ext = filename.split('.')[-1].lower()
            if ext == 'mp4': file_type = 'video/mp4'
            elif ext in ['mkv', 'webm']: file_type = 'video/webm'
            elif ext == 'mov': file_type = 'video/quicktime'
            elif ext in ['jpg', 'jpeg']: file_type = 'image/jpeg'
            elif ext == 'png': file_type = 'image/png'
            elif ext == 'gif': file_type = 'image/gif'
        
        return jsonify({
            'filename': filename,
            'size': file_info[1],
            'type': file_type,
            'uploaded_at': file_info[3],
            'password_required': password_required,
            'expires_at': expires_at
        }), 200
    except Exception as e:
        print(f"Share info error: {e}")
        return jsonify({'message': 'Failed to get share info'}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/shares/<int:share_id>', methods=['DELETE'])
@token_required
def delete_share(current_user_id, share_id):
    """Delete a share link"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('SELECT id FROM shares WHERE id = ? AND user_id = ?', 
                      (share_id, current_user_id))
        if not cursor.fetchone():
            return jsonify({'message': 'Share not found'}), 404
        
        cursor.execute('DELETE FROM shares WHERE id = ?', (share_id,))
        conn.commit()
        
        return jsonify({'message': 'Share deleted successfully'}), 200
    except Exception as e:
        conn.rollback()
        print(f"Delete share error: {e}")
        return jsonify({'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/shares/download/<token>', methods=['GET', 'POST'])
def download_shared_file(token):
    """Download a shared file"""
    log_error(f"DOWNLOAD REQUEST: Token={token}, Method={request.method}")
    password = None
    if request.method == 'POST':
        try:
            data = request.get_json(silent=True) or {}
            password = data.get('password', '')
        except:
            password = ''
    else:
        password = request.args.get('p')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('SELECT file_id, user_id, password, expires_at FROM shares WHERE token = ?', 
                      (token,))
        share = cursor.fetchone()
        
        if not share:
            log_error(f"Shared download failed: Token {token} not found in database")
            return jsonify({'message': 'Share not found'}), 404
        
        file_id = share[0]
        share_user_id = share[1]
        password_hash = share[2]
        expires_at = share[3]
        
        log_error(f"SHARE FOUND: FileID={file_id}, OwnerID={share_user_id}")
        
        # Check if share has expired
        if expires_at:
            try:
                exp_date = datetime.datetime.fromisoformat(expires_at)
                if exp_date < datetime.datetime.now():
                    log_error(f"Shared link expired: {expires_at}")
                    return jsonify({'message': 'Link has expired'}), 401
            except Exception as e:
                log_error(f"Expiry date error for token {token}", e)
        
        if password_hash:
            if not password or not check_password_hash(password_hash, password):
                log_error("Invalid password provided for shared file")
                return jsonify({'message': 'Invalid password'}), 401
        
        cursor.execute('SELECT path, filename, stored_filename, type, user_id, is_encrypted, iv, size FROM files WHERE id = ?', (file_id,))
        file_info = cursor.fetchone()
        
        if not file_info:
            log_error(f"Shared download failed: File ID {file_id} missing from files table")
            return jsonify({'message': 'File not found'}), 404
        
        file_path_db = file_info[0]
        original_filename = file_info[1]
        stored_filename = file_info[2]
        owner_user_id = file_info[4]
        is_encrypted = bool(file_info[5])
        iv_base64 = file_info[6]
        file_size = file_info[7]
        
        # Professional MIME detection
        file_type = get_mimetype(original_filename)
        
        log_error(f"FILE INFO: Path={file_path_db}, StoredName={stored_filename}, OwnerID={owner_user_id}")
        
        # Robust path resolution - handles Windows/Linux mismatches
        # Convert stored path to use current OS separators
        normalized_db_path = file_path_db.replace('\\', os.sep).replace('/', os.sep)
        
        potential_paths = [
            normalized_db_path,
            os.path.join(app.config['UPLOAD_FOLDER'], str(owner_user_id), stored_filename),
            os.path.join(app.config['UPLOAD_FOLDER'], stored_filename),
            os.path.abspath(normalized_db_path) if not os.path.isabs(normalized_db_path) else None,
            os.path.join(os.getcwd(), 'uploads', str(owner_user_id), stored_filename),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads', str(owner_user_id), stored_filename)
        ]
        
        actual_path = None
        log_error(f"FINDING SHARED FILE: {stored_filename}")
        for i, p in enumerate(potential_paths):
            if p:
                abs_p = os.path.abspath(p)
                exists = os.path.exists(abs_p)
                log_error(f"Path Check {i+1}: {abs_p} | Exists: {exists}")
                if exists and os.path.isfile(abs_p):
                    actual_path = abs_p
                    break
        
        if not actual_path:
            # Recursive search as last resort
            log_error(f"NOT FOUND in standard locations. Starting emergency recursive search in {app.config['UPLOAD_FOLDER']}...")
            for root, dirs, files in os.walk(app.config['UPLOAD_FOLDER']):
                if stored_filename in files:
                    actual_path = os.path.join(root, stored_filename)
                    log_error(f"EMERGENCY FIND: {actual_path}")
                    break
        
        if not actual_path:
            log_error(f"Shared download failed: File {stored_filename} NOT FOUND on server at any location")
            return jsonify({'message': 'File not found on server'}), 404
        
        log_error(f"FILE FOUND: {actual_path}")
        
        # Update access count
        cursor.execute('UPDATE shares SET access_count = access_count + 1 WHERE token = ?', (token,))
        conn.commit()
        
        # Check if it's a preview request
        is_preview = request.args.get('preview') == 'true'
        
        if is_encrypted and iv_base64:
            iv = base64.b64decode(iv_base64)
            # Use is_preview to determine if it should be an attachment
            return stream_decrypted_file(actual_path, app.config['ENCRYPTION_KEY'], iv, original_filename, file_type, file_size, as_attachment=not is_preview)
        
        try:
            return send_file(
                actual_path,
                as_attachment=not is_preview,
                download_name=original_filename,
                mimetype=file_type,
                conditional=True
            )
        except Exception as e:
            log_error(f"Shared send_file failed for {actual_path}", e)
            return jsonify({'message': f'Cannot serve file: {str(e)}'}), 500
    except Exception as e:
        log_error("Shared download exception", e)
        return jsonify({'message': f'Download failed: {str(e)}'}), 500
    finally:
        cursor.close()
        conn.close()

# STATS ROUTE
@app.route('/api/stats', methods=['GET'])
@token_required
def get_stats(current_user_id):
    """Get user statistics"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('SELECT COALESCE(SUM(size), 0) FROM files WHERE user_id = ?', 
                      (current_user_id,))
        total_size = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM files WHERE user_id = ?', (current_user_id,))
        total_files = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM shares WHERE user_id = ?', (current_user_id,))
        total_shares = cursor.fetchone()[0]
        
        cursor.execute('SELECT COALESCE(SUM(access_count), 0) FROM shares WHERE user_id = ?', 
                      (current_user_id,))
        total_views = cursor.fetchone()[0]
        
        return jsonify({
            'total_files': total_files,
            'total_size': total_size,
            'total_shares': total_shares,
            'total_views': total_views
        }), 200
    except Exception as e:
        print(f"Stats error: {e}")
        return jsonify({'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# ADMIN ROUTES
@app.route('/api/admin/stats', methods=['GET'])
@admin_required
def admin_stats(current_user_id):
    """Get admin dashboard statistics"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('SELECT COUNT(*) FROM users')
        total_users = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM files')
        total_files = cursor.fetchone()[0]
        
        cursor.execute('SELECT COALESCE(SUM(size), 0) FROM files')
        total_storage = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM shares')
        total_shares = cursor.fetchone()[0]

        # Get online users (seen in the last 5 minutes)
        five_minutes_ago = (datetime.datetime.now() - datetime.timedelta(minutes=5)).isoformat()
        cursor.execute('SELECT COUNT(*) FROM users WHERE last_seen > ?', (five_minutes_ago,))
        online_users = cursor.fetchone()[0]
        
        # Get registration status
        cursor.execute("SELECT value FROM settings WHERE key = 'registrations_enabled'")
        reg_status = cursor.fetchone()
        reg_enabled = (reg_status[0] == 'true') if reg_status else True
        
        return jsonify({
            'total_users': total_users,
            'total_files': total_files,
            'total_storage': total_storage,
            'total_shares': total_shares,
            'online_users': online_users,
            'registrations_enabled': reg_enabled
        }), 200
    except Exception as e:
        print(f"Admin stats error: {e}")
        return jsonify({'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/admin/settings/registrations', methods=['POST'])
@admin_required
def admin_toggle_registrations(current_user_id):
    """Enable or disable new user registrations"""
    data = request.get_json()
    enabled = data.get('enabled')
    
    if enabled is None:
        return jsonify({'message': 'Enabled status required'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        value = 'true' if enabled else 'false'
        cursor.execute("UPDATE settings SET value = ? WHERE key = 'registrations_enabled'", (value,))
        conn.commit()
        return jsonify({'message': f'Registrations {"enabled" if enabled else "disabled"} successfully'}), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/admin/users/<int:user_id>/block', methods=['POST'])
@admin_required
def admin_toggle_user_block(current_user_id, user_id):
    """Block or unblock a user"""
    if current_user_id == user_id:
        return jsonify({'message': 'Cannot block your own account'}), 400
        
    data = request.get_json()
    block = data.get('block')
    
    if block is None:
        return jsonify({'message': 'Block status required'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('UPDATE users SET is_blocked = ? WHERE id = ?', (1 if block else 0, user_id))
        conn.commit()
        return jsonify({'message': f'User {"blocked" if block else "unblocked"} successfully'}), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/admin/settings/blocked-countries', methods=['GET', 'POST'])
@admin_required
def admin_manage_blocked_countries(current_user_id):
    """Get or update blocked countries list (comma-separated ISO codes)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if request.method == 'POST':
        data = request.get_json()
        countries = data.get('countries', '').upper()
        try:
            cursor.execute("UPDATE settings SET value = ? WHERE key = 'blocked_countries'", (countries,))
            conn.commit()
            return jsonify({'message': 'Blocked countries updated successfully'}), 200
        except Exception as e:
            return jsonify({'message': str(e)}), 500
        finally:
            cursor.close()
            conn.close()
    else:
        try:
            cursor.execute("SELECT value FROM settings WHERE key = 'blocked_countries'")
            row = cursor.fetchone()
            return jsonify({'countries': row[0] if row else ''}), 200
        finally:
            cursor.close()
            conn.close()

@app.route('/api/admin/users', methods=['GET'])
@admin_required
def admin_list_users(current_user_id):
    """List all users"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            SELECT u.id, u.username, u.email, u.is_admin, u.created_at, u.is_blocked, u.last_seen,
                   COUNT(DISTINCT f.id) as file_count,
                   COALESCE(SUM(f.size), 0) as total_size
            FROM users u
            LEFT JOIN files f ON u.id = f.user_id
            GROUP BY u.id
            ORDER BY u.created_at DESC
        ''')
        users = cursor.fetchall()
        
        user_list = [{
            'id': u[0],
            'username': u[1],
            'email': u[2],
            'is_admin': bool(u[3]),
            'created_at': u[4],
            'is_blocked': bool(u[5]),
            'last_seen': u[6],
            'file_count': u[7],
            'total_size': u[8]
        } for u in users]
        
        return jsonify({'users': user_list}), 200
    except Exception as e:
        print(f"Admin list users error: {e}")
        return jsonify({'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@admin_required
def admin_delete_user(current_user_id, user_id):
    """Delete a user and their files"""
    if current_user_id == user_id:
        return jsonify({'message': 'Cannot delete your own account'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('SELECT path FROM files WHERE user_id = ?', (user_id,))
        files = cursor.fetchall()
        
        for file in files:
            try:
                if os.path.exists(file[0]):
                    os.remove(file[0])
            except Exception as e:
                print(f"Error deleting file {file[0]}: {e}")
        
        user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(user_id))
        if os.path.exists(user_folder):
            import shutil
            shutil.rmtree(user_folder)
        
        cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        
        return jsonify({'message': 'User deleted successfully'}), 200
    except Exception as e:
        conn.rollback()
        print(f"Admin delete user error: {e}")
        return jsonify({'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/admin/users/create', methods=['POST'])
@admin_required
def admin_create_user(current_user_id):
    """Admin creates a new user"""
    data = request.get_json()
    
    if not data or not data.get('email') or not data.get('password') or not data.get('username'):
        return jsonify({'message': 'Missing required fields'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('SELECT id FROM users WHERE email = ?', (data['email'],))
        if cursor.fetchone():
            return jsonify({'message': 'Email already exists'}), 400
        
        is_admin = 1 if data.get('is_admin') else 0
        
        cursor.execute(
            'INSERT INTO users (username, email, password, is_admin) VALUES (?, ?, ?, ?)',
            (data['username'], data['email'], generate_password_hash(data['password']), is_admin)
        )
        conn.commit()
        
        return jsonify({
            'message': 'User created successfully',
            'user': {
                'id': cursor.lastrowid,
                'username': data['username'],
                'email': data['email'],
                'is_admin': bool(is_admin)
            }
        }), 201
    except Exception as e:
        conn.rollback()
        print(f"Admin create user error: {e}")
        return jsonify({'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/admin/users/<int:user_id>/toggle-admin', methods=['POST'])
@admin_required
def admin_toggle_admin(current_user_id, user_id):
    """Toggle admin status for a user"""
    if current_user_id == user_id:
        return jsonify({'message': 'Cannot modify your own admin status'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('SELECT is_admin FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        new_admin_status = 0 if user[0] else 1
        cursor.execute('UPDATE users SET is_admin = ? WHERE id = ?', (new_admin_status, user_id))
        conn.commit()
        
        return jsonify({
            'message': 'Admin status updated',
            'is_admin': bool(new_admin_status)
        }), 200
    except Exception as e:
        conn.rollback()
        print(f"Admin toggle error: {e}")
        return jsonify({'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/admin/files', methods=['GET'])
@admin_required
def admin_list_all_files(current_user_id):
    """List all files from all users"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            SELECT f.id, f.filename, f.size, f.uploaded_at, 
                   u.username, u.email, f.user_id
            FROM files f
            JOIN users u ON f.user_id = u.id
            ORDER BY f.uploaded_at DESC
        ''')
        files = cursor.fetchall()
        
        file_list = [{
            'id': f[0],
            'filename': f[1],
            'size': f[2],
            'uploaded_at': f[3],
            'username': f[4],
            'user_email': f[5],
            'user_id': f[6]
        } for f in files]
        
        return jsonify({'files': file_list}), 200
    except Exception as e:
        print(f"Admin list files error: {e}")
        return jsonify({'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/admin/files/<int:file_id>', methods=['DELETE'])
@admin_required
def admin_delete_file(current_user_id, file_id):
    """Delete any file as admin"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('SELECT path, stored_filename, user_id FROM files WHERE id = ?', (file_id,))
        file_info = cursor.fetchone()
        
        if not file_info:
            return jsonify({'message': 'File not found'}), 404
        
        file_path = file_info[0]
        stored_filename = file_info[1]
        user_id = file_info[2]
        
        if os.path.exists(file_path):
            os.remove(file_path)
        else:
            user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(user_id))
            fallback_path = os.path.join(user_folder, stored_filename)
            if os.path.exists(fallback_path):
                os.remove(fallback_path)
        
        cursor.execute('DELETE FROM shares WHERE file_id = ?', (file_id,))
        cursor.execute('DELETE FROM files WHERE id = ?', (file_id,))
        conn.commit()
        
        return jsonify({'message': 'File deleted successfully'}), 200
    except Exception as e:
        conn.rollback()
        print(f"Admin delete file error: {e}")
        return jsonify({'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# SERVE STATIC FILES
@app.route('/')
def index():
    """Serve index.html"""
    try:
        return send_from_directory('static', 'index.html')
    except Exception as e:
        return jsonify({'message': 'Frontend not found. Please ensure index.html is in the static folder.'}), 404

@app.route('/<path:path>')
def serve_static(path):
    """Serve static files"""
    try:
        return send_from_directory('static', path)
    except:
        return jsonify({'message': 'File not found'}), 404

# ERROR HANDLERS
@app.errorhandler(404)
def not_found(error):
    return jsonify({'message': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    print(f"Internal error: {error}")
    return jsonify({'message': 'Internal server error'}), 500

@app.errorhandler(413)
def too_large(error):
    return jsonify({'message': 'File too large. Maximum size is 100MB'}), 413

if __name__ == '__main__':
    print("\n" + "="*50)
    print("🚀 Cloud Storage Backend Starting...")
    print("="*50)
    
    if init_database():
        # Path Doctor - Production Diagnostics
        abs_root = os.path.dirname(os.path.abspath(__file__))
        abs_uploads = os.path.abspath(app.config['UPLOAD_FOLDER'])
        abs_db = os.path.abspath(DB_PATH)
        
        log_error("--- PATH DOCTOR ---")
        log_error(f"APP ROOT: {abs_root}")
        log_error(f"UPLOAD FOLDER: {abs_uploads}")
        log_error(f"DATABASE: {abs_db}")
        log_error(f"CURRENT WORKING DIR: {os.getcwd()}")
        log_error(f"ENCRYPTION KEY STATUS: {'STABLE' if os.getenv('ENCRYPTION_KEY') else 'FALLBACK (Using Secret Key)'}")
        log_error("-------------------")
        
        app.run(debug=True, host='0.0.0.0', port=5000)
    else:
        print("\n❌ Failed to initialize database. Exiting...")
        exit(1)