import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cloud_storage.db')

def migrate():
    print(f"Starting migration for {DB_PATH}...")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # 1. Add missing columns to users table
    columns_to_add = [
        ('is_blocked', 'INTEGER DEFAULT 0'),
        ('last_seen', 'TIMESTAMP')
    ]
    
    cursor.execute("PRAGMA table_info(users)")
    existing_columns = [col[1] for col in cursor.fetchall()]
    
    for col_name, col_type in columns_to_add:
        if col_name not in existing_columns:
            print(f"Adding column {col_name} to users table...")
            cursor.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_type}")
        else:
            print(f"Column {col_name} already exists in users table.")
            
    # 2. Create settings table if not exists
    print("Creating settings table if not exists...")
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    ''')
    
    # 3. Insert default settings
    print("Inserting default settings...")
    cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('registrations_enabled', 'true')")
    cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('blocked_countries', '')")
    
    conn.commit()
    conn.close()
    print("Migration completed successfully!")

if __name__ == "__main__":
    migrate()
