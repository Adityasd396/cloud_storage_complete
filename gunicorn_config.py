# Gunicorn Configuration for Cloud Storage
import multiprocessing

# Bind to all interfaces on port 5000
bind = "0.0.0.0:5000"

# Number of worker processes
# Standard formula: (2 * cores) + 1
workers = multiprocessing.cpu_count() * 2 + 1

# Worker type - 'gthread' is excellent for I/O bound tasks like file streaming
worker_class = "gthread"

# Number of threads per worker
threads = 10

# CRITICAL: Timeout for large file transfers (100GB files)
# Set to 1 hour (3600 seconds) or more to prevent Gunicorn from killing workers during long transfers
timeout = 36000

# Keep-alive connections to improve performance
keepalive = 50

# Maximum number of simultaneous clients
worker_connections = 10000

# Logging
accesslog = "gunicorn_access.log"
errorlog = "gunicorn_error.log"
loglevel = "info"

# Preload application to save memory and speed up startup
preload_app = True
