#!/usr/bin/env python3
"""
Run the Cyber Security Monitor application
"""
import sys
import os

# Get the absolute path of the current directory
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

# Now import and run the app
from backend.app import app, start_monitoring

if __name__ == '__main__':
    print("=" * 60)
    print("CYBER SECURITY MONITOR")
    print("=" * 60)
    print("Starting server...")
    print("Access the application at: http://localhost:5000")
    print("Press Ctrl+C to stop")
    print("-" * 60)
    print("Default login: admin / admin (set ADMIN_USERNAME/ADMIN_PASSWORD in .env)")

    # Starts the always-on background scanner (works even if the browser is closed)
    start_monitoring()

    # use_reloader=False keeps a single main process so the monitor thread
    # does not get duplicated by the auto-reloader.
    app.run(debug=True, port=5000, host='0.0.0.0', use_reloader=False)