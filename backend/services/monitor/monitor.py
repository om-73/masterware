import time
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import sys
# Add shared directory to path
current_dir = os.path.dirname(os.path.abspath(__file__))
shared_dir = os.path.abspath(os.path.join(current_dir, '../../shared'))
sys.path.append(shared_dir)

from analyzer import analyze_local
from quarantine import quarantine_file

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MONITOR_DIR = os.path.join(BASE_DIR, "monitored_folder")
LOG_FILE = os.path.join(BASE_DIR, "monitor_log.txt")

os.makedirs(MONITOR_DIR, exist_ok=True)

class MalwareEventHandler(FileSystemEventHandler):
    def __init__(self, callback):
        self.callback = callback

    def on_created(self, event):
        if not event.is_directory:
            # Give file a moment to finish writing
            time.sleep(1) 
            self.callback(event.src_path)

class FolderMonitor:
    def __init__(self, directory=MONITOR_DIR):
        self.directory = directory
        self.observer = Observer()
        self.handler = MalwareEventHandler(self.handle_new_file)
        self.is_running = False

    def start(self):
        if not self.is_running:
            self.observer.schedule(self.handler, self.directory, recursive=False)
            self.observer.start()
            self.is_running = True
            print(f"[*] Monitor started on {self.directory}")

    def stop(self):
        if self.is_running:
            self.observer.stop()
            self.observer.join()
            self.is_running = False
            print("[*] Monitor stopped")

    def handle_new_file(self, file_path):
        filename = os.path.basename(file_path)
        # Skip temp files
        if filename.startswith('.') or filename.endswith('.tmp'):
            return

        print(f"[*] New file detected: {filename}")
        
        # Run Local Analysis
        try:
            report = analyze_local(file_path, filename)
            print(f"[*] Analysis complete. Score: {report['score']} ({report['risk']})")
            
            # Auto-Quarantine if Critical
            if report['risk'] == "Critical":
                print(f"[!] Critical Threat! Auto-quarantining {filename}...")
                success, msg = quarantine_file(file_path, filename, "Critical")
                if success:
                    print(f"    -> Quarantined: {msg}")
            
            # In a real app, we'd push this event to the UI via WebSocket
            # Here we can log it to a monitor_log.txt or DB
            self.log_event(filename, report['score'], report['risk'])

        except Exception as e:
            print(f"[!] Error analyzing {filename}: {e}")

    def log_event(self, filename, score, risk):
        # Simple text log for now
        with open(LOG_FILE, "a") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {filename} | Score: {score} | Risk: {risk}\n")

# Global instance
monitor_service = FolderMonitor()
