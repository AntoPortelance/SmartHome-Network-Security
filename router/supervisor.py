"""Stop the container if either the firewall logger or dashboard exits."""

import signal
import subprocess
import sys
import threading

stopping = threading.Event()
for signum in (signal.SIGTERM, signal.SIGINT):
    signal.signal(signum, lambda *_: stopping.set())

processes = []
exit_code = 0
try:
    processes.append(subprocess.Popen(["ulogd", "-c", "/etc/ulogd.conf"]))
    processes.append(subprocess.Popen([sys.executable, "-u", "/app/app.py"]))
    while not stopping.wait(0.2):
        if any(process.poll() is not None for process in processes):
            exit_code = 1
            break
finally:
    for process in processes:
        if process.poll() is None:
            process.terminate()
    for process in processes:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
sys.exit(exit_code)
