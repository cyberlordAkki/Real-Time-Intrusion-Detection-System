import subprocess, os, signal, sys

PID_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rt_pid.txt")
ENGINE   = os.path.join(os.path.dirname(os.path.abspath(__file__)), "realtime_engine.py")

def start_realtime():
    if os.path.exists(PID_FILE):
        return False, "Already Running"
    p = subprocess.Popen([sys.executable, ENGINE])   # sys.executable = correct python path
    with open(PID_FILE, "w") as f:
        f.write(str(p.pid))
    return True, "Started"

def stop_realtime():
    if not os.path.exists(PID_FILE):
        return False, "Not Running"
    try:
        pid = int(open(PID_FILE).read())
        os.kill(pid, signal.SIGTERM)
    except:
        pass
    os.remove(PID_FILE)
    return True, "Stopped"

def is_running():
    return os.path.exists(PID_FILE)
