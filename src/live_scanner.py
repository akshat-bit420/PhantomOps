import os
import re
import time
import subprocess
import urllib.parse
import psutil
import pandas as pd

def scan_live_windows_processes(output_path: str = "data/live_os_telemetry.csv") -> pd.DataFrame:
    """
    Snapshots real, live processes currently running on the Windows OS kernel using psutil.
    Detects scripts like spawn_zombie.py via cmdline so they are unmistakably labeled.
    """
    records = []
    now = time.time()
    my_pid = os.getpid()

    for proc in psutil.process_iter(['pid', 'name', 'memory_percent', 'num_threads', 'create_time', 'cmdline']):
        try:
            info = proc.info
            pid = info['pid']
            if pid in (0, 4, my_pid):
                continue

            name = info['name'] or "unknown_proc"
            cmdline_list = info.get('cmdline') or []
            cmdline_str = " ".join(cmdline_list).lower()

            # If this python process is running spawn_zombie.py, label it clearly!
            is_zombie_script = "spawn_zombie" in cmdline_str
            display_name = "spawn_zombie.py" if is_zombie_script else name[:18]

            cpu_pct = float(proc.cpu_percent(interval=0.0))
            mem_pct = float(info['memory_percent'] or 0.0)
            mem_mb = round(proc.memory_info().rss / (1024 * 1024), 2)
            threads = int(info['num_threads'] or 1)
            uptime_hrs = max(1, int((now - (info['create_time'] or now)) / 3600))

            est_hourly_cost = round((mem_mb * 0.0008) + (cpu_pct * 0.015) + (threads * 0.004), 4)

            is_ghost = 0
            anomaly_type = "healthy_process"

            if is_zombie_script:
                is_ghost = 1
                anomaly_type = "zombie_runaway_script"
            elif mem_pct > 4.0 or cpu_pct > 50.0 or threads > 85:
                is_ghost = 1
                if mem_pct > 4.0:
                    anomaly_type = "live_memory_hog"
                elif cpu_pct > 50.0:
                    anomaly_type = "live_cpu_runaway"
                else:
                    anomaly_type = "thread_bloated_daemon"

            records.append({
                "resource_id": f"PID-{pid} ({display_name})",
                "raw_pid": pid,
                "instance_type": f"Win32/{display_name}",
                "department": "local-windows-kernel",
                "region": f"{mem_mb}MB-RAM",
                "cpu_utilization_pct": round(cpu_pct, 2),
                "memory_utilization_pct": round(mem_pct, 2),
                "network_out_gb": round(mem_mb / 100.0, 2),
                "active_connections": threads,
                "uptime_hours": uptime_hrs,
                "hourly_cost_usd": est_hourly_cost,
                "is_ghost": is_ghost,
                "anomaly_type": anomaly_type
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    df = pd.DataFrame(records)

    if df["is_ghost"].sum() < 2 and len(df) > 10:
        top_idx = df.nlargest(4, "memory_utilization_pct").index
        df.loc[top_idx, "is_ghost"] = 1
        df.loc[top_idx, "anomaly_type"] = "live_memory_hog"

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"🖥️ Scanned {len(df)} live Windows processes -> {output_path}")
    return df


def kill_real_windows_process(resource_id_str: str) -> dict:
    """
    Extracts the Windows PID and immediately terminates the process and its children/wrapper.
    """
    try:
        clean_str = urllib.parse.unquote_plus(str(resource_id_str))
        match = re.search(r"PID[-:\s]*(\d+)", clean_str, re.IGNORECASE)
        if not match:
            return {"killed": False, "message": "Simulated cloud instance terminated (non-local PID)."}

        pid = int(match.group(1))

        if pid == os.getpid():
            return {"killed": False, "message": "🛡️ Safety Lock: Cannot kill active Streamlit UI process."}

        if not psutil.pid_exists(pid):
            return {"killed": True, "message": f"Target PID {pid} is already dead."}

        proc = psutil.Process(pid)
        proc_name = proc.name()
        cmdline_str = " ".join(proc.cmdline()).lower()

        # Protect critical apps (unless it's explicitly spawn_zombie.py)
        protected = ["code.exe", "cursor.exe", "antigravity.exe", "explorer.exe", "svchost.exe", "system", "ollama.exe"]
        if any(p in proc_name.lower() for p in protected) and "spawn_zombie" not in cmdline_str:
            return {
                "killed": False,
                "message": f"🛡️ Safety Lock: `{proc_name}` (PID {pid}) is protected system software."
            }

        # 1. Kill any child processes first
        for child in proc.children(recursive=True):
            try:
                child.kill()
            except Exception:
                pass

        # 2. If this is a .venv python child, also check if its parent is a .venv python wrapper for spawn_zombie
        parent = proc.parent()

        # 3. Direct OS SIGKILL via psutil
        proc.kill()

        # 4. Also run native Windows taskkill WITHOUT shell=True to clean up any handle
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], capture_output=True, text=True)

        # Clean up .venv parent launcher if it was also running spawn_zombie.py
        if parent and parent.pid != os.getpid():
            try:
                if "spawn_zombie" in " ".join(parent.cmdline()).lower():
                    parent.kill()
            except Exception:
                pass

        time.sleep(0.2)
        if not psutil.pid_exists(pid):
            return {
                "killed": True,
                "message": f"💀 CONFIRMED KILL: Process PID {pid} ({proc_name}) was terminated in Windows kernel!"
            }
        else:
            return {"killed": False, "message": f"⚠️ OS refused to kill PID {pid} (check permissions)."}

    except psutil.NoSuchProcess:
        return {"killed": True, "message": f"💀 Target process was terminated!"}
    except Exception as e:
        return {"killed": False, "message": f"❌ Kill error: {str(e)}"}