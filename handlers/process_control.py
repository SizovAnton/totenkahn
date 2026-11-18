import subprocess
import sys

def terminate_process(process):
    if process.poll() is not None:
        return

    if sys.platform == 'win32':
        try:
            subprocess.run(
                ['taskkill.exe', '/PID', str(process.pid), '/T', '/F'],
                capture_output=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass

    if process.poll() is None:
        process.kill()

    process.wait(timeout=15)
