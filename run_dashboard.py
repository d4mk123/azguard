import os
import subprocess
import sys
from pathlib import Path

if __name__ == "__main__":
    app = Path("src/azguard/dashboard.py").resolve()
    env = dict(os.environ)
    src = Path("src").resolve()
    env["PYTHONPATH"] = str(src) + os.pathsep + env.get("PYTHONPATH", "")
    subprocess.run(
        [sys.executable, "-m", "streamlit", "run", str(app), "--", *sys.argv[1:]],
        check=True,
        env=env,
    )
