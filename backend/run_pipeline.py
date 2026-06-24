import subprocess
import sys
import os

def main():
    print("\n=== ClearSOC Pipeline ===")
    script = os.path.join(os.path.dirname(__file__), "soc_pipeline_v2.py")
    result = subprocess.run([sys.executable, script])
    if result.returncode != 0:
        print("[FAILED] Pipeline exited with errors.")
        sys.exit(1)
    print("[OK] Pipeline completed successfully.")

if __name__ == "__main__":
    main()
