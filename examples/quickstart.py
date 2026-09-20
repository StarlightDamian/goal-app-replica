"""Run an isolated controller demo; no browser or target application is accessed."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    controller = Path(__file__).resolve().parents[1] / "scripts" / "replica_ctl.py"
    with tempfile.TemporaryDirectory(prefix="goal-app-replica-demo-") as directory:
        root = Path(directory)
        code = root / "code"
        code.mkdir()
        workspace = root / "state" / "demo-web"
        commands = [
            ["start", "--project-id", "demo-web", "--workspace-root", str(root / "state"),
             "--code-root", str(code), "--reference-id", "demo-reference",
             "--reference-platform", "web", "--replica-id", "demo-replica",
             "--replica-platform", "web", "--web-fidelity", "functional",
             "--asset-rights", "user_owned", "--reference-write-policy", "read_only"],
            ["status", "--workspace", str(workspace)],
            ["validate", "--workspace", str(workspace)],
        ]
        for arguments in commands:
            result = subprocess.run([sys.executable, str(controller), *arguments],
                                    check=True, capture_output=True, text=True, encoding="utf-8")
            payload = json.loads(result.stdout)
            if payload.get("ok") is not True:
                raise RuntimeError(result.stdout)
            if arguments[0] == "validate" and payload.get("valid") is not True:
                raise RuntimeError(result.stdout)
            print(result.stdout.strip())
    print("Demo passed: start -> status -> validate. Temporary workspace removed.")


if __name__ == "__main__":
    main()
