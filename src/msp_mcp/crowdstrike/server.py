"""CrowdStrike Falcon: launches CrowdStrike's official falcon-mcp with our credential.

falcon-mcp (github.com/CrowdStrike/falcon-mcp, MIT) needs mcp<2 and this repo uses mcp 2.x, so it
lives in its own venv (%LOCALAPPDATA%\\MSP-MCP\\falcon-venv, pinned version, see README). This
module reads the API client from the shared store (`CrowdStrikeFalconApi`: username = client ID,
password = client secret), puts it in falcon-mcp's environment and runs it over stdio.

- Read-only unless MSP_MCP_CROWDSTRIKE_WRITES=1 (falcon-mcp --read-only drops every mutating
  tool). falcon-mcp's write tools have no dry run and are not in our audit log beyond the start.
- Modules: CROWDSTRIKE_MODULES (comma list), else DEFAULT_MODULES. The API client's scopes are
  the real limit; a module without its scope answers 403.
- FALCON_BASE_URL defaults to US-1; falconpy follows the redirect to the tenant's own cloud.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from msp_mcp.core.credentials import load_machine_credential
from msp_mcp.core.guard import audit, writes_enabled

DEFAULT_MODULES = ("detections,hosts,hostgroups,policies,exclusions,quarantine,ioc,"
                   "discover,sensorusage,zerotrustassessment")


def falcon_exe() -> Path:
    env = os.environ.get("FALCON_MCP_EXE")
    if env:
        return Path(env)
    base = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "MSP-MCP" / "falcon-venv"
    return base / "Scripts" / "falcon-mcp.exe"


def main() -> None:
    exe = falcon_exe()
    if not exe.exists():
        sys.exit(f"falcon-mcp not found at {exe}; install it (see MSP-MCP README, CrowdStrike).")
    client_id, secret = load_machine_credential("CrowdStrikeFalconApi")
    env = dict(os.environ, FALCON_CLIENT_ID=client_id, FALCON_CLIENT_SECRET=secret,
               FALCON_MCP_TRANSPORT="stdio",
               FALCON_MCP_MODULES=os.environ.get("CROWDSTRIKE_MODULES") or DEFAULT_MODULES,
               FALCON_MCP_USER_AGENT_COMMENT="msp-mcp")
    if writes_enabled("crowdstrike"):
        env.pop("FALCON_MCP_READ_ONLY", None)
        audit("crowdstrike", "start", {"modules": env["FALCON_MCP_MODULES"]}, "writes enabled")
    else:
        env["FALCON_MCP_READ_ONLY"] = "true"
    # Run from the venv folder: falcon-mcp loads a .env from the working directory.
    r = subprocess.run([str(exe)], env=env, cwd=exe.parent)
    sys.exit(r.returncode)


if __name__ == "__main__":
    main()
