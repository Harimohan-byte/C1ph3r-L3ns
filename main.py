"""Root application entrypoint for CIPHER LENS.

Boots the unified FastAPI application and serves both the /api/v1/ REST engine
and the high-contrast React cyber frontend on 0.0.0.0:$PORT.
"""

import os
import sys
from pathlib import Path

# Ensure src/ is on Python module search path
_root = Path(__file__).resolve().parent
_src = _root / "src"
if str(_src) not in sys.path:
    sys.path.insert(0, str(_src))

import uvicorn

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    host = "0.0.0.0"
    print(f"\n[CIPHER LENS] Launching Autonomous VAPT Advisory System on http://{host}:{port}")
    uvicorn.run("cipher_lens.api.main:app", host=host, port=port, reload=False)

