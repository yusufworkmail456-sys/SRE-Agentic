"""Dev entrypoint: python -m sre_platform.run"""
from __future__ import annotations

import uvicorn

from .config import settings

if __name__ == "__main__":
    uvicorn.run(
        "sre_platform.app:app",
        host=settings.host,
        port=settings.port,
        log_level="info",
    )
