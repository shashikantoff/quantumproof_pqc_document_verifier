"""Start the API after syncing the demo issuer (for ephemeral-disk hosts like Render free).

Run as:  python -m app.start_demo
No shell quoting is needed, so it works as a plain Render "Docker Command".
"""

import os
import sys
import traceback


def main() -> None:
    try:
        from .sync_demo_issuer import main as sync_main

        sync_main()
    except Exception:  # never block the API from starting
        traceback.print_exc()
        print("WARNING: demo issuer sync failed; starting API anyway", flush=True)

    port = os.environ.get("PORT", "8000")
    os.execvp(
        sys.executable,
        [
            sys.executable,
            "-m",
            "uvicorn",
            "app.main:app",
            "--host",
            "0.0.0.0",
            "--port",
            port,
        ],
    )


if __name__ == "__main__":
    main()
