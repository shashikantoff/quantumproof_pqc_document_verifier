import json
import os
from pathlib import Path
from urllib.parse import urlsplit


webhook_url = os.environ.get("ALERT_WEBHOOK_URL", "").strip()
parsed_url = urlsplit(webhook_url)
if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
    raise SystemExit(
        "ALERT_WEBHOOK_URL must be an absolute HTTP(S) URL to enable monitoring."
    )

template = Path("/template/alertmanager.yml.template").read_text(encoding="utf-8")
rendered = template.replace("__ALERT_WEBHOOK_URL__", json.dumps(webhook_url))
Path("/output/alertmanager.yml").write_text(rendered, encoding="utf-8")
