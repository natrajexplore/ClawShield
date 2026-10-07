"""Slack incoming-webhook notifier (FR-20).

- The webhook URL is a secret: read from the env var *named* in config at send time,
  never logged, never included in an error message.
- Only https://hooks.slack.com/... is accepted, so a tampered or mistaken config cannot
  redirect alerts (and the metrics in them) to an arbitrary host.
- Messages carry run ids and metrics only: never prompt, response or canary text.
"""

import json
import urllib.error
import urllib.request
from collections.abc import Callable
from urllib.parse import urlsplit

from clawshield.config import read_secret

SLACK_HOST = "hooks.slack.com"
TIMEOUT_S = 10
MAX_TEXT = 3000

Opener = Callable[..., object]


class NotifyError(Exception):
    """The alert could not be sent. Message never contains the webhook URL."""


def validate_webhook(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.hostname != SLACK_HOST or parts.port not in (None, 443):
        raise NotifyError(f"webhook must be an https://{SLACK_HOST}/ URL")
    if parts.username or parts.password:
        raise NotifyError("webhook URL must not contain credentials")
    if not parts.path.startswith("/services/"):
        raise NotifyError("webhook path must start with /services/")


def send_slack(env_name: str | None, text: str, *, opener: Opener = urllib.request.urlopen) -> None:
    secret = read_secret(env_name)
    if secret is None:
        raise NotifyError(f"environment variable {env_name} is not set")
    url = secret.get_secret_value()
    validate_webhook(url)
    body = json.dumps({"text": text[:MAX_TEXT]}).encode("utf-8")
    request = urllib.request.Request(  # noqa: S310 - scheme/host validated above
        url, data=body, method="POST", headers={"Content-Type": "application/json"}
    )
    try:
        response = opener(request, timeout=TIMEOUT_S)
    except urllib.error.HTTPError as exc:
        raise NotifyError(f"Slack rejected the alert: HTTP {exc.code}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise NotifyError(f"cannot reach Slack: {type(reason).__name__}") from None
    status = getattr(response, "status", 200)
    if status != 200:
        raise NotifyError(f"Slack rejected the alert: HTTP {status}")
