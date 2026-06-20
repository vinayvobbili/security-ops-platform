"""
XSOAR Markdown Image Operations

Download images / pasted screenshots embedded in XSOAR case notes. Analysts
routinely paste evidence (original-request emails, tool screenshots) directly
into war-room notes as markdown images served from ``/markdown/image/<name>``.
Those are not returned as text by the investigation API, so this module pulls
the raw bytes for offline viewing / OCR.
"""
import logging
import os
import re

from ._client import ApiException
from ._retry import truncate_error_message

log = logging.getLogger(__name__)

DEFAULT_IMAGE_DIR = "data/transient/xsoar_images"

# Accept headers covering the formats XSOAR serves for pasted images.
_ACCEPT = ["image/png", "image/jpeg", "image/gif", "image/*", "application/octet-stream"]


def normalize_image_ref(image_ref: str) -> str:
    """Reduce any image reference to its bare server filename.

    Accepts a bare filename, a ``/xsoar/markdown/image/<name>`` path, a full
    URL, or a whole ``![alt](path)`` markdown snippet, and returns ``<name>``.
    """
    ref = (image_ref or "").strip()
    # If a full markdown image snippet was passed, pull the URL out of (...).
    m = re.search(r"\(([^)]+)\)\s*$", ref)
    if m:
        ref = m.group(1).strip()
    # Drop any query string / fragment, then take the last path segment.
    ref = ref.split("?", 1)[0].split("#", 1)[0]
    name = ref.rstrip("/").rsplit("/", 1)[-1]
    if not name:
        raise ValueError(f"Could not extract an image filename from: {image_ref!r}")
    return name


def download_markdown_image(client, image_ref: str, dest_dir: str = DEFAULT_IMAGE_DIR) -> dict:
    """Download a single markdown-embedded image from XSOAR to disk.

    Args:
        client: demisto-py client (TicketHandler.client).
        image_ref: bare filename, markdown image path/URL, or ``![](...)`` snippet.
        dest_dir: directory to write the image into (created if missing).

    Returns:
        ``{"path", "filename", "bytes", "content_type"}``.

    Raises:
        ApiException: if every candidate endpoint path fails.
    """
    name = normalize_image_ref(image_ref)

    # The configured host may or may not already include the ``/xsoar`` prefix
    # that appears in stored note paths, so try both forms.
    candidate_paths = [f"/markdown/image/{name}", f"/xsoar/markdown/image/{name}"]

    last_err = None
    for path in candidate_paths:
        try:
            resp = client.generic_request(
                path=path,
                method="GET",
                accept=_ACCEPT,
                _preload_content=False,
                _return_http_data_only=True,
            )
            data = resp.data
            if not data:
                last_err = ApiException(status=204, reason=f"empty body from {path}")
                continue
            content_type = ""
            try:
                content_type = resp.getheader("Content-Type") or ""
            except Exception:
                pass

            os.makedirs(dest_dir, exist_ok=True)
            out_path = os.path.join(dest_dir, name)
            with open(out_path, "wb") as fh:
                fh.write(data)

            log.info(f"Downloaded XSOAR image {name} ({len(data)} bytes) via {path}")
            return {
                "path": out_path,
                "filename": name,
                "bytes": len(data),
                "content_type": content_type,
            }
        except ApiException as e:
            last_err = e
            log.debug(f"Image fetch failed at {path}: {truncate_error_message(e)}")
            continue

    raise last_err or ApiException(reason=f"Could not download image {name}")
