"""Minimal GitLab REST client — open a detection-as-code merge request.

Used by the detection-as-code pipeline to push a reviewed detection to the
detection-content repo as a merge request (branch + commit + MR), so the
repo's own CI/CD pipeline takes it the rest of the way to XSIAM. This is the
only write path; everything upstream (lint, compile, dry-run, review) is local.

Configuration is read straight from the environment so the client is fully
self-contained and inert until a token is provisioned (no creds = not
configured = the pipeline surfaces a clear "configure GitLab" message rather
than failing). GitLab is corp-internal, so when GITLAB_USE_SOCKS is enabled the
client egresses through the corp SOCKS proxy (localhost:1079), same as the other corp-internal clients.

Env:
  GITLAB_BASE_URL        e.g. https://gitlab.example.com   (no trailing /api)
  GITLAB_API_TOKEN       a personal/project access token with api+write_repository
  GITLAB_PROJECT_ID      numeric id OR url-encoded path (group%2Fproject)
  GITLAB_DEFAULT_BRANCH  base branch for MRs (default: main)
  GITLAB_DETECTION_PATH  repo dir detections live under (default: detections)
  GITLAB_USE_SOCKS       true|false — egress via corp SOCKS :1079 (default: true)
  GITLAB_SOCKS_URL       override the SOCKS url (default: socks5h://localhost:1079)
"""

from __future__ import annotations

import logging
import os
from typing import Dict, Optional
from urllib.parse import quote

import requests

logger = logging.getLogger(__name__)

_TIMEOUT = 30


def _env(key: str, default: str = "") -> str:
    return (os.environ.get(key) or default).strip()


class GitLabClient:
    """Thin GitLab v4 REST wrapper scoped to the one operation we need."""

    def __init__(self):
        self.base_url = _env("GITLAB_BASE_URL").rstrip("/")
        self.token = _env("GITLAB_API_TOKEN")
        self.project_id = _env("GITLAB_PROJECT_ID")
        self.default_branch = _env("GITLAB_DEFAULT_BRANCH", "main")
        self.detection_path = _env("GITLAB_DETECTION_PATH", "detections").strip("/")
        self.use_socks = _env("GITLAB_USE_SOCKS", "true").lower() not in ("false", "0", "no")
        self.socks_url = _env("GITLAB_SOCKS_URL", "socks5h://localhost:1079")

    # ── config ────────────────────────────────────────────────────────────────
    def is_configured(self) -> bool:
        return bool(self.base_url and self.token and self.project_id)

    def config_hint(self) -> str:
        missing = [k for k, v in (
            ("GITLAB_BASE_URL", self.base_url),
            ("GITLAB_API_TOKEN", self.token),
            ("GITLAB_PROJECT_ID", self.project_id),
        ) if not v]
        return "Set " + ", ".join(missing) + " to enable live merge requests." if missing else ""

    def _proxies(self) -> Optional[Dict[str, str]]:
        if self.use_socks and self.socks_url:
            return {"http": self.socks_url, "https": self.socks_url}
        return None

    def _proj(self) -> str:
        # numeric id stays as-is; a group/project path must be url-encoded
        pid = self.project_id
        if pid.isdigit():
            return pid
        return quote(pid, safe="")

    def _api(self, path: str) -> str:
        return f"{self.base_url}/api/v4/{path.lstrip('/')}"

    def _headers(self) -> Dict[str, str]:
        return {"PRIVATE-TOKEN": self.token, "Content-Type": "application/json"}

    def _file_exists(self, proj: str, path: str, ref: str, proxies) -> bool:
        """True if `path` already exists on `ref` (so we update rather than create)."""
        try:
            r = requests.head(
                self._api(f"projects/{proj}/repository/files/{quote(path, safe='')}"),
                headers=self._headers(), params={"ref": ref},
                proxies=proxies, timeout=_TIMEOUT,
            )
            return r.status_code == 200
        except requests.exceptions.RequestException:
            return False

    # ── the one write op ──────────────────────────────────────────────────────
    def open_merge_request(
        self,
        branch: str,
        files: Dict[str, str],
        title: str,
        description: str,
        commit_message: str,
    ) -> Dict:
        """Create `branch` off the default branch, commit `files` (path->content),
        and open a merge request back into the default branch.

        Returns {"ok": True, "mr_url": ..., "branch": ...} or {"error": "..."}.
        Never raises — all failures come back as an {"error": ...} dict.
        """
        if not self.is_configured():
            return {"error": "GitLab is not configured. " + self.config_hint()}
        if not files:
            return {"error": "No files to commit."}

        proj = self._proj()
        proxies = self._proxies()

        # 1) Create the feature branch off the default branch. (Doing this as a
        # discrete step, rather than via the commit API's start_branch, is what
        # GitLab reliably accepts — the combined form 400s on some versions with
        # "You can only create or edit files when you are on a branch".)
        try:
            br = requests.post(
                self._api(f"projects/{proj}/repository/branches"),
                headers=self._headers(), proxies=proxies, timeout=_TIMEOUT,
                params={"branch": branch, "ref": self.default_branch},
            )
            branch_exists = br.status_code in (200, 201) or (
                br.status_code == 400 and "already exists" in (br.text or "").lower())
            if not branch_exists:
                return {"error": _gl_err("create branch", br)}
        except requests.exceptions.RequestException as e:
            logger.warning("[gitlab] create branch failed: %s", e)
            return {"error": f"GitLab create-branch request failed: {e}"}

        # 2) Commit every file onto that branch, choosing create vs update per
        # file. The branch inherits the default branch's files (e.g. a repo that
        # already ships a .gitlab-ci.yml / README), so a blanket "create" would
        # 400 on those; an existing file must be an "update" action instead.
        actions = []
        for p, content in files.items():
            verb = "update" if self._file_exists(proj, p, branch, proxies) else "create"
            actions.append({"action": verb, "file_path": p, "content": content})
        commit_payload = {"branch": branch, "commit_message": commit_message, "actions": actions}
        try:
            r = requests.post(
                self._api(f"projects/{proj}/repository/commits"),
                headers=self._headers(), json=commit_payload,
                proxies=proxies, timeout=_TIMEOUT,
            )
            if r.status_code not in (200, 201):
                return {"error": _gl_err("commit", r)}
        except requests.exceptions.RequestException as e:
            logger.warning("[gitlab] commit failed: %s", e)
            return {"error": f"GitLab commit request failed: {e}"}

        # 3) Open the MR.
        mr_payload = {
            "source_branch": branch,
            "target_branch": self.default_branch,
            "title": title,
            "description": description,
            "remove_source_branch": True,
        }
        try:
            r = requests.post(
                self._api(f"projects/{proj}/merge_requests"),
                headers=self._headers(), json=mr_payload,
                proxies=proxies, timeout=_TIMEOUT,
            )
            if r.status_code not in (200, 201):
                return {"error": _gl_err("merge_request", r)}
            data = r.json()
            return {"ok": True, "mr_url": data.get("web_url"),
                    "mr_iid": data.get("iid"), "branch": branch}
        except requests.exceptions.RequestException as e:
            logger.warning("[gitlab] MR open failed: %s", e)
            return {"error": f"GitLab merge-request request failed: {e}"}


def _gl_err(stage: str, resp) -> str:
    code = resp.status_code
    if code == 401:
        return "GitLab rejected the token (401) — check GITLAB_API_TOKEN scope (api, write_repository)."
    if code == 403:
        return "GitLab denied access (403) — the token lacks permission on this project."
    if code == 404:
        return "GitLab project not found (404) — check GITLAB_PROJECT_ID."
    body = (resp.text or "")[:300]
    return f"GitLab {stage} failed ({code}): {body}"
