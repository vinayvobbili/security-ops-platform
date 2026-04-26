"""Recap Job Manager.

In-memory job tracking for the meeting recap pipeline. Modeled on
async_export_manager.py but stripped down — no dedup hashing or notes lock,
just basic status tracking for a small number of background transcription jobs.

Jobs do NOT survive a web server restart. For ~1 recording per week, this is
fine: a restart mid-job surfaces as a 'failed — please re-upload' on the UI.
"""

import logging
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


@dataclass
class RecapJob:
    """In-memory record of a recap pipeline run."""

    job_id: str
    status: str = "queued"  # queued | transcribing | summarizing | storing | complete | failed
    progress_message: Optional[str] = None
    recap_id: Optional[int] = None
    error: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    requested_by: Optional[str] = None
    audio_filename: Optional[str] = None
    meeting_type: Optional[str] = None

    TERMINAL_STATUSES = ("complete", "failed")

    @property
    def is_active(self) -> bool:
        return self.status not in self.TERMINAL_STATUSES

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "status": self.status,
            "progress_message": self.progress_message,
            "recap_id": self.recap_id,
            "error": self.error,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "requested_by": self.requested_by,
            "audio_filename": self.audio_filename,
            "meeting_type": self.meeting_type,
        }


class RecapJobManager:
    """Thread-safe in-memory store for RecapJob instances."""

    def __init__(self) -> None:
        self._jobs: dict[str, RecapJob] = {}
        self._lock = threading.Lock()
        logger.info("RecapJobManager initialized")

    def create_job(
        self,
        requested_by: Optional[str] = None,
        audio_filename: Optional[str] = None,
        meeting_type: Optional[str] = None,
    ) -> str:
        job_id = str(uuid.uuid4())
        with self._lock:
            self._jobs[job_id] = RecapJob(
                job_id=job_id,
                requested_by=requested_by,
                audio_filename=audio_filename,
                meeting_type=meeting_type,
            )
        logger.info(f"Created recap job {job_id} (requested_by={requested_by})")
        return job_id

    def list_active(self) -> list[RecapJob]:
        """Return non-terminal jobs, newest first."""
        with self._lock:
            jobs = [j for j in self._jobs.values() if j.is_active]
        return sorted(jobs, key=lambda j: j.created_at, reverse=True)

    def get_job(self, job_id: str) -> Optional[RecapJob]:
        with self._lock:
            return self._jobs.get(job_id)

    def _set_status(self, job_id: str, status: str, message: Optional[str] = None) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job.status = status
            job.progress_message = message
            if status != "queued" and job.started_at is None:
                job.started_at = datetime.now()

    def mark_complete(self, job_id: str, recap_id: int) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job.status = "complete"
            job.recap_id = recap_id
            job.completed_at = datetime.now()
            job.progress_message = None
        logger.info(f"Recap job {job_id} complete (recap_id={recap_id})")

    def mark_failed(self, job_id: str, error: str) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job.status = "failed"
            job.error = error
            job.completed_at = datetime.now()
        logger.error(f"Recap job {job_id} failed: {error}")

    def start_pipeline_thread(
        self,
        job_id: str,
        pipeline_func: Callable[..., int],
        **kwargs: Any,
    ) -> None:
        """Run pipeline_func in a daemon thread, updating job status as it progresses.

        pipeline_func must accept a `progress_callback` kwarg that takes a single
        string (the new stage name) and return an int (the new recap_id).
        """

        def _on_stage(stage: str) -> None:
            self._set_status(job_id, stage, message=f"{stage}...")

        def _worker() -> None:
            try:
                logger.info(f"Recap job {job_id} starting pipeline")
                recap_id = pipeline_func(progress_callback=_on_stage, **kwargs)
                self.mark_complete(job_id, recap_id)
            except Exception as e:
                logger.exception(f"Recap job {job_id} pipeline error: {e}")
                self.mark_failed(job_id, str(e))

        threading.Thread(target=_worker, daemon=True, name=f"recap-job-{job_id[:8]}").start()


# Module-level singleton — same usage pattern as the export manager
_manager: Optional[RecapJobManager] = None
_manager_lock = threading.Lock()


def get_manager() -> RecapJobManager:
    global _manager
    if _manager is not None:
        return _manager
    with _manager_lock:
        if _manager is None:
            _manager = RecapJobManager()
    return _manager
