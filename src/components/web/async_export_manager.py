"""Async Export Job Manager for Meaningful Metrics.

Manages long-running export jobs with progress tracking.
Jobs run in background threads and are tracked in-memory.
"""

import hashlib
import json
import logging
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

logger = logging.getLogger(__name__)


def hash_export_request(filters: Any, visible_columns: Any, include_notes: bool) -> str:
    """Compute a stable hash of an export request payload for idempotency.

    Two requests with identical (filters, columns, include_notes) collapse to the
    same hash so the manager can dedup duplicate clicks and identical concurrent
    requests from different users.
    """
    payload = {
        'filters': filters or {},
        'visible_columns': sorted(visible_columns) if visible_columns else [],
        'include_notes': bool(include_notes),
    }
    canonical = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


@dataclass
class ExportJob:
    """Represents an async export job with progress tracking."""

    job_id: str
    status: str  # 'queued', 'processing', 'complete', 'failed'
    progress: int = 0  # Current progress count
    total: int = 0  # Total items to process
    error: Optional[str] = None
    file_path: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    request_hash: Optional[str] = None  # Idempotency key for dedup
    requested_by: Optional[str] = None  # Client IP that started the job
    queue_message: Optional[str] = None  # Human-readable wait reason while queued
    warnings: list = field(default_factory=list)  # Non-fatal issues to surface after success

    def to_dict(self) -> Dict[str, Any]:
        """Convert job to dict for JSON serialization."""
        return {
            'job_id': self.job_id,
            'status': self.status,
            'progress': self.progress,
            'total': self.total,
            'error': self.error,
            'file_path': self.file_path,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'server_time': datetime.now().isoformat(),
            'requested_by': self.requested_by,
            'queue_message': self.queue_message,
            'warnings': list(self.warnings),
        }


class AsyncExportManager:
    """Manages async export jobs with thread-safe operations."""

    def __init__(self):
        self.jobs: Dict[str, ExportJob] = {}
        self.lock = threading.Lock()
        # Maps request_hash -> job_id for active (queued/processing) jobs.
        # Used to dedup identical requests so duplicate clicks and concurrent
        # requests for the same data collapse to a single underlying export.
        self._active_hashes: Dict[str, str] = {}
        # Serializes notes-enabled exports. Notes exports hammer XSOAR with
        # MAX_WORKERS parallel /investigation/{id} calls; running two at once
        # doubles the load and was a contributor to the Apr 8 stall. Workers
        # acquire this lock before doing the heavy fetch and release it after.
        self._notes_export_lock = threading.Lock()
        logger.info("AsyncExportManager initialized")

    def create_or_get_job(
        self,
        request_hash: str,
        requested_by: Optional[str] = None,
    ) -> Tuple[str, bool]:
        """Create a new export job, OR return an existing job_id if an identical
        request is already queued/processing.

        Args:
            request_hash: Stable hash of the export request payload.
            requested_by: Client IP for visibility (logged + surfaced in queue messages).

        Returns:
            Tuple of (job_id, deduped) where deduped=True means the returned
            job_id points to a pre-existing in-flight job.
        """
        with self.lock:
            existing_id = self._active_hashes.get(request_hash)
            if existing_id and existing_id in self.jobs:
                existing_job = self.jobs[existing_id]
                if existing_job.status in ('queued', 'processing'):
                    logger.info(
                        f"Deduped export request from {requested_by}: returning "
                        f"existing job {existing_id} (status={existing_job.status}, "
                        f"originally requested by {existing_job.requested_by}) "
                        f"for hash {request_hash}"
                    )
                    return existing_id, True

            job_id = str(uuid.uuid4())
            self.jobs[job_id] = ExportJob(
                job_id=job_id,
                status='queued',
                request_hash=request_hash,
                requested_by=requested_by,
            )
            self._active_hashes[request_hash] = job_id

        logger.info(
            f"Created export job: {job_id} (hash={request_hash}, requested_by={requested_by})"
        )
        return job_id, False

    def _release_hash(self, job_id: str) -> None:
        """Drop the dedup entry for a job once it reaches a terminal state.
        Caller must hold self.lock."""
        job = self.jobs.get(job_id)
        if job and job.request_hash:
            if self._active_hashes.get(job.request_hash) == job_id:
                del self._active_hashes[job.request_hash]

    def get_job(self, job_id: str) -> Optional[ExportJob]:
        """Get job by ID."""
        with self.lock:
            return self.jobs.get(job_id)

    def update_progress(self, job_id: str, progress: int, total: int):
        """Update job progress."""
        with self.lock:
            if job_id in self.jobs:
                self.jobs[job_id].progress = progress
                self.jobs[job_id].total = total

    def mark_processing(self, job_id: str, total: int):
        """Mark job as processing with total count."""
        with self.lock:
            if job_id in self.jobs:
                self.jobs[job_id].status = 'processing'
                self.jobs[job_id].total = total
                self.jobs[job_id].started_at = datetime.now()
                logger.info(f"Job {job_id} started processing {total} items")

    def mark_complete(self, job_id: str, file_path: str):
        """Mark job as complete with file path."""
        with self.lock:
            if job_id in self.jobs:
                self.jobs[job_id].status = 'complete'
                self.jobs[job_id].file_path = file_path
                self.jobs[job_id].completed_at = datetime.now()
                self.jobs[job_id].queue_message = None
                self._release_hash(job_id)
                logger.info(f"Job {job_id} completed: {file_path}")

    def mark_failed(self, job_id: str, error: str):
        """Mark job as failed with error message."""
        with self.lock:
            if job_id in self.jobs:
                self.jobs[job_id].status = 'failed'
                self.jobs[job_id].error = error
                self.jobs[job_id].completed_at = datetime.now()
                self.jobs[job_id].queue_message = None
                self._release_hash(job_id)
                logger.error(f"Job {job_id} failed: {error}")

    def add_warning(self, job_id: str, warning: str):
        """Attach a non-fatal warning to a job. Surfaced alongside success."""
        with self.lock:
            if job_id in self.jobs:
                self.jobs[job_id].warnings.append(warning)
                logger.warning(f"Job {job_id} warning: {warning}")

    def start_export_thread(
        self,
        job_id: str,
        export_func: Callable,
        serialize_with_notes_lock: bool = False,
        **kwargs,
    ):
        """Start export in background thread with progress callback.

        Args:
            job_id: Job ID returned from create_or_get_job.
            export_func: Callable that runs the export. Receives progress_callback kwarg.
            serialize_with_notes_lock: If True, the worker will acquire the
                global notes-export lock before running so only one heavy
                notes-enabled export executes at a time. Other queued workers
                wait their turn here, not in the route handler.
            **kwargs: Forwarded to export_func.
        """

        def progress_callback(current: int, total: int):
            """Callback to update progress from worker."""
            self.update_progress(job_id, current, total)

            # Mark as processing on first progress callback
            with self.lock:
                if job_id in self.jobs and self.jobs[job_id].status == 'queued':
                    self.jobs[job_id].status = 'processing'
                    self.jobs[job_id].started_at = datetime.now()
                    self.jobs[job_id].queue_message = None
                    logger.info(f"Job {job_id} marked as processing")

        def warning_callback(msg: str):
            """Callback exports use to surface non-fatal issues to the user."""
            self.add_warning(job_id, msg)

        def _set_queue_message(msg: Optional[str]):
            with self.lock:
                if job_id in self.jobs:
                    self.jobs[job_id].queue_message = msg

        def worker():
            """Background worker to run export."""
            acquired_lock = False
            try:
                if serialize_with_notes_lock:
                    # Try non-blocking acquire first to detect contention and
                    # surface a wait message before blocking on the lock.
                    if not self._notes_export_lock.acquire(blocking=False):
                        # Identify who's holding it (best effort) for visibility
                        with self.lock:
                            holder = next(
                                (
                                    j for j in self.jobs.values()
                                    if j.status == 'processing'
                                    and j.job_id != job_id
                                    and j.request_hash is not None
                                ),
                                None,
                            )
                        wait_msg = (
                            f"Waiting for another notes export to finish"
                            + (
                                f" (started by {holder.requested_by} at "
                                f"{holder.started_at.strftime('%H:%M:%S')})"
                                if holder and holder.started_at
                                else ""
                            )
                        )
                        logger.info(f"Job {job_id} queued behind notes-export lock: {wait_msg}")
                        _set_queue_message(wait_msg)
                        self._notes_export_lock.acquire()  # Block until released
                    acquired_lock = True
                    _set_queue_message(None)

                logger.info(f"Starting export worker for job {job_id}")

                # Run the export function with progress callback
                file_path = export_func(
                    progress_callback=progress_callback,
                    warning_callback=warning_callback,
                    **kwargs,
                )

                # Mark as complete
                self.mark_complete(job_id, file_path)

            except Exception as e:
                logger.error(f"Export job {job_id} failed: {e}", exc_info=True)
                self.mark_failed(job_id, str(e))
            finally:
                if acquired_lock:
                    self._notes_export_lock.release()

        # Start background thread
        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        logger.info(
            f"Started background thread for job {job_id} "
            f"(serialize_with_notes_lock={serialize_with_notes_lock})"
        )

    def cleanup_old_jobs(self, max_age_hours: int = 24):
        """Remove jobs older than max_age_hours."""
        cutoff = datetime.now()

        with self.lock:
            to_remove = []
            for job_id, job in self.jobs.items():
                age_hours = (cutoff - job.created_at).total_seconds() / 3600
                if age_hours > max_age_hours:
                    # Remove file if exists
                    if job.file_path and Path(job.file_path).exists():
                        try:
                            Path(job.file_path).unlink()
                            logger.info(f"Deleted old export file: {job.file_path}")
                        except Exception as e:
                            logger.warning(f"Failed to delete file {job.file_path}: {e}")
                    to_remove.append(job_id)

            for job_id in to_remove:
                self._release_hash(job_id)
                del self.jobs[job_id]
                logger.info(f"Cleaned up old job: {job_id}")


# Global instance
_export_manager = None


def get_export_manager() -> AsyncExportManager:
    """Get or create global export manager instance."""
    global _export_manager
    if _export_manager is None:
        _export_manager = AsyncExportManager()
    return _export_manager
