"""Async Export Job Manager for Meaningful Metrics.

Manages long-running export jobs with progress tracking.
Jobs run in background threads and are tracked in-memory.
"""

import logging
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Callable, Any

logger = logging.getLogger(__name__)


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
        }


class AsyncExportManager:
    """Manages async export jobs with thread-safe operations."""

    def __init__(self):
        self.jobs: Dict[str, ExportJob] = {}
        self.lock = threading.Lock()
        logger.info("AsyncExportManager initialized")

    def create_job(self) -> str:
        """Create a new export job and return its ID."""
        job_id = str(uuid.uuid4())

        with self.lock:
            self.jobs[job_id] = ExportJob(
                job_id=job_id,
                status='queued'
            )

        logger.info(f"Created export job: {job_id}")
        return job_id

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
                logger.info(f"Job {job_id} completed: {file_path}")

    def mark_failed(self, job_id: str, error: str):
        """Mark job as failed with error message."""
        with self.lock:
            if job_id in self.jobs:
                self.jobs[job_id].status = 'failed'
                self.jobs[job_id].error = error
                self.jobs[job_id].completed_at = datetime.now()
                logger.error(f"Job {job_id} failed: {error}")

    def start_export_thread(self, job_id: str, export_func: Callable, **kwargs):
        """Start export in background thread with progress callback."""

        def progress_callback(current: int, total: int):
            """Callback to update progress from worker."""
            self.update_progress(job_id, current, total)

            # Mark as processing on first progress callback
            with self.lock:
                if job_id in self.jobs and self.jobs[job_id].status == 'queued':
                    self.jobs[job_id].status = 'processing'
                    self.jobs[job_id].started_at = datetime.now()
                    logger.info(f"Job {job_id} marked as processing")

        def worker():
            """Background worker to run export."""
            try:
                logger.info(f"Starting export worker for job {job_id}")

                # Run the export function with progress callback
                file_path = export_func(progress_callback=progress_callback, **kwargs)

                # Mark as complete
                self.mark_complete(job_id, file_path)

            except Exception as e:
                logger.error(f"Export job {job_id} failed: {e}", exc_info=True)
                self.mark_failed(job_id, str(e))

        # Start background thread
        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        logger.info(f"Started background thread for job {job_id}")

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
