"""Celery application configuration."""

from celery import Celery
from celery.schedules import crontab

from keyspider.config import settings

app = Celery(
    "keyspider",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)

app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_routes={
        "keyspider.workers.scan_tasks.*": {"queue": "scan"},
        "keyspider.workers.key_tasks.*": {"queue": "key"},
        "keyspider.workers.spider_tasks.*": {"queue": "spider"},
        "keyspider.workers.watch_tasks.*": {"queue": "watcher"},
    },
    task_default_queue="default",
    beat_schedule={
        "scheduled-full-scan": {
            "task": "keyspider.workers.scan_tasks.scheduled_full_scan",
            "schedule": crontab(hour=2, minute=0),  # Daily at 2 AM
        },
        "health-check-watchers": {
            "task": "keyspider.workers.watch_tasks.health_check_watchers",
            "schedule": crontab(minute="*/5"),  # Every 5 minutes
        },
    },
)

app.autodiscover_tasks([
    "keyspider.workers.scan_tasks",
    "keyspider.workers.key_tasks",
    "keyspider.workers.spider_tasks",
    "keyspider.workers.watch_tasks",
])
