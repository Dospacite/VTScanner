#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
from collections import deque
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import requests
from dotenv import load_dotenv
from pymongo import ASCENDING, MongoClient
from pymongo.collection import Collection
from pymongo.errors import DocumentTooLarge, OperationFailure

try:
    from scrapling.fetchers import StealthyFetcher
except Exception as exc:  # pragma: no cover - runtime environment dependent
    StealthyFetcher = None
    SCRAPLING_IMPORT_ERROR = repr(exc)
else:
    SCRAPLING_IMPORT_ERROR = None


UTC = timezone.utc
VT_BASE_URL = "https://www.virustotal.com/api/v3"
GSB_FIND_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
URLSCAN_LIVE_URL = "https://urlscan.io/json/live/"


class RetryableError(RuntimeError):
    """Signals a transient failure that should be retried later."""


class RateLimitError(RuntimeError):
    """Signals a rate limit response with an explicit cooldown."""

    def __init__(self, message: str, cooldown_seconds: float) -> None:
        super().__init__(message)
        self.cooldown_seconds = cooldown_seconds


@dataclass
class VTRequestStats:
    day: str
    total_requests: int = 0
    submit_requests: int = 0
    analysis_requests: int = 0
    other_requests: int = 0
    successful_requests: int = 0
    quota_429s: int = 0


def utcnow() -> datetime:
    return datetime.now(UTC)


def getenv_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    return int(value)


def getenv_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def compact_text(text: str, max_bytes: int) -> tuple[str, bool]:
    encoded = text.encode("utf-8", errors="ignore")
    if len(encoded) <= max_bytes:
        return text, False
    trimmed = encoded[:max_bytes].decode("utf-8", errors="ignore")
    return trimmed, True


def safe_json(response: requests.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return {"raw_text": response.text[:2000]}


def parse_retry_after_seconds(value: str | None, default: float) -> float:
    if not value:
        return default
    try:
        return max(float(value), default)
    except ValueError:
        return default


def is_retryable_status(status_code: int) -> bool:
    return status_code in {408, 409, 425, 429, 500, 502, 503, 504}


@dataclass
class SlidingWindowLimiter:
    limit: int
    window_seconds: int
    name: str
    hits: deque[float] = field(default_factory=deque)

    def _prune(self, now: float) -> None:
        cutoff = now - self.window_seconds
        while self.hits and self.hits[0] <= cutoff:
            self.hits.popleft()

    def next_available_in(self, now: float | None = None) -> float:
        now = now or time.time()
        self._prune(now)
        if len(self.hits) < self.limit:
            return 0.0
        return max((self.hits[0] + self.window_seconds) - now, 0.0)

    def reserve(self, now: float | None = None) -> None:
        now = now or time.time()
        self._prune(now)
        self.hits.append(now)

    def wait(self) -> None:
        while True:
            delay = self.next_available_in()
            if delay <= 0:
                self.reserve()
                return
            logging.info("Rate limit %s reached, sleeping %.2fs", self.name, delay)
            time.sleep(min(max(delay, 0.25), 60.0))


@dataclass
class VTKeyState:
    api_key: str
    fingerprint: str
    minute_limiter: SlidingWindowLimiter
    day_limiter: SlidingWindowLimiter
    min_interval_seconds: float
    cooldown_until: float = 0.0
    last_reserved_at: float = 0.0
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @classmethod
    def from_api_key(
        cls,
        api_key: str,
        *,
        minute_limit: int,
        minute_window_seconds: int,
        day_limit: int,
        day_window_seconds: int,
        min_interval_seconds: float,
    ) -> "VTKeyState":
        fingerprint = hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:12]
        return cls(
            api_key=api_key,
            fingerprint=fingerprint,
            minute_limiter=SlidingWindowLimiter(
                minute_limit, minute_window_seconds, f"vt-minute-{fingerprint}"
            ),
            day_limiter=SlidingWindowLimiter(
                day_limit, day_window_seconds, f"vt-day-{fingerprint}"
            ),
            min_interval_seconds=min_interval_seconds,
        )

    def next_available_in(self, now: float) -> float:
        waits = [
            self.minute_limiter.next_available_in(now),
            self.day_limiter.next_available_in(now),
            max(self.cooldown_until - now, 0.0),
        ]
        if self.last_reserved_at > 0:
            waits.append(max((self.last_reserved_at + self.min_interval_seconds) - now, 0.0))
        return max(waits)

    def reserve(self, now: float) -> None:
        self.minute_limiter.reserve(now)
        self.day_limiter.reserve(now)
        self.last_reserved_at = now

    def wait(self) -> None:
        while True:
            with self.lock:
                now = time.time()
                wait = self.next_available_in(now)
                if wait <= 0:
                    self.reserve(now)
                    return
            logging.info(
                "VirusTotal key %s rate-limited, sleeping %.2fs",
                self.fingerprint,
                wait,
            )
            time.sleep(min(max(wait, 0.25), 60.0))

    def mark_rate_limited(self, cooldown_seconds: float) -> None:
        with self.lock:
            self.cooldown_until = max(self.cooldown_until, time.time() + cooldown_seconds)


class VTScannerService:
    def __init__(self) -> None:
        load_dotenv()

        self.mongo_uri = os.environ["MONGO_URI"]
        self.gsb_api_key = os.environ["GOOGLE_SAFE_BROWSING_API_KEY"]
        self.urlscan_api_key = os.environ["URLSCAN_API_KEY"]
        self.vt_api_key = os.environ["VT_API_KEY"]
        self.mongo_db_name = os.getenv("MONGO_DB_NAME", "urlscan")
        self.mongo_collection_name = os.getenv("MONGO_COLLECTION_NAME", "live")

        self.request_timeout = getenv_int("REQUEST_TIMEOUT_SECONDS", 60)
        self.error_sleep_seconds = getenv_int("ERROR_SLEEP_SECONDS", 30)
        self.idle_sleep_seconds = getenv_int("IDLE_SLEEP_SECONDS", 60)
        self.t7_days = getenv_int("T7_DELAY_DAYS", 7)
        self.scrape_html_max_bytes = getenv_int("SCRAPE_HTML_MAX_BYTES", 524288)
        self.scrape_headless = getenv_bool("SCRAPE_HEADLESS", True)
        self.scrape_worker_count = max(getenv_int("SCRAPE_WORKER_COUNT", 4), 1)
        self.vt_batch_size = getenv_int("VT_BATCH_SIZE", 128)
        self.vt_collect_batch_size = getenv_int(
            "VT_COLLECT_BATCH_SIZE", self.vt_batch_size
        )
        self.vt_pending_target = getenv_int("VT_PENDING_TARGET", self.vt_batch_size)
        self.vt_batch_settle_seconds = getenv_int("VT_BATCH_SETTLE_SECONDS", 180)
        self.vt_batch_poll_interval_seconds = getenv_int(
            "VT_BATCH_POLL_INTERVAL_SECONDS", 30
        )
        self.vt_submission_worker_count = max(
            getenv_int("VT_SUBMISSION_WORKER_COUNT", 8), 1
        )
        self.vt_analysis_worker_count = max(
            getenv_int("VT_ANALYSIS_WORKER_COUNT", 32), 1
        )
        self.vt_submission_max_inflight = max(
            getenv_int(
                "VT_SUBMISSION_MAX_INFLIGHT",
                max(self.vt_batch_size, self.vt_submission_worker_count * 4),
            ),
            1,
        )
        self.vt_analysis_max_inflight = max(
            getenv_int(
                "VT_ANALYSIS_MAX_INFLIGHT",
                max(self.vt_collect_batch_size, self.vt_analysis_worker_count * 2),
            ),
            1,
        )
        self.vt_pending_backoff_multiplier = getenv_int(
            "VT_PENDING_BACKOFF_MULTIPLIER", 1
        )
        self.vt_pending_max_poll_interval_seconds = getenv_int(
            "VT_PENDING_MAX_POLL_INTERVAL_SECONDS",
            self.vt_batch_poll_interval_seconds,
        )
        self.vt_minute_limit = getenv_int("VT_MINUTE_LIMIT", 20000)
        self.vt_minute_window_seconds = getenv_int("VT_MINUTE_WINDOW_SECONDS", 60)
        self.vt_day_limit = getenv_int("VT_DAY_LIMIT", 20000)
        self.vt_day_window_seconds = getenv_int("VT_DAY_WINDOW_SECONDS", 86400)
        self.vt_min_request_spacing_seconds = getenv_int(
            "VT_MIN_REQUEST_SPACING_SECONDS", 1
        )
        self.vt_disable_throttle = getenv_bool("VT_DISABLE_THROTTLE", False)
        self.vt_rate_limit_cooldown_seconds = getenv_int(
            "VT_RATE_LIMIT_COOLDOWN_SECONDS", 180
        )
        self.vt_submit_retry_cooldown_seconds = getenv_int(
            "VT_SUBMIT_RETRY_COOLDOWN_SECONDS",
            max(self.vt_rate_limit_cooldown_seconds, 300),
        )
        self.vt_analysis_retry_cooldown_seconds = getenv_int(
            "VT_ANALYSIS_RETRY_COOLDOWN_SECONDS",
            max(self.vt_rate_limit_cooldown_seconds, 300),
        )

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "VTScanner/1.0"})
        self.vt_submission_executor = ThreadPoolExecutor(
            max_workers=self.vt_submission_worker_count,
            thread_name_prefix="virustotal-submit",
        )
        self.vt_analysis_executor = ThreadPoolExecutor(
            max_workers=self.vt_analysis_worker_count,
            thread_name_prefix="virustotal-analysis",
        )
        self.gsb_session = requests.Session()
        self.gsb_session.headers.update({"User-Agent": "VTScanner/1.0"})
        self.gsb_executor = ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="google-safe-browsing",
        )
        self.gsb_rate_limit_until = datetime.min.replace(tzinfo=UTC)
        self.scrape_executor = ThreadPoolExecutor(
            max_workers=self.scrape_worker_count,
            thread_name_prefix="scrapling",
        )
        self.vt_submission_futures: dict[Future[Any], dict[str, Any]] = {}
        self.vt_analysis_futures: dict[Future[Any], dict[str, Any]] = {}
        self.gsb_futures: dict[Future[Any], dict[str, Any]] = {}
        self.scrape_futures: dict[Future[Any], dict[str, Any]] = {}
        self.vt_request_stats = VTRequestStats(day=utcnow().date().isoformat())
        self.vt_request_lock = threading.Lock()

        self.vt_key = VTKeyState.from_api_key(
            self.vt_api_key,
            minute_limit=self.vt_minute_limit,
            minute_window_seconds=self.vt_minute_window_seconds,
            day_limit=self.vt_day_limit,
            day_window_seconds=self.vt_day_window_seconds,
            min_interval_seconds=self.vt_min_request_spacing_seconds,
        )
        self.urlscan_retrieve_limiter = SlidingWindowLimiter(
            5000, 3600, "urlscan-retrieve-hour"
        )

        self.mongo_client = MongoClient(
            self.mongo_uri,
            serverSelectionTimeoutMS=10000,
            connectTimeoutMS=10000,
            socketTimeoutMS=60000,
            tz_aware=True,
        )
        self.collection: Collection = self.mongo_client[self.mongo_db_name][
            self.mongo_collection_name
        ]

    def ensure_indexes(self) -> None:
        self.collection.create_index([("task.url", ASCENDING)], name="task_url_idx")
        self.collection.create_index(
            [("scans.T0.next_scan_due_at", ASCENDING)], name="t0_next_scan_due_idx"
        )
        self.collection.create_index(
            [("scans.T7.completed_at", ASCENDING)], name="t7_completed_idx"
        )
        self.collection.create_index(
            [("scans.T7.change_detection.significant", ASCENDING)],
            name="t7_significant_idx",
        )
        self.collection.create_index(
            [("scans.T0_pending.submitted_at", ASCENDING)],
            name="t0_pending_submitted_idx",
        )
        self.collection.create_index(
            [("scans.T7_pending.submitted_at", ASCENDING)],
            name="t7_pending_submitted_idx",
        )
        self.collection.create_index(
            [("scans.T0_pending.next_poll_due_at", ASCENDING)],
            name="t0_pending_next_poll_due_idx",
        )
        self.collection.create_index(
            [("scans.T0_queue.queued_at", ASCENDING)],
            name="t0_queue_queued_at_idx",
        )
        self.collection.create_index(
            [("scans.T7_queue.queued_at", ASCENDING)],
            name="t7_queue_queued_at_idx",
        )
        self.collection.create_index(
            [("scans.T7_pending.next_poll_due_at", ASCENDING)],
            name="t7_pending_next_poll_due_idx",
        )
        self.collection.create_index(
            [("scans.T0_gsb_pending.submitted_at", ASCENDING)],
            name="t0_gsb_pending_submitted_idx",
        )
        self.collection.create_index(
            [("scans.T7_gsb_pending.submitted_at", ASCENDING)],
            name="t7_gsb_pending_submitted_idx",
        )

    def inspect_existing_format(self) -> None:
        sample = self.collection.find_one()
        if not sample:
            logging.info("Collection %s.%s is empty.", self.mongo_db_name, self.mongo_collection_name)
            return

        sample_summary = {
            "top_level_keys": sorted(sample.keys()),
            "urlscanresults_keys": sorted((sample.get("urlscanresults") or {}).keys()),
            "has_dom": "dom" in sample,
            "dom_keys": sorted((sample.get("dom") or {}).keys())
            if isinstance(sample.get("dom"), dict)
            else None,
            "has_legacy_vtresults": "vtresults" in sample,
            "has_scans": "scans" in sample,
        }
        logging.info("Existing document format summary: %s", sample_summary)

    def purge_legacy_scan_fields(self) -> None:
        filter_query = {
            "$or": [
                {"vtresults": {"$exists": True}},
                {"vtresults_updated_at": {"$exists": True}},
                {"labels": {"$exists": True}},
            ]
        }
        legacy_count = self.collection.count_documents(filter_query)
        if legacy_count == 0:
            logging.info("No legacy vtresults/labels fields found.")
            return

        result = self.collection.update_many(
            filter_query,
            {
                "$unset": {
                    "vtresults": "",
                    "vtresults_updated_at": "",
                    "labels": "",
                }
            },
        )
        logging.info(
            "Removed legacy scan fields from %s documents (matched=%s, modified=%s).",
            legacy_count,
            result.matched_count,
            result.modified_count,
        )

    def run_forever(self) -> None:
        self.ensure_indexes()
        self.purge_legacy_scan_fields()
        self.ensure_t0_queue_for_unscanned_urls()
        self.ensure_t7_queue_for_due_urls()
        self.inspect_existing_format()
        logging.info("Starting scanner loop on %s.%s", self.mongo_db_name, self.mongo_collection_name)

        while True:
            try:
                did_work = False
                if self.ensure_t0_queue_for_unscanned_urls() > 0:
                    did_work = True
                if self.ensure_t7_queue_for_due_urls() > 0:
                    did_work = True

                if self.process_pending_t7_scrape():
                    did_work = True

                vt_work_count, pending_count = self.process_pending_virustotal_results()
                if vt_work_count > 0:
                    did_work = True

                gsb_work_count, gsb_has_more_work = self.process_google_safe_browsing_queue()
                if gsb_work_count > 0:
                    did_work = True

                current_pending_count = pending_count + len(self.vt_submission_futures)
                submitted_count = self.fill_virustotal_submission_queue(current_pending_count)
                if submitted_count > 0:
                    did_work = True

                if not gsb_has_more_work:
                    inserted = self.backfill_from_live_feed()
                    if inserted > 0:
                        did_work = True

                if did_work:
                    continue
                logging.info("No work found. Sleeping for %ss.", self.idle_sleep_seconds)
                time.sleep(self.idle_sleep_seconds)
            except KeyboardInterrupt:
                logging.info("Scanner interrupted. Exiting.")
                raise
            except Exception:
                logging.exception("Scanner loop failed. Sleeping for %ss.", self.error_sleep_seconds)
                time.sleep(self.error_sleep_seconds)

    def ensure_t0_queue_for_unscanned_urls(self) -> int:
        queued_at = utcnow()
        result = self.collection.update_many(
            {
                "$and": [
                    {"task.url": {"$type": "string", "$ne": ""}},
                    {"scans.T0.virustotal": {"$exists": False}},
                    {"scans.T0_pending": {"$exists": False}},
                    {"scans.T0_queue": {"$exists": False}},
                ]
            },
            {
                "$set": {
                    "scans.T0_queue": {
                        "queued_at": queued_at,
                        "source": "missing_t0_backfill",
                    },
                    "scans.last_updated_at": queued_at,
                }
            },
        )
        if result.modified_count > 0:
            logging.info(
                "Queued %s URLs missing T0 VirusTotal scans.",
                result.modified_count,
            )
        return int(result.modified_count)

    def ensure_t7_queue_for_due_urls(self) -> int:
        queued_at = utcnow()
        due_cutoff = queued_at - timedelta(days=self.t7_days)
        result = self.collection.update_many(
            {
                "$and": [
                    {"task.url": {"$type": "string", "$ne": ""}},
                    {"scans.T0.completed_at": {"$exists": True}},
                    {"scans.T7.virustotal": {"$exists": False}},
                    {"scans.T7_pending": {"$exists": False}},
                    {"scans.T7_queue": {"$exists": False}},
                    {"scans.T7.ignored": {"$ne": True}},
                    {
                        "$or": [
                            {"scans.T7_submit_retry_at": {"$exists": False}},
                            {"scans.T7_submit_retry_at": {"$lte": queued_at}},
                        ]
                    },
                    {
                        "$or": [
                            {"scans.T0.next_scan_due_at": {"$lte": queued_at}},
                            {
                                "$and": [
                                    {"scans.T0.next_scan_due_at": {"$exists": False}},
                                    {"scans.T0.completed_at": {"$lte": due_cutoff}},
                                ]
                            },
                        ]
                    },
                ]
            },
            {
                "$set": {
                    "scans.T7_queue": {
                        "queued_at": queued_at,
                        "source": "due_t7_backfill",
                    },
                    "scans.last_updated_at": queued_at,
                }
            },
        )
        if result.modified_count > 0:
            logging.info(
                "Queued %s URLs due for T7 VirusTotal scans.",
                result.modified_count,
            )
        return int(result.modified_count)

    def process_pending_t7_scrape(self) -> bool:
        completed_count = self.collect_completed_scrape_futures()
        capacity = self.scrape_worker_count - len(self.scrape_futures)
        if capacity <= 0:
            return completed_count > 0

        docs = list(
            self.collection.find(
                {
                    "task.url": {"$type": "string", "$ne": ""},
                    "scans.T7.change_detection.significant": True,
                    "scans.T7.ignored": {"$ne": True},
                    "$or": [
                        {"scans.T7.scrape": {"$exists": False}},
                        {"scans.T7.scrape.status": {"$ne": "success"}},
                    ],
                },
                sort=[("scans.T7.completed_at", ASCENDING)],
                limit=capacity,
            )
        )
        if not docs:
            return completed_count > 0

        scheduled_count = 0
        for doc in docs:
            url = doc["task"]["url"]
            logging.info("Queueing pending T7 scrape retry for %s", url)
            if self.queue_scrape_work(
                document_id=doc["_id"],
                stage="T7",
                url=url,
                reason="retry_pending_significant_change",
                previous_scrape=doc.get("scans", {}).get("T7", {}).get("scrape"),
            ):
                scheduled_count += 1

        return (completed_count + scheduled_count) > 0

    def has_inflight_scrape(self, document_id: Any, stage: str) -> bool:
        return any(
            meta.get("document_id") == document_id and meta.get("stage") == stage
            for meta in self.scrape_futures.values()
        )

    def has_successful_scrape(self, scan: dict[str, Any]) -> bool:
        return ((scan.get("scrape") or {}).get("status") == "success")

    def count_pending_virustotal_documents(self, limit: int | None = None) -> int:
        if limit is None:
            limit = self.vt_pending_target + 1
        if limit <= 0:
            return 0

        projections = {"_id": 1}
        pending_ids: set[Any] = set()
        stage_queries = [
            ("scans.T7_pending.submitted_at", {"scans.T7_pending.submitted_at": {"$exists": True}}),
            ("scans.T0_pending.submitted_at", {"scans.T0_pending.submitted_at": {"$exists": True}}),
        ]
        for sort_field, query in stage_queries:
            remaining = limit - len(pending_ids)
            if remaining <= 0:
                break
            cursor = self.collection.find(
                query,
                projections,
                sort=[(sort_field, ASCENDING), ("_id", ASCENDING)],
                limit=remaining,
            )
            for doc in cursor:
                pending_ids.add(doc["_id"])
                if len(pending_ids) >= limit:
                    break
        return len(pending_ids)

    def pending_entry_projection(self) -> dict[str, int]:
        return {
            "task.url": 1,
            "scans.T0_pending": 1,
            "scans.T7_pending": 1,
            "scans.T0.virustotal.malicious_engine_count": 1,
            "scans.T0.google_safe_browsing.matched": 1,
        }

    def list_ready_pending_virustotal_entries(self, limit: int) -> list[dict[str, Any]]:
        if limit <= 0:
            return []

        now = utcnow()
        legacy_cutoff = now - timedelta(seconds=self.vt_batch_settle_seconds)
        stage_queries = [
            (
                "scans.T7_pending.next_poll_due_at",
                {
                    "$or": [
                        {"scans.T7_pending.next_poll_due_at": {"$lte": now}},
                        {
                            "$and": [
                                {"scans.T7_pending": {"$exists": True}},
                                {"scans.T7_pending.next_poll_due_at": {"$exists": False}},
                                {"scans.T7_pending.submitted_at": {"$lte": legacy_cutoff}},
                            ]
                        },
                    ]
                },
            ),
            (
                "scans.T0_pending.next_poll_due_at",
                {
                    "$or": [
                        {"scans.T0_pending.next_poll_due_at": {"$lte": now}},
                        {
                            "$and": [
                                {"scans.T0_pending": {"$exists": True}},
                                {"scans.T0_pending.next_poll_due_at": {"$exists": False}},
                                {"scans.T0_pending.submitted_at": {"$lte": legacy_cutoff}},
                            ]
                        },
                    ]
                },
            ),
        ]

        docs: list[dict[str, Any]] = []
        for sort_field, query in stage_queries:
            docs.extend(
                list(
                    self.collection.find(
                        query,
                        self.pending_entry_projection(),
                        sort=[
                            (sort_field, ASCENDING),
                            ("_id", ASCENDING),
                        ],
                        limit=limit,
                    )
                )
            )

        deduped_docs: dict[Any, dict[str, Any]] = {}
        for doc in docs:
            deduped_docs[doc["_id"]] = doc

        ready_entries: list[dict[str, Any]] = []
        for doc in deduped_docs.values():
            scans = doc.get("scans") or {}
            for stage in ("T7", "T0"):
                pending = scans.get(f"{stage}_pending")
                if not isinstance(pending, dict):
                    continue
                submitted_at = pending.get("submitted_at")
                if not isinstance(submitted_at, datetime):
                    submitted_at = now
                next_poll_due_at = pending.get("next_poll_due_at")
                if isinstance(next_poll_due_at, datetime) and next_poll_due_at > now:
                    continue
                if next_poll_due_at is None and submitted_at > legacy_cutoff:
                    continue
                ready_entries.append(
                    {
                        "document_id": doc["_id"],
                        "document": doc,
                        "stage": stage,
                        "url": pending.get("requested_url")
                        or doc.get("task", {}).get("url"),
                        "pending": pending,
                        "submitted_at": submitted_at,
                        "last_polled_at": pending.get("last_polled_at"),
                        "next_poll_due_at": next_poll_due_at,
                    }
                )

        ready_entries.sort(
            key=lambda entry: (
                entry["next_poll_due_at"] or entry["submitted_at"],
                0 if entry["stage"] == "T7" else 1,
            )
        )
        return ready_entries[:limit]

    def process_pending_virustotal_results(self) -> tuple[int, int]:
        pending_count = self.count_pending_virustotal_documents(limit=1)
        work_count = 0

        work_count += self.collect_completed_vt_analysis_futures()

        available_slots = max(
            self.vt_analysis_max_inflight - self.count_inflight_vt_analyses(),
            0,
        )
        if pending_count == 0 or available_slots == 0:
            return work_count, pending_count

        ready_entries = self.list_ready_pending_virustotal_entries(
            min(self.vt_collect_batch_size, available_slots)
        )
        if not ready_entries:
            return work_count, pending_count

        for entry in ready_entries:
            if self.has_inflight_vt_analysis(entry["document_id"], entry["stage"]):
                continue
            analysis_id = entry["pending"]["analysis_id"]
            logging.info(
                "Queueing VirusTotal analysis fetch %s for %s",
                analysis_id,
                entry["url"],
            )
            future = self.vt_analysis_executor.submit(
                self.fetch_virustotal_analysis, analysis_id
            )
            self.vt_analysis_futures[future] = entry
            work_count += 1

        return work_count, pending_count

    def has_inflight_vt_analysis(self, document_id: Any, stage: str) -> bool:
        return any(
            meta.get("document_id") == document_id and meta.get("stage") == stage
            for meta in self.vt_analysis_futures.values()
        )

    def count_inflight_vt_submissions(self) -> int:
        return len(self.vt_submission_futures)

    def count_inflight_vt_analyses(self) -> int:
        return len(self.vt_analysis_futures)

    def fill_virustotal_submission_queue(self, known_pending_count: int | None = None) -> int:
        completed_count = self.collect_completed_vt_submission_futures()
        pending_count = (
            self.count_pending_virustotal_documents(
                limit=self.vt_pending_target + len(self.vt_submission_futures) + 1
            )
            if known_pending_count is None
            else known_pending_count
        )
        available_slots = max(
            min(
                self.vt_pending_target - pending_count - len(self.vt_submission_futures),
                self.vt_submission_max_inflight - self.count_inflight_vt_submissions(),
            ),
            0,
        )
        if available_slots == 0:
            return completed_count

        scheduled_count = 0

        queued_t0_candidates = self.find_queued_t0_candidates(
            min(self.vt_batch_size, available_slots)
        )
        scheduled = self.submit_candidate_documents("T0", queued_t0_candidates)
        scheduled_count += scheduled
        available_slots = max(available_slots - scheduled, 0)

        if available_slots > 0:
            queued_t7_candidates = self.find_queued_t7_candidates(
                min(self.vt_batch_size, available_slots)
            )
            scheduled = self.submit_candidate_documents("T7", queued_t7_candidates)
            scheduled_count += scheduled
            available_slots = max(available_slots - scheduled, 0)

        if available_slots > 0:
            t0_candidates = self.find_missing_t0_candidates(
                min(self.vt_batch_size, available_slots)
            )
            scheduled_count += self.submit_candidate_documents("T0", t0_candidates)

        return completed_count + scheduled_count

    def find_queued_t0_candidates(self, limit: int) -> list[dict[str, Any]]:
        now = utcnow()
        return list(
            self.collection.find(
                {
                    "$and": [
                        {"task.url": {"$type": "string", "$ne": ""}},
                        {"scans.T0_queue": {"$exists": True}},
                        {"scans.T0.virustotal": {"$exists": False}},
                        {"scans.T0_pending": {"$exists": False}},
                        {
                            "$or": [
                                {"scans.T0_submit_retry_at": {"$exists": False}},
                                {"scans.T0_submit_retry_at": {"$lte": now}},
                            ]
                        },
                    ],
                },
                sort=[
                    ("scans.T0_queue.queued_at", ASCENDING),
                    ("task.time", ASCENDING),
                    ("_id", ASCENDING),
                ],
                limit=limit,
            )
        )

    def find_queued_t7_candidates(self, limit: int) -> list[dict[str, Any]]:
        now = utcnow()
        return list(
            self.collection.find(
                {
                    "$and": [
                        {"task.url": {"$type": "string", "$ne": ""}},
                        {"scans.T7_queue": {"$exists": True}},
                        {"scans.T7.virustotal": {"$exists": False}},
                        {"scans.T7_pending": {"$exists": False}},
                        {"scans.T7.ignored": {"$ne": True}},
                        {
                            "$or": [
                                {"scans.T7_submit_retry_at": {"$exists": False}},
                                {"scans.T7_submit_retry_at": {"$lte": now}},
                            ]
                        },
                    ],
                },
                sort=[
                    ("scans.T7_queue.queued_at", ASCENDING),
                    ("scans.T0.completed_at", ASCENDING),
                    ("_id", ASCENDING),
                ],
                limit=limit,
            )
        )

    def process_google_safe_browsing_queue(self) -> tuple[int, bool]:
        work_count = self.collect_completed_gsb_futures()
        if len(self.gsb_futures) > 0:
            return work_count, True

        now = utcnow()
        if now < self.gsb_rate_limit_until:
            remaining = (self.gsb_rate_limit_until - now).total_seconds()
            logging.info(
                "Google Safe Browsing cooldown active for %.0fs; skipping queue.",
                remaining,
            )
            return work_count, False

        pending_entries = self.list_ready_pending_google_safe_browsing_entries(1)
        if pending_entries:
            entry = pending_entries[0]
            self.queue_google_safe_browsing_pending_entry(entry)
            return work_count + 1, True

        t7_candidates = self.find_due_t7_gsb_candidates(1)
        if t7_candidates:
            return work_count + self.submit_google_safe_browsing_candidates("T7", t7_candidates), True

        t0_candidates = self.find_missing_t0_gsb_candidates(1)
        if t0_candidates:
            return work_count + self.submit_google_safe_browsing_candidates("T0", t0_candidates), True

        return work_count, False

    def list_ready_pending_google_safe_browsing_entries(
        self, limit: int
    ) -> list[dict[str, Any]]:
        if limit <= 0:
            return []

        docs = list(
            self.collection.find(
                {
                    "$or": [
                        {"scans.T0_gsb_pending": {"$exists": True}},
                        {"scans.T7_gsb_pending": {"$exists": True}},
                    ]
                },
                {
                    "task.url": 1,
                    "scans.T0_gsb_pending": 1,
                    "scans.T7_gsb_pending": 1,
                },
                sort=[("_id", ASCENDING)],
                limit=max(limit * 2, 4),
            )
        )
        entries: list[dict[str, Any]] = []
        for doc in docs:
            scans = doc.get("scans") or {}
            for stage in ("T7", "T0"):
                pending = scans.get(f"{stage}_gsb_pending")
                if not isinstance(pending, dict):
                    continue
                entries.append(
                    {
                        "document_id": doc["_id"],
                        "stage": stage,
                        "url": pending.get("requested_url") or doc.get("task", {}).get("url"),
                        "pending": pending,
                    }
                )
        entries.sort(
            key=lambda entry: (
                (entry["pending"].get("submitted_at") or utcnow()),
                0 if entry["stage"] == "T7" else 1,
            )
        )
        return entries[:limit]

    def find_due_t7_gsb_candidates(self, limit: int) -> list[dict[str, Any]]:
        now = utcnow()
        return list(
            self.collection.find(
                {
                    "$and": [
                        {"task.url": {"$type": "string", "$ne": ""}},
                        {"scans.T0.completed_at": {"$exists": True}},
                        {"scans.T7_gsb_pending": {"$exists": False}},
                        {"scans.T7.google_safe_browsing": {"$exists": False}},
                        {"scans.T7.ignored": {"$ne": True}},
                        {
                            "$or": [
                                {"scans.T7_gsb_retry_at": {"$exists": False}},
                                {"scans.T7_gsb_retry_at": {"$lte": now}},
                            ]
                        },
                        {
                            "$or": [
                                {"scans.T0.next_scan_due_at": {"$lte": now}},
                                {
                                    "$and": [
                                        {"scans.T0.next_scan_due_at": {"$exists": False}},
                                        {
                                            "scans.T0.completed_at": {
                                                "$lte": now - timedelta(days=self.t7_days)
                                            }
                                        },
                                    ]
                                },
                            ]
                        },
                    ]
                },
                sort=[("scans.T0.completed_at", ASCENDING)],
                limit=limit,
            )
        )

    def find_missing_t0_gsb_candidates(self, limit: int) -> list[dict[str, Any]]:
        now = utcnow()
        return list(
            self.collection.find(
                {
                    "$and": [
                        {"task.url": {"$type": "string", "$ne": ""}},
                        {"scans.T0_gsb_pending": {"$exists": False}},
                        {"scans.T0.google_safe_browsing": {"$exists": False}},
                        {
                            "$or": [
                                {"scans.T0_gsb_retry_at": {"$exists": False}},
                                {"scans.T0_gsb_retry_at": {"$lte": now}},
                            ]
                        },
                    ]
                },
                sort=[("task.time", ASCENDING), ("_id", ASCENDING)],
                limit=limit,
            )
        )

    def submit_google_safe_browsing_candidates(
        self, stage: str, docs: list[dict[str, Any]]
    ) -> int:
        submitted_count = 0
        for doc in docs:
            url = doc["task"]["url"]
            pending_payload = {
                "requested_url": url,
                "submitted_at": utcnow(),
            }
            result = self.collection.update_one(
                {
                    "_id": doc["_id"],
                    f"scans.{stage}_gsb_pending": {"$exists": False},
                    f"scans.{stage}.google_safe_browsing": {"$exists": False},
                },
                {
                    "$set": {
                        f"scans.{stage}_gsb_pending": pending_payload,
                        "scans.last_updated_at": utcnow(),
                    },
                    "$unset": {
                        f"scans.{stage}_gsb_retry_at": "",
                        f"scans.{stage}_last_gsb_error": "",
                    },
                },
            )
            if result.matched_count != 1:
                continue
            self.queue_google_safe_browsing_pending_entry(
                {
                    "document_id": doc["_id"],
                    "stage": stage,
                    "url": url,
                    "pending": pending_payload,
                }
            )
            submitted_count += 1
        return submitted_count

    def queue_google_safe_browsing_pending_entry(self, entry: dict[str, Any]) -> None:
        future = self.gsb_executor.submit(self.check_google_safe_browsing, entry["url"])
        self.gsb_futures[future] = entry

    def collect_completed_gsb_futures(self) -> int:
        completed_count = 0
        for future in list(self.gsb_futures):
            if not future.done():
                continue
            entry = self.gsb_futures.pop(future)
            completed_count += 1
            try:
                gsb = future.result()
            except Exception as exc:
                logging.exception(
                    "Failed to collect Google Safe Browsing result for %s",
                    entry["url"],
                )
                failed_at = utcnow()
                retry_at = failed_at + timedelta(seconds=self.error_sleep_seconds)
                if isinstance(exc, RateLimitError):
                    retry_at = failed_at + timedelta(seconds=exc.cooldown_seconds)
                    if retry_at > self.gsb_rate_limit_until:
                        self.gsb_rate_limit_until = retry_at
                    self.collection.update_one(
                        {"_id": entry["document_id"]},
                        {
                            "$unset": {f"scans.{entry['stage']}_gsb_pending": ""},
                            "$set": {
                                f"scans.{entry['stage']}_gsb_retry_at": retry_at,
                                f"scans.{entry['stage']}_last_gsb_error": (
                                    f"gsb_rate_limited_at={failed_at.isoformat()}"
                                ),
                                "scans.last_updated_at": failed_at,
                            },
                        },
                    )
                    continue
                if entry["stage"] == "T7":
                    self.ignore_t7_scan(
                        entry["document_id"],
                        reason="google_safe_browsing_failed",
                    )
                    continue
                self.collection.update_one(
                    {"_id": entry["document_id"]},
                    {
                        "$unset": {f"scans.{entry['stage']}_gsb_pending": ""},
                        "$set": {
                            f"scans.{entry['stage']}_gsb_retry_at": retry_at,
                            f"scans.{entry['stage']}_last_gsb_error": (
                                f"gsb_failed_at={failed_at.isoformat()}"
                            ),
                            "scans.last_updated_at": failed_at,
                        },
                    },
                )
                continue

            partial_scan = {
                "requested_url": entry["url"],
                "started_at": entry["pending"].get("submitted_at") or utcnow(),
                "completed_at": utcnow(),
                "google_safe_browsing": gsb,
            }
            self.reconcile_stage_scan(
                entry["document_id"],
                entry["stage"],
                partial_scan,
                unset_paths=self.gsb_pending_clear_paths(entry["stage"]),
            )
        return completed_count

    def find_due_t7_candidates(self, limit: int) -> list[dict[str, Any]]:
        now = utcnow()
        return list(
            self.collection.find(
                {
                    "$and": [
                        {"task.url": {"$type": "string", "$ne": ""}},
                        {"scans.T0.completed_at": {"$exists": True}},
                        {"scans.T7.virustotal": {"$exists": False}},
                        {"scans.T7_pending": {"$exists": False}},
                        {"scans.T7.ignored": {"$ne": True}},
                        {
                            "$or": [
                                {"scans.T7_submit_retry_at": {"$exists": False}},
                                {"scans.T7_submit_retry_at": {"$lte": now}},
                            ]
                        },
                        {
                            "$or": [
                                {"scans.T0.next_scan_due_at": {"$lte": now}},
                                {
                                    "$and": [
                                        {"scans.T0.next_scan_due_at": {"$exists": False}},
                                        {
                                            "scans.T0.completed_at": {
                                                "$lte": now - timedelta(days=self.t7_days)
                                            }
                                        },
                                    ]
                                },
                            ]
                        },
                    ],
                },
                sort=[("scans.T0.completed_at", ASCENDING)],
                limit=limit,
            )
        )

    def find_missing_t0_candidates(self, limit: int) -> list[dict[str, Any]]:
        now = utcnow()
        return list(
            self.collection.find(
                {
                    "$and": [
                        {"task.url": {"$type": "string", "$ne": ""}},
                        {"scans.T0.virustotal": {"$exists": False}},
                        {"scans.T0_pending": {"$exists": False}},
                        {
                            "$or": [
                                {"scans.T0_submit_retry_at": {"$exists": False}},
                                {"scans.T0_submit_retry_at": {"$lte": now}},
                            ]
                        },
                    ],
                },
                sort=[("task.time", ASCENDING), ("_id", ASCENDING)],
                limit=limit,
            )
        )

    def submit_candidate_documents(
        self, stage: str, docs: list[dict[str, Any]]
    ) -> int:
        if not docs:
            return 0

        logging.info("Queueing %s VirusTotal %s scans", len(docs), stage)
        submitted_count = 0
        for doc in docs:
            if self.has_inflight_vt_submission(doc["_id"], stage):
                continue
            url = doc["task"]["url"]
            future = self.vt_submission_executor.submit(self.submit_virustotal_scan, url)
            self.vt_submission_futures[future] = {
                "document_id": doc["_id"],
                "stage": stage,
                "url": url,
            }
            submitted_count += 1

        return submitted_count

    def has_inflight_vt_submission(self, document_id: Any, stage: str) -> bool:
        return any(
            meta.get("document_id") == document_id and meta.get("stage") == stage
            for meta in self.vt_submission_futures.values()
        )

    def collect_completed_vt_submission_futures(self) -> int:
        completed_count = 0
        for future in list(self.vt_submission_futures):
            if not future.done():
                continue
            meta = self.vt_submission_futures.pop(future)
            completed_count += 1
            self.handle_vt_submission_completion(meta, future)
        return completed_count

    def handle_vt_submission_completion(
        self, meta: dict[str, Any], future: Future[Any]
    ) -> None:
        stage = meta["stage"]
        url = meta["url"]
        document_id = meta["document_id"]
        try:
            submission = future.result()
            pending_payload = {
                "requested_url": url,
                "submitted_at": submission["submitted_at"],
                "analysis_id": submission["analysis_id"],
                "submission": submission["submission_payload"],
                "last_polled_at": None,
                "poll_count": 0,
                "next_poll_due_at": submission["submitted_at"]
                + timedelta(seconds=self.vt_batch_settle_seconds),
            }
            result = self.collection.update_one(
                {
                    "_id": document_id,
                    f"scans.{stage}.virustotal": {"$exists": False},
                    f"scans.{stage}_pending": {"$exists": False},
                },
                {
                    "$set": {
                        f"scans.{stage}_pending": pending_payload,
                        "scans.last_updated_at": utcnow(),
                    },
                    "$unset": {
                        **(
                            {"scans.T0_queue": ""}
                            if stage == "T0"
                            else {"scans.T7_queue": ""}
                        ),
                        f"scans.{stage}_submit_retry_at": "",
                        f"scans.{stage}_last_submit_error": "",
                    },
                },
            )
            if result.matched_count != 1:
                logging.warning(
                    "Skipped recording pending %s submission for %s because the document changed.",
                    stage,
                    url,
                )
        except Exception:
            logging.exception(
                "Failed to submit VirusTotal %s scan for %s (%s)",
                stage,
                url,
                document_id,
            )
            if stage == "T7":
                self.ignore_t7_scan(
                    document_id,
                    reason="virustotal_submission_failed",
                )
                return
            failed_at = utcnow()
            retry_at = failed_at + timedelta(
                seconds=self.vt_submit_retry_cooldown_seconds
            )
            self.collection.update_one(
                {"_id": document_id},
                {
                    "$set": {
                        f"scans.{stage}_submit_retry_at": retry_at,
                        f"scans.{stage}_last_submit_error": (
                            f"submit_failed_at={failed_at.isoformat()}"
                        ),
                        "scans.last_updated_at": failed_at,
                    }
                },
            )

    def mark_pending_virustotal_polled(self, entry: dict[str, Any]) -> None:
        stage = entry["stage"]
        pending = entry["pending"]
        poll_count = int(pending.get("poll_count", 0) or 0) + 1
        polled_at = utcnow()
        self.update_document(
            entry["document_id"],
            {
                "$set": {
                    f"scans.{stage}_pending.last_polled_at": polled_at,
                    f"scans.{stage}_pending.poll_count": poll_count,
                    f"scans.{stage}_pending.next_poll_due_at": self.calculate_next_pending_poll_at(
                        poll_count=poll_count,
                        now=polled_at,
                    ),
                    "scans.last_updated_at": polled_at,
                }
            },
        )

    def mark_pending_virustotal_retry(
        self,
        entry: dict[str, Any],
        *,
        error: str,
        cooldown_seconds: int | None = None,
    ) -> None:
        stage = entry["stage"]
        if stage == "T7":
            self.ignore_t7_scan(
                entry["document_id"],
                reason=error,
            )
            return
        pending = entry["pending"]
        poll_count = int(pending.get("poll_count", 0) or 0) + 1
        polled_at = utcnow()
        delay_seconds = (
            cooldown_seconds
            if cooldown_seconds is not None
            else self.vt_analysis_retry_cooldown_seconds
        )
        next_poll_due_at = max(
            self.calculate_next_pending_poll_at(
                poll_count=poll_count,
                now=polled_at,
            ),
            polled_at + timedelta(seconds=delay_seconds),
        )
        self.update_document(
            entry["document_id"],
            {
                "$set": {
                    f"scans.{stage}_pending.last_polled_at": polled_at,
                    f"scans.{stage}_pending.poll_count": poll_count,
                    f"scans.{stage}_pending.next_poll_due_at": next_poll_due_at,
                    f"scans.{stage}_pending.last_error": error[:500],
                    "scans.last_updated_at": polled_at,
                }
            },
        )

    def calculate_next_pending_poll_at(
        self,
        *,
        poll_count: int,
        now: datetime,
    ) -> datetime:
        delay_seconds = self.vt_batch_poll_interval_seconds * (
            self.vt_pending_backoff_multiplier ** max(poll_count - 1, 0)
        )
        delay_seconds = max(delay_seconds, self.vt_batch_poll_interval_seconds)
        delay_seconds = min(delay_seconds, self.vt_pending_max_poll_interval_seconds)
        return now + timedelta(seconds=delay_seconds)

    def collect_completed_vt_analysis_futures(self) -> int:
        completed_count = 0
        for future in list(self.vt_analysis_futures):
            if not future.done():
                continue
            entry = self.vt_analysis_futures.pop(future)
            completed_count += 1
            analysis_id = entry["pending"]["analysis_id"]
            try:
                analysis = future.result()
            except Exception:
                logging.exception(
                    "Failed to collect VirusTotal analysis %s for %s",
                    analysis_id,
                    entry["url"],
                )
                self.mark_pending_virustotal_retry(
                    entry,
                    error=f"analysis_fetch_failed:{analysis_id}",
                )
                continue

            status = analysis.get("data", {}).get("attributes", {}).get("status")
            if status == "completed":
                self.finalize_scan_after_vt(entry, analysis)
            else:
                self.mark_pending_virustotal_polled(entry)
        return completed_count

    def finalize_scan_after_vt(
        self, entry: dict[str, Any], analysis: dict[str, Any]
    ) -> None:
        stage = entry["stage"]
        pending = entry["pending"]
        vt_result = self.build_virustotal_result(pending=pending, analysis=analysis)
        partial_scan = {
            "requested_url": entry["url"],
            "started_at": entry["submitted_at"],
            "completed_at": utcnow(),
            "virustotal": vt_result,
        }
        self.reconcile_stage_scan(
            entry["document_id"],
            stage,
            partial_scan,
            unset_paths=self.vt_pending_clear_paths(stage),
        )

    def vt_pending_clear_paths(self, stage: str) -> list[str]:
        return [
            f"scans.{stage}_pending",
            f"scans.{stage}_submit_retry_at",
            f"scans.{stage}_last_submit_error",
        ]

    def gsb_pending_clear_paths(self, stage: str) -> list[str]:
        return [
            f"scans.{stage}_gsb_pending",
            f"scans.{stage}_gsb_retry_at",
            f"scans.{stage}_last_gsb_error",
        ]

    def collect_completed_scrape_futures(self) -> int:
        completed_count = 0
        for future in list(self.scrape_futures):
            if not future.done():
                continue
            meta = self.scrape_futures.pop(future)
            completed_count += 1
            stage = meta["stage"]
            try:
                scrape = future.result()
            except Exception as exc:
                logging.exception(
                    "Scrape worker failed for document %s stage %s",
                    meta["document_id"],
                    stage,
                )
                scrape = {
                    "triggered": True,
                    "status": "error",
                    "reason": "scrape_worker_failed",
                    "error": repr(exc),
                    "checked_at": utcnow(),
                }

            self.reconcile_stage_scan(
                meta["document_id"],
                stage,
                {"scrape": scrape},
                allow_scrape_queue=False,
            )
            if stage == "T7" and scrape.get("status") == "error":
                self.ignore_t7_scan(
                    meta["document_id"],
                    reason=(scrape.get("error") or scrape.get("reason") or "scrape_failed"),
                )
        return completed_count

    def process_due_t7(self) -> bool:
        return bool(self.find_due_t7_candidates(1))

    def process_missing_t0(self) -> bool:
        return bool(self.find_missing_t0_candidates(1))

    def write_scan(
        self,
        document_id: Any,
        stage: str,
        scan: dict[str, Any],
        *,
        unset_paths: list[str] | None = None,
    ) -> None:
        update = {
            "$set": {
                f"scans.{stage}": scan,
                "scans.last_updated_at": utcnow(),
            }
        }
        if unset_paths:
            update["$unset"] = {path: "" for path in unset_paths}
        try:
            self.update_document(document_id, update)
        except (DocumentTooLarge, OperationFailure) as exc:
            if isinstance(exc, OperationFailure) and "too large" not in str(exc).lower():
                raise
            logging.warning(
                "Document %s exceeded MongoDB size limit for %s, retrying with compact scan payload.",
                document_id,
                stage,
            )
            compact_scan = self.compact_scan_payload(scan)
            update["$set"][f"scans.{stage}"] = compact_scan
            self.update_document(document_id, update)

    def merge_scan_payload(
        self, existing: dict[str, Any], partial: dict[str, Any]
    ) -> dict[str, Any]:
        merged = dict(existing)
        for key, value in partial.items():
            if key == "requested_url":
                merged[key] = merged.get(key) or value
            elif key in {"started_at", "completed_at"}:
                current = merged.get(key)
                if isinstance(current, datetime) and isinstance(value, datetime):
                    merged[key] = min(current, value)
                else:
                    merged[key] = current or value
            elif key == "next_scan_due_at":
                merged[key] = merged.get(key) or value
            else:
                merged[key] = value
        return merged

    def ignore_t7_scan(self, document_id: Any, *, reason: str) -> None:
        ignored_at = utcnow()
        self.collection.update_one(
            {"_id": document_id},
            {
                "$set": {
                    "scans.T7.ignored": True,
                    "scans.T7.ignored_at": ignored_at,
                    "scans.T7.ignored_reason": reason[:500],
                    "scans.last_updated_at": ignored_at,
                },
                "$unset": {
                    "scans.T7_queue": "",
                    "scans.T7_pending": "",
                    "scans.T7_submit_retry_at": "",
                    "scans.T7_last_submit_error": "",
                    "scans.T7_gsb_pending": "",
                    "scans.T7_gsb_retry_at": "",
                    "scans.T7_last_gsb_error": "",
                },
            },
        )

    def reconcile_stage_scan(
        self,
        document_id: Any,
        stage: str,
        partial_scan: dict[str, Any],
        *,
        unset_paths: list[str] | None = None,
        allow_scrape_queue: bool = True,
    ) -> dict[str, Any]:
        doc = self.collection.find_one(
            {"_id": document_id},
            {
                "task.url": 1,
                "scans.T0": 1,
                f"scans.{stage}": 1,
            },
        )
        if not doc:
            raise RuntimeError(f"Document {document_id!r} disappeared during scan reconciliation.")

        scans = doc.get("scans") or {}
        existing = scans.get(stage)
        if not isinstance(existing, dict):
            existing = {}

        merged = self.merge_scan_payload(existing, partial_scan)
        merged["requested_url"] = merged.get("requested_url") or doc.get("task", {}).get("url")

        if stage == "T0":
            completed_at = merged.get("completed_at")
            if isinstance(completed_at, datetime) and "next_scan_due_at" not in merged:
                merged["next_scan_due_at"] = completed_at + timedelta(days=self.t7_days)
        else:
            baseline = (scans.get("T0") or {}) if isinstance(scans.get("T0"), dict) else {}
            change_detection = self.evaluate_significant_change(baseline, merged)
            merged["change_detection"] = change_detection
            if change_detection["significant"]:
                if allow_scrape_queue and not self.has_successful_scrape(merged):
                    self.queue_scrape_work(
                        document_id=document_id,
                        stage=stage,
                        url=merged.get("requested_url") or doc.get("task", {}).get("url"),
                        reason=", ".join(change_detection["reasons"]),
                    )
            elif "scrape" not in merged:
                merged["scrape"] = {
                    "triggered": False,
                    "status": "skipped",
                    "reason": "no_significant_change",
                    "reasons": change_detection["reasons"],
                    "checked_at": utcnow(),
                }

        self.write_scan(document_id, stage, merged, unset_paths=unset_paths)
        return merged

    def queue_scrape_work(
        self,
        *,
        document_id: Any,
        stage: str,
        url: str,
        reason: str,
        previous_scrape: dict[str, Any] | None = None,
    ) -> bool:
        if not url or self.has_inflight_scrape(document_id, stage):
            return False
        future = self.scrape_executor.submit(
            self.scrape_url,
            url=url,
            reason=reason,
            previous_scrape=previous_scrape,
        )
        self.scrape_futures[future] = {
            "document_id": document_id,
            "stage": stage,
        }
        return True

    def update_document(self, document_id: Any, update: dict[str, Any]) -> None:
        result = self.collection.update_one({"_id": document_id}, update)
        if result.matched_count != 1:
            raise RuntimeError(f"Failed to update document {document_id!r}.")

    def compact_scan_payload(self, scan: dict[str, Any]) -> dict[str, Any]:
        compact = {
            "requested_url": scan.get("requested_url"),
            "started_at": scan.get("started_at"),
            "completed_at": scan.get("completed_at"),
            "virustotal": {
                "submitted_at": scan.get("virustotal", {}).get("submitted_at"),
                "completed_at": scan.get("virustotal", {}).get("completed_at"),
                "analysis_id": scan.get("virustotal", {}).get("analysis_id"),
                "analysis_status": scan.get("virustotal", {}).get("analysis_status"),
                "final_url": scan.get("virustotal", {}).get("final_url"),
                "stats": scan.get("virustotal", {}).get("stats"),
                "malicious_engine_count": scan.get("virustotal", {}).get("malicious_engine_count"),
                "suspicious_engine_count": scan.get("virustotal", {}).get("suspicious_engine_count"),
                "non_harmless_engines": scan.get("virustotal", {}).get("non_harmless_engines"),
            },
            "google_safe_browsing": scan.get("google_safe_browsing"),
            "change_detection": scan.get("change_detection"),
        }
        if "next_scan_due_at" in scan:
            compact["next_scan_due_at"] = scan["next_scan_due_at"]
        if "scrape" in scan:
            compact["scrape"] = self.compact_scrape_payload(scan["scrape"])
        return compact

    def compact_scrape_payload(self, scrape: dict[str, Any]) -> dict[str, Any]:
        compact = {
            "triggered": scrape.get("triggered"),
            "status": scrape.get("status"),
            "reason": scrape.get("reason"),
            "fetched_at": scrape.get("fetched_at"),
            "final_url": scrape.get("final_url"),
            "status_code": scrape.get("status_code"),
            "title": scrape.get("title"),
            "content_sha256": scrape.get("content_sha256"),
            "truncated": scrape.get("truncated"),
        }
        if scrape.get("error"):
            compact["error"] = scrape["error"]
        return compact

    def submit_virustotal_scan(self, url: str) -> dict[str, Any]:
        submitted_at = utcnow()
        submit_payload = self.virustotal_request(
            "POST",
            "/urls",
            data={"url": url},
            expected_statuses={200, 201},
        )
        return {
            "submitted_at": submitted_at,
            "analysis_id": submit_payload["data"]["id"],
            "submission_payload": submit_payload,
        }

    def build_virustotal_result(
        self, *, pending: dict[str, Any], analysis: dict[str, Any]
    ) -> dict[str, Any]:
        attributes = analysis["data"]["attributes"]
        stats = attributes.get("stats", {})
        non_harmless = [
            {
                "engine": engine_name,
                "category": engine_result.get("category"),
                "result": engine_result.get("result"),
                "method": engine_result.get("method"),
            }
            for engine_name, engine_result in (attributes.get("results") or {}).items()
            if engine_result.get("category") not in {"SCAN_CATEGORY_HARMLESS", "SCAN_CATEGORY_UNDETECTED"}
        ]
        non_harmless.sort(key=lambda entry: (entry["category"] or "", entry["engine"]))
        return {
            "submitted_at": pending.get("submitted_at"),
            "completed_at": utcnow(),
            "analysis_id": pending.get("analysis_id"),
            "analysis_status": attributes.get("status"),
            "final_url": attributes.get("url"),
            "stats": stats,
            "malicious_engine_count": int(stats.get("malicious", 0) or 0),
            "suspicious_engine_count": int(stats.get("suspicious", 0) or 0),
            "non_harmless_engines": non_harmless,
            "analysis": analysis,
            "submission": pending.get("submission"),
        }

    def fetch_virustotal_analysis(self, analysis_id: str) -> dict[str, Any]:
        return self.virustotal_request("GET", f"/analyses/{analysis_id}")

    def record_vt_request(self, method: str, path: str, status_code: int) -> None:
        current_day = utcnow().date().isoformat()
        stats = self.vt_request_stats
        if stats.day != current_day:
            logging.info(
                "VT daily summary day=%s total=%s submit=%s analyses=%s other=%s success=%s quota_429=%s",
                stats.day,
                stats.total_requests,
                stats.submit_requests,
                stats.analysis_requests,
                stats.other_requests,
                stats.successful_requests,
                stats.quota_429s,
            )
            stats = VTRequestStats(day=current_day)
            self.vt_request_stats = stats

        stats.total_requests += 1
        if method == "POST" and path == "/urls":
            stats.submit_requests += 1
        elif method == "GET" and path.startswith("/analyses/"):
            stats.analysis_requests += 1
        else:
            stats.other_requests += 1

        if 200 <= status_code < 300:
            stats.successful_requests += 1
        if status_code == 429:
            stats.quota_429s += 1

        if stats.total_requests % 25 == 0 or status_code == 429:
            logging.info(
                "VT usage day=%s total=%s submit=%s analyses=%s other=%s success=%s quota_429=%s last=%s %s status=%s",
                stats.day,
                stats.total_requests,
                stats.submit_requests,
                stats.analysis_requests,
                stats.other_requests,
                stats.successful_requests,
                stats.quota_429s,
                method,
                path,
                status_code,
            )

    def virustotal_request(
        self,
        method: str,
        path: str,
        *,
        expected_statuses: set[int] | None = None,
        **kwargs: Any,
    ) -> Any:
        expected_statuses = expected_statuses or {200}
        last_error: Exception | None = None
        max_attempts = 1 if path.startswith("/analyses/") else 3
        for attempt in range(max_attempts):
            headers = dict(kwargs.pop("headers", {}))
            with self.vt_request_lock:
                if not self.vt_disable_throttle:
                    self.vt_key.wait()
                key = self.vt_key
                headers["x-apikey"] = key.api_key
                try:
                    response = self.session.request(
                        method,
                        f"{VT_BASE_URL}{path}",
                        headers=headers,
                        timeout=self.request_timeout,
                        **kwargs,
                    )
                except requests.RequestException as exc:
                    last_error = exc
                    sleep_for = min(2**attempt, 30)
                    logging.warning(
                        "VirusTotal request failed with %s using key %s, retrying in %ss",
                        exc,
                        key.fingerprint,
                        sleep_for,
                    )
                    time.sleep(sleep_for)
                    continue

            self.record_vt_request(method, path, response.status_code)

            if response.status_code in expected_statuses:
                return safe_json(response)

            payload = safe_json(response)
            if is_retryable_status(response.status_code):
                if response.status_code == 429:
                    if not self.vt_disable_throttle:
                        cooldown_seconds = parse_retry_after_seconds(
                            response.headers.get("Retry-After"),
                            float(self.vt_rate_limit_cooldown_seconds),
                        )
                        self.vt_key.mark_rate_limited(cooldown_seconds)
                        logging.warning(
                            "Cooling down VirusTotal key %s for %.1fs after rate limit response",
                            key.fingerprint,
                            cooldown_seconds,
                        )
                    raise RetryableError(
                        f"VirusTotal quota exceeded for {method} {path} using key {key.fingerprint}"
                    )
                else:
                    sleep_for = min(2**attempt, 60)
                logging.warning(
                    "VirusTotal returned %s for %s %s with key %s, retrying in %.1fs: %s",
                    response.status_code,
                    method,
                    path,
                    key.fingerprint,
                    sleep_for,
                    payload,
                )
                time.sleep(sleep_for)
                continue

            raise RuntimeError(
                f"VirusTotal request {method} {path} failed with {response.status_code}: {payload}"
            )

        raise RetryableError(f"VirusTotal request {method} {path} failed repeatedly: {last_error}")

    def check_google_safe_browsing(self, url: str) -> dict[str, Any]:
        now = utcnow()
        if now < self.gsb_rate_limit_until:
            remaining = (self.gsb_rate_limit_until - now).total_seconds()
            raise RateLimitError(
                f"Google Safe Browsing cooldown active for {url}",
                cooldown_seconds=remaining,
            )
        payload = {
            "client": {"clientId": "vt-scanner", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

        for attempt in range(6):
            try:
                response = self.gsb_session.post(
                    GSB_FIND_URL,
                    params={"key": self.gsb_api_key},
                    json=payload,
                    timeout=self.request_timeout,
                )
            except requests.RequestException as exc:
                sleep_for = min(2**attempt, 30)
                logging.warning(
                    "Google Safe Browsing request failed with %s, retrying in %ss",
                    exc,
                    sleep_for,
                )
                time.sleep(sleep_for)
                continue

            body = safe_json(response)
            if response.status_code == 200:
                matches = body.get("matches", []) if isinstance(body, dict) else []
                return {
                    "status": "malicious" if matches else "safe",
                    "url": url,
                    "matched": bool(matches),
                    "match_count": len(matches),
                    "threat_types": sorted(
                        {match.get("threatType") for match in matches if match.get("threatType")}
                    ),
                    "platform_types": sorted(
                        {match.get("platformType") for match in matches if match.get("platformType")}
                    ),
                    "threat_entry_types": sorted(
                        {
                            match.get("threatEntryType")
                            for match in matches
                            if match.get("threatEntryType")
                        }
                    ),
                    "matches": matches,
                    "checked_at": utcnow(),
                    "error": None,
                }

            if response.status_code == 429:
                raise RateLimitError(
                    f"Google Safe Browsing rate limited for {url}",
                    cooldown_seconds=12 * 60 * 60,
                )

            if is_retryable_status(response.status_code):
                sleep_for = min(2**attempt, 60)
                logging.warning(
                    "Google Safe Browsing returned %s, retrying in %ss: %s",
                    response.status_code,
                    sleep_for,
                    body,
                )
                time.sleep(sleep_for)
                continue

            raise RuntimeError(
                f"Google Safe Browsing lookup failed with {response.status_code}: {body}"
            )

        raise RetryableError(f"Google Safe Browsing lookup failed repeatedly for {url}")

    def evaluate_significant_change(
        self, baseline: dict[str, Any], current: dict[str, Any]
    ) -> dict[str, Any]:
        previous_vt = int(
            ((baseline.get("virustotal") or {}).get("malicious_engine_count") or 0)
        )
        current_vt = int(
            ((current.get("virustotal") or {}).get("malicious_engine_count") or 0)
        )
        previous_gsb_malicious = bool(
            ((baseline.get("google_safe_browsing") or {}).get("matched") or False)
        )
        current_gsb_malicious = bool(
            ((current.get("google_safe_browsing") or {}).get("matched") or False)
        )

        reasons: list[str] = []
        if previous_vt < 7 and current_vt > 7:
            reasons.append("virustotal_malicious_threshold_crossed")
        if not previous_gsb_malicious and current_gsb_malicious:
            reasons.append("google_safe_browsing_became_malicious")

        return {
            "significant": bool(reasons),
            "reasons": reasons,
            "baseline": {
                "virustotal_malicious_engine_count": previous_vt,
                "google_safe_browsing_malicious": previous_gsb_malicious,
            },
            "current": {
                "virustotal_malicious_engine_count": current_vt,
                "google_safe_browsing_malicious": current_gsb_malicious,
            },
            "evaluated_at": utcnow(),
        }

    def scrape_url(
        self,
        *,
        url: str,
        reason: str,
        previous_scrape: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if StealthyFetcher is None:
            return {
                "triggered": True,
                "status": "error",
                "reason": reason,
                "error": f"scrapling_import_failed: {SCRAPLING_IMPORT_ERROR}",
                "checked_at": utcnow(),
                "previous_scrape_status": (previous_scrape or {}).get("status"),
            }

        fetcher = StealthyFetcher()
        page = None
        try:
            for call in (
                lambda: fetcher.fetch(
                    url,
                    headless=self.scrape_headless,
                    network_idle=True,
                    disable_resources=True,
                ),
                lambda: fetcher.fetch(url),
                lambda: fetcher.get(url),
            ):
                try:
                    page = call()
                    break
                except TypeError:
                    continue
                except Exception as exc:  # pragma: no cover - depends on target site/runtime
                    return {
                        "triggered": True,
                        "status": "error",
                        "reason": reason,
                        "error": repr(exc),
                        "checked_at": utcnow(),
                    }
            if page is None:
                return {
                    "triggered": True,
                    "status": "error",
                    "reason": reason,
                    "error": "No compatible Scrapling fetch method was available.",
                    "checked_at": utcnow(),
                }

            html = self.extract_scrape_html(page)
            truncated_html, truncated = compact_text(html, self.scrape_html_max_bytes)
            title = self.extract_scrape_title(page)
            final_url = self.extract_page_attr(page, ["url", "real_url", "response_url"])
            status_code = self.extract_page_attr(page, ["status", "status_code", "code"])
            return {
                "triggered": True,
                "status": "success",
                "reason": reason,
                "fetched_at": utcnow(),
                "final_url": final_url,
                "status_code": status_code,
                "title": title,
                "html": truncated_html,
                "truncated": truncated,
                "content_sha256": hashlib.sha256(truncated_html.encode("utf-8")).hexdigest(),
            }
        except Exception as exc:  # pragma: no cover - depends on target site/runtime
            return {
                "triggered": True,
                "status": "error",
                "reason": reason,
                "error": repr(exc),
                "checked_at": utcnow(),
            }
        finally:
            closer = getattr(fetcher, "close", None)
            if callable(closer):
                try:
                    closer()
                except Exception:
                    logging.debug("Ignoring Scrapling close failure", exc_info=True)

    def extract_scrape_html(self, page: Any) -> str:
        for attr in ("html", "content", "body", "markup", "text"):
            value = getattr(page, attr, None)
            if callable(value):
                try:
                    value = value()
                except TypeError:
                    value = None
            if isinstance(value, bytes):
                return value.decode("utf-8", errors="ignore")
            if isinstance(value, str) and value:
                return value
        return str(page)

    def extract_scrape_title(self, page: Any) -> str | None:
        title_value = getattr(page, "title", None)
        if callable(title_value):
            try:
                title_value = title_value()
            except TypeError:
                title_value = None
        if isinstance(title_value, str) and title_value.strip():
            return title_value.strip()

        css = getattr(page, "css", None)
        if callable(css):
            for selector in ("title::text", "title"):
                try:
                    selection = css(selector)
                except Exception:
                    continue
                getter = getattr(selection, "get", None)
                if callable(getter):
                    try:
                        result = getter()
                    except Exception:
                        continue
                    if isinstance(result, str) and result.strip():
                        return result.strip()
        return None

    def extract_page_attr(self, page: Any, attr_names: list[str]) -> Any:
        for attr_name in attr_names:
            value = getattr(page, attr_name, None)
            if callable(value):
                try:
                    value = value()
                except TypeError:
                    value = None
            if value is not None:
                return value
        return None

    def backfill_from_live_feed(self) -> int:
        response = self.session.get(URLSCAN_LIVE_URL, timeout=self.request_timeout)
        response.raise_for_status()
        payload = safe_json(response)
        results = payload.get("results", []) if isinstance(payload, dict) else []

        unique_by_url: dict[str, dict[str, Any]] = {}
        for item in results:
            url = (item.get("task") or {}).get("url")
            if not isinstance(url, str) or not url.strip():
                continue
            unique_by_url.setdefault(url, item)

        if not unique_by_url:
            return 0

        urls = list(unique_by_url.keys())
        existing_urls = set(
            self.collection.distinct("task.url", {"task.url": {"$in": urls}})
        )

        inserted = 0
        for url, live_item in unique_by_url.items():
            if url in existing_urls:
                continue
            try:
                new_doc = self.build_document_from_live_item(live_item)
            except Exception:
                logging.exception("Failed to backfill urlscan document for %s", url)
                continue

            result = self.collection.update_one(
                {"_id": new_doc["_id"]},
                {"$setOnInsert": new_doc},
                upsert=True,
            )
            if result.upserted_id is not None:
                inserted += 1
                logging.info("Inserted new live urlscan document for %s", url)

        if inserted == 0:
            logging.info("Live feed had no new unique URLs to insert.")
        else:
            logging.info("Inserted %s new live urlscan documents.", inserted)
        return inserted

    def build_document_from_live_item(self, live_item: dict[str, Any]) -> dict[str, Any]:
        result_url = live_item.get("result")
        if not isinstance(result_url, str) or not result_url:
            raise ValueError(f"Live item {live_item.get('_id')} is missing result URL.")

        urlscanresults = self.fetch_urlscan_json(result_url)
        dom_url = (urlscanresults.get("task") or {}).get("domURL")
        dom_payload = self.fetch_urlscan_dom(dom_url) if dom_url else None

        document = {
            "_id": live_item.get("_id"),
            "submitter": live_item.get("submitter") or {},
            "task": live_item.get("task") or {},
            "stats": live_item.get("stats") or {},
            "page": live_item.get("page") or {},
            "_score": live_item.get("_score"),
            "result": live_item.get("result"),
            "screenshot": live_item.get("screenshot"),
            "urlscanresults": urlscanresults,
            "urlscanresults_updated_at": utcnow(),
            "scans": {
                "T0_queue": {
                    "queued_at": utcnow(),
                    "source": "urlscan_live_feed",
                }
            },
        }
        if dom_payload is not None:
            document["dom"] = dom_payload
        return document

    def fetch_urlscan_json(self, url: str) -> dict[str, Any]:
        self.urlscan_retrieve_limiter.wait()
        headers = {"API-Key": self.urlscan_api_key}
        response = self.session.get(url, headers=headers, timeout=self.request_timeout)
        if response.status_code != 200:
            raise RuntimeError(
                f"urlscan result fetch failed with {response.status_code}: {safe_json(response)}"
            )
        payload = safe_json(response)
        if not isinstance(payload, dict):
            raise RuntimeError(f"Unexpected urlscan result payload type for {url!r}.")
        return payload

    def fetch_urlscan_dom(self, url: str) -> dict[str, Any]:
        self.urlscan_retrieve_limiter.wait()
        headers = {"API-Key": self.urlscan_api_key}
        response = self.session.get(url, headers=headers, timeout=self.request_timeout)
        if response.status_code != 200:
            raise RuntimeError(
                f"urlscan DOM fetch failed with {response.status_code}: {response.text[:1000]}"
            )
        return {
            "data": response.content,
            "size": len(response.content),
        }


def configure_logging() -> None:
    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(message)s",
    )


def main() -> None:
    configure_logging()
    service = VTScannerService()
    service.run_forever()


if __name__ == "__main__":
    main()
