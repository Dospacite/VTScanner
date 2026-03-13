#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import logging
import os
import time
from collections import deque
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

    def mark_rate_limited(self, cooldown_seconds: float) -> None:
        self.cooldown_until = max(self.cooldown_until, time.time() + cooldown_seconds)


class VTKeyPool:
    def __init__(
        self,
        api_keys: list[str],
        *,
        minute_limit: int,
        minute_window_seconds: int,
        day_limit: int,
        day_window_seconds: int,
        min_interval_seconds: float,
    ) -> None:
        if not api_keys:
            raise ValueError("At least one VirusTotal API key is required.")
        self.keys = [
            VTKeyState.from_api_key(
                key,
                minute_limit=minute_limit,
                minute_window_seconds=minute_window_seconds,
                day_limit=day_limit,
                day_window_seconds=day_window_seconds,
                min_interval_seconds=min_interval_seconds,
            )
            for key in api_keys
        ]
        self.next_index = 0

    def acquire(self) -> VTKeyState:
        while True:
            now = time.time()
            best_key: VTKeyState | None = None
            best_wait: float | None = None
            total_keys = len(self.keys)
            for offset in range(total_keys):
                key = self.keys[(self.next_index + offset) % total_keys]
                wait = key.next_available_in(now)
                if wait <= 0:
                    key.reserve(now)
                    self.next_index = (self.next_index + offset + 1) % total_keys
                    return key
                if best_wait is None or wait < best_wait:
                    best_key = key
                    best_wait = wait
            if best_key is None or best_wait is None:
                raise RuntimeError("VirusTotal key scheduler failed unexpectedly.")
            logging.info(
                "All VirusTotal keys are rate-limited, waiting %.2fs for key %s",
                best_wait,
                best_key.fingerprint,
            )
            time.sleep(min(max(best_wait, 0.25), 60.0))

    def mark_rate_limited(self, key: VTKeyState, cooldown_seconds: float) -> None:
        key.mark_rate_limited(cooldown_seconds)
        logging.warning(
            "Cooling down VirusTotal key %s for %.1fs after rate limit response",
            key.fingerprint,
            cooldown_seconds,
        )


class VTScannerService:
    def __init__(self) -> None:
        load_dotenv()

        self.mongo_uri = os.environ["MONGO_URI"]
        self.gsb_api_key = os.environ["GOOGLE_SAFE_BROWSING_API_KEY"]
        self.urlscan_api_key = os.environ["URLSCAN_API_KEY"]
        self.mongo_db_name = os.getenv("MONGO_DB_NAME", "urlscan")
        self.mongo_collection_name = os.getenv("MONGO_COLLECTION_NAME", "live")
        self.vt_keys_file = os.getenv("VT_API_KEYS_FILE", "VTAPIKEYS.txt")

        self.request_timeout = getenv_int("REQUEST_TIMEOUT_SECONDS", 60)
        self.error_sleep_seconds = getenv_int("ERROR_SLEEP_SECONDS", 30)
        self.idle_sleep_seconds = getenv_int("IDLE_SLEEP_SECONDS", 60)
        self.t7_days = getenv_int("T7_DELAY_DAYS", 7)
        self.scrape_html_max_bytes = getenv_int("SCRAPE_HTML_MAX_BYTES", 524288)
        self.scrape_headless = getenv_bool("SCRAPE_HEADLESS", True)
        self.vt_batch_size = getenv_int("VT_BATCH_SIZE", 100)
        self.vt_collect_batch_size = getenv_int("VT_COLLECT_BATCH_SIZE", self.vt_batch_size)
        self.vt_pending_target = getenv_int("VT_PENDING_TARGET", max(self.vt_batch_size * 3, 300))
        self.vt_batch_settle_seconds = getenv_int("VT_BATCH_SETTLE_SECONDS", 300)
        self.vt_batch_poll_interval_seconds = getenv_int(
            "VT_BATCH_POLL_INTERVAL_SECONDS", 30
        )
        self.vt_batch_max_wait_seconds = getenv_int(
            "VT_BATCH_MAX_WAIT_SECONDS", 900
        )
        self.vt_minute_limit = getenv_int("VT_MINUTE_LIMIT", 3)
        self.vt_minute_window_seconds = getenv_int("VT_MINUTE_WINDOW_SECONDS", 75)
        self.vt_day_limit = getenv_int("VT_DAY_LIMIT", 480)
        self.vt_day_window_seconds = getenv_int("VT_DAY_WINDOW_SECONDS", 86400)
        self.vt_min_request_spacing_seconds = getenv_int(
            "VT_MIN_REQUEST_SPACING_SECONDS", 17
        )
        self.vt_rate_limit_cooldown_seconds = getenv_int(
            "VT_RATE_LIMIT_COOLDOWN_SECONDS", 180
        )

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "VTScanner/1.0"})

        self.vt_pool = VTKeyPool(
            self._load_vt_keys(self.vt_keys_file),
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

    def _load_vt_keys(self, path: str) -> list[str]:
        with open(path, "r", encoding="utf-8") as handle:
            keys = [line.strip() for line in handle if line.strip()]
        if not keys:
            raise ValueError(f"No VirusTotal API keys found in {path}.")
        return keys

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
        self.inspect_existing_format()
        logging.info("Starting scanner loop on %s.%s", self.mongo_db_name, self.mongo_collection_name)

        while True:
            try:
                did_work = False
                if self.process_pending_t7_scrape():
                    did_work = True

                finalized_count, polled_count, pending_count = (
                    self.process_pending_virustotal_results()
                )
                if finalized_count > 0 or polled_count > 0:
                    did_work = True

                current_pending_count = max(pending_count - finalized_count, 0)
                submitted_count = self.fill_virustotal_submission_queue(current_pending_count)
                if submitted_count > 0:
                    did_work = True

                if current_pending_count == 0 and submitted_count == 0:
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

    def process_pending_t7_scrape(self) -> bool:
        doc = self.collection.find_one(
            {
                "task.url": {"$type": "string", "$ne": ""},
                "scans.T7.change_detection.significant": True,
                "$or": [
                    {"scans.T7.scrape": {"$exists": False}},
                    {"scans.T7.scrape.status": {"$ne": "success"}},
                ],
            },
            sort=[("scans.T7.completed_at", ASCENDING)],
        )
        if not doc:
            return False

        url = doc["task"]["url"]
        logging.info("Retrying pending T7 scrape for %s", url)
        scrape = self.scrape_url(
            url=url,
            reason="retry_pending_significant_change",
            previous_scrape=doc.get("scans", {}).get("T7", {}).get("scrape"),
        )
        self.update_document(
            doc["_id"],
            {
                "$set": {
                    "scans.T7.scrape": scrape,
                    "scans.last_updated_at": utcnow(),
                }
            },
        )
        return True

    def count_pending_virustotal_documents(self) -> int:
        return self.collection.count_documents(
            {
                "$or": [
                    {"scans.T0_pending": {"$exists": True}},
                    {"scans.T7_pending": {"$exists": True}},
                ]
            }
        )

    def list_pending_virustotal_entries(self) -> list[dict[str, Any]]:
        docs = list(
            self.collection.find(
                {
                    "$or": [
                        {"scans.T0_pending": {"$exists": True}},
                        {"scans.T7_pending": {"$exists": True}},
                    ]
                },
                {
                    "task.url": 1,
                    "scans.T0": 1,
                    "scans.T0_pending": 1,
                    "scans.T7_pending": 1,
                },
            )
        )
        entries: list[dict[str, Any]] = []
        for doc in docs:
            scans = doc.get("scans") or {}
            for stage in ("T7", "T0"):
                pending = scans.get(f"{stage}_pending")
                if not isinstance(pending, dict):
                    continue
                submitted_at = pending.get("submitted_at")
                if not isinstance(submitted_at, datetime):
                    submitted_at = utcnow()
                entries.append(
                    {
                        "document_id": doc["_id"],
                        "document": doc,
                        "stage": stage,
                        "url": pending.get("requested_url")
                        or doc.get("task", {}).get("url"),
                        "pending": pending,
                        "submitted_at": submitted_at,
                        "last_polled_at": pending.get("last_polled_at"),
                    }
                )

        entries.sort(
            key=lambda entry: (
                entry["submitted_at"],
                0 if entry["stage"] == "T7" else 1,
            )
        )
        return entries

    def process_pending_virustotal_results(self) -> tuple[int, int, int]:
        pending_entries = self.list_pending_virustotal_entries()
        pending_count = len(pending_entries)
        if pending_count == 0:
            return 0, 0, 0

        now = utcnow()
        settle_cutoff = now - timedelta(seconds=self.vt_batch_settle_seconds)
        poll_cutoff = now - timedelta(seconds=self.vt_batch_poll_interval_seconds)
        ready_entries: list[dict[str, Any]] = []

        for entry in pending_entries:
            if entry["submitted_at"] > settle_cutoff:
                continue
            last_polled_at = entry["last_polled_at"]
            if isinstance(last_polled_at, datetime) and last_polled_at > poll_cutoff:
                continue
            ready_entries.append(entry)
            if len(ready_entries) >= self.vt_collect_batch_size:
                break

        finalized_count = 0
        polled_count = 0
        for entry in ready_entries:
            analysis_id = entry["pending"]["analysis_id"]
            try:
                analysis = self.fetch_virustotal_analysis(analysis_id)
            except Exception:
                logging.exception(
                    "Failed to collect VirusTotal analysis %s for %s",
                    analysis_id,
                    entry["url"],
                )
                continue

            status = (
                analysis.get("data", {})
                .get("attributes", {})
                .get("status")
            )
            if status == "completed":
                self.finalize_pending_virustotal_result(entry, analysis)
                finalized_count += 1
            else:
                self.mark_pending_virustotal_polled(entry)
                polled_count += 1

        return finalized_count, polled_count, pending_count

    def fill_virustotal_submission_queue(self, known_pending_count: int | None = None) -> int:
        pending_count = (
            self.count_pending_virustotal_documents()
            if known_pending_count is None
            else known_pending_count
        )
        available_slots = max(self.vt_pending_target - pending_count, 0)
        if available_slots == 0:
            return 0

        submitted_count = 0

        t7_candidates = self.find_due_t7_candidates(min(self.vt_batch_size, available_slots))
        submitted_count += self.submit_candidate_documents("T7", t7_candidates)
        available_slots = max(available_slots - submitted_count, 0)

        if available_slots > 0:
            t0_candidates = self.find_missing_t0_candidates(
                min(self.vt_batch_size, available_slots)
            )
            submitted_count += self.submit_candidate_documents("T0", t0_candidates)

        return submitted_count

    def find_due_t7_candidates(self, limit: int) -> list[dict[str, Any]]:
        now = utcnow()
        return list(
            self.collection.find(
                {
                    "task.url": {"$type": "string", "$ne": ""},
                    "scans.T0.completed_at": {"$exists": True},
                    "scans.T7": {"$exists": False},
                    "scans.T7_pending": {"$exists": False},
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
                    ],
                },
                sort=[("scans.T0.completed_at", ASCENDING)],
                limit=limit,
            )
        )

    def find_missing_t0_candidates(self, limit: int) -> list[dict[str, Any]]:
        return list(
            self.collection.find(
                {
                    "task.url": {"$type": "string", "$ne": ""},
                    "scans.T0": {"$exists": False},
                    "scans.T0_pending": {"$exists": False},
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

        logging.info("Submitting %s VirusTotal %s scans", len(docs), stage)
        submitted_count = 0
        for doc in docs:
            url = doc["task"]["url"]
            try:
                submission = self.submit_virustotal_scan(url)
                pending_payload = {
                    "requested_url": url,
                    "submitted_at": submission["submitted_at"],
                    "analysis_id": submission["analysis_id"],
                    "submission": submission["submission_payload"],
                    "last_polled_at": None,
                    "poll_count": 0,
                }
                result = self.collection.update_one(
                    {
                        "_id": doc["_id"],
                        f"scans.{stage}": {"$exists": False},
                        f"scans.{stage}_pending": {"$exists": False},
                    },
                    {
                        "$set": {
                            f"scans.{stage}_pending": pending_payload,
                            "scans.last_updated_at": utcnow(),
                        }
                    },
                )
                if result.matched_count != 1:
                    logging.warning(
                        "Skipped recording pending %s submission for %s because the document changed.",
                        stage,
                        url,
                    )
                    continue
                submitted_count += 1
            except Exception:
                logging.exception(
                    "Failed to submit VirusTotal %s scan for %s (%s)",
                    stage,
                    url,
                    doc["_id"],
                )

        return submitted_count

    def mark_pending_virustotal_polled(self, entry: dict[str, Any]) -> None:
        stage = entry["stage"]
        pending = entry["pending"]
        poll_count = int(pending.get("poll_count", 0) or 0) + 1
        self.update_document(
            entry["document_id"],
            {
                "$set": {
                    f"scans.{stage}_pending.last_polled_at": utcnow(),
                    f"scans.{stage}_pending.poll_count": poll_count,
                    "scans.last_updated_at": utcnow(),
                }
            },
        )

    def finalize_pending_virustotal_result(
        self, entry: dict[str, Any], analysis: dict[str, Any]
    ) -> None:
        stage = entry["stage"]
        pending = entry["pending"]
        vt_result = self.build_virustotal_result(pending=pending, analysis=analysis)
        scan = self.build_scan_snapshot(
            url=entry["url"],
            started_at=entry["submitted_at"],
            vt=vt_result,
        )

        if stage == "T0":
            scan["next_scan_due_at"] = scan["completed_at"] + timedelta(days=self.t7_days)
        else:
            baseline = entry["document"].get("scans", {}).get("T0") or {}
            change_detection = self.evaluate_significant_change(baseline, scan)
            scan["change_detection"] = change_detection
            if change_detection["significant"]:
                scan["scrape"] = self.scrape_url(
                    url=entry["url"],
                    reason=", ".join(change_detection["reasons"]),
                )
            else:
                scan["scrape"] = {
                    "triggered": False,
                    "status": "skipped",
                    "reason": "no_significant_change",
                    "reasons": change_detection["reasons"],
                    "checked_at": utcnow(),
                }

        self.write_scan(entry["document_id"], stage, scan, clear_pending=True)

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
        clear_pending: bool = False,
    ) -> None:
        update = {
            "$set": {
                f"scans.{stage}": scan,
                "scans.last_updated_at": utcnow(),
            }
        }
        if clear_pending:
            update["$unset"] = {f"scans.{stage}_pending": ""}
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

    def build_scan_snapshot(
        self, *, url: str, started_at: datetime, vt: dict[str, Any]
    ) -> dict[str, Any]:
        gsb = self.check_google_safe_browsing(url)
        completed_at = utcnow()
        return {
            "requested_url": url,
            "started_at": started_at,
            "completed_at": completed_at,
            "virustotal": vt,
            "google_safe_browsing": gsb,
        }

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
        for attempt in range(6):
            key = self.vt_pool.acquire()
            headers = dict(kwargs.pop("headers", {}))
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

            if response.status_code in expected_statuses:
                return safe_json(response)

            payload = safe_json(response)
            if is_retryable_status(response.status_code):
                if response.status_code == 429:
                    cooldown_seconds = parse_retry_after_seconds(
                        response.headers.get("Retry-After"),
                        float(self.vt_rate_limit_cooldown_seconds),
                    )
                    self.vt_pool.mark_rate_limited(key, cooldown_seconds)
                    sleep_for = cooldown_seconds
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
                response = self.session.post(
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
