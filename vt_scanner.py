#!/usr/bin/env python3
"""
VirusTotal URL Scanner

Continuously scans URLs from MongoDB using the VirusTotal API.
Processes URLs in batches, handles rate limiting with exponential backoff,
and rotates between multiple API keys.
"""

import os
import sys
import time
import logging
from typing import Optional
from datetime import datetime, timezone

import requests
from pymongo import MongoClient
from pymongo.collection import Collection
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

# Constants
BATCH_SIZE = 100
SCAN_DELAY_SECONDS = 3.2
POLL_INTERVAL_SECONDS = 30
VT_API_BASE_URL = "https://www.virustotal.com/api/v3"
URLSCAN_API_BASE_URL = "https://urlscan.io/api/v1"
MAX_BACKOFF_SECONDS = 300  # 5 minutes max backoff
INITIAL_BACKOFF_SECONDS = 10
URLSCAN_POLL_DELAY_SECONDS = 10  # Time to wait before fetching urlscan results
URLSCAN_MAX_RETRIES = 3  # Max retries for fetching urlscan results


class APIKeyManager:
    """Manages VirusTotal API key rotation."""

    def __init__(self, keys_file: str):
        self.keys = self._load_keys(keys_file)
        if not self.keys:
            raise ValueError(f"No API keys found in {keys_file}")
        self.current_index = 0
        self.backoff_until: dict[str, float] = {}  # key -> timestamp when backoff ends
        logger.info(f"Loaded {len(self.keys)} API keys")

    def _load_keys(self, keys_file: str) -> list[str]:
        """Load API keys from file."""
        try:
            with open(keys_file, "r") as f:
                keys = [line.strip() for line in f if line.strip()]
            return keys
        except FileNotFoundError:
            logger.error(f"API keys file not found: {keys_file}")
            raise

    def get_key(self) -> Optional[str]:
        """Get an available API key, considering backoff periods."""
        now = time.time()
        attempts = 0

        while attempts < len(self.keys):
            key = self.keys[self.current_index]
            backoff_end = self.backoff_until.get(key, 0)

            if now >= backoff_end:
                return key

            # Try next key
            self.current_index = (self.current_index + 1) % len(self.keys)
            attempts += 1

        # All keys are in backoff, find the one with shortest wait
        min_wait_key = min(self.keys, key=lambda k: self.backoff_until.get(k, 0))
        wait_time = self.backoff_until[min_wait_key] - now
        if wait_time > 0:
            logger.warning(f"All API keys rate-limited. Waiting {wait_time:.1f}s")
            time.sleep(wait_time)
        return min_wait_key

    def rotate(self):
        """Rotate to the next API key."""
        self.current_index = (self.current_index + 1) % len(self.keys)
        logger.debug(f"Rotated to API key index {self.current_index}")

    def mark_rate_limited(self, key: str, backoff_seconds: float):
        """Mark a key as rate-limited with exponential backoff."""
        current_backoff = self.backoff_until.get(key, 0)
        now = time.time()

        if current_backoff > now:
            # Already in backoff, increase it
            remaining = current_backoff - now
            new_backoff = min(remaining * 2, MAX_BACKOFF_SECONDS)
        else:
            new_backoff = backoff_seconds

        self.backoff_until[key] = now + new_backoff
        logger.warning(f"API key rate-limited. Backoff for {new_backoff:.1f}s")
        self.rotate()


class VirusTotalScanner:
    """Handles VirusTotal API interactions."""

    def __init__(self, key_manager: APIKeyManager):
        self.key_manager = key_manager
        self.session = requests.Session()

    def _make_request(
        self, method: str, endpoint: str, **kwargs
    ) -> Optional[requests.Response]:
        """Make an API request with retry and backoff logic."""
        url = f"{VT_API_BASE_URL}/{endpoint}"
        max_retries = len(self.key_manager.keys) * 2

        for attempt in range(max_retries):
            api_key = self.key_manager.get_key()
            if not api_key:
                logger.error("No API key available")
                return None

            headers = kwargs.pop("headers", {})
            headers["x-apikey"] = api_key

            try:
                response = self.session.request(method, url, headers=headers, **kwargs)

                if response.status_code == 429:
                    # Rate limited
                    self.key_manager.mark_rate_limited(api_key, INITIAL_BACKOFF_SECONDS)
                    continue

                return response

            except requests.RequestException as e:
                logger.error(f"Request error: {e}")
                time.sleep(INITIAL_BACKOFF_SECONDS)

        logger.error(f"Failed after {max_retries} attempts")
        return None

    def submit_url(self, url: str) -> dict:
        """Submit a URL for scanning."""
        response = self._make_request("POST", "urls", data={"url": url})

        if response is None:
            return {"error": "Failed to submit URL - no response"}

        if response.status_code == 200:
            data = response.json()
            analysis_id = data.get("data", {}).get("id")
            if analysis_id:
                return {"analysis_id": analysis_id, "status": "submitted"}
            return {"error": "No analysis ID in response", "response": data}

        return {
            "error": f"Submit failed with status {response.status_code}",
            "details": response.text[:500],
        }

    def get_analysis(self, analysis_id: str) -> dict:
        """Get analysis results for a submitted URL."""
        response = self._make_request("GET", f"analyses/{analysis_id}")

        if response is None:
            return {"error": "Failed to get analysis - no response"}

        if response.status_code == 200:
            return response.json()

        return {
            "error": f"Analysis fetch failed with status {response.status_code}",
            "details": response.text[:500],
        }


def fetch_urlscan_results(
    result_url: str, session: requests.Session, api_key: Optional[str] = None
) -> dict:
    """Fetch scan results from urlscan.io result URL."""
    headers = {}
    if api_key:
        headers["x-api-key"] = api_key

    for attempt in range(URLSCAN_MAX_RETRIES):
        try:
            response = session.get(result_url, headers=headers)

            if response.status_code == 200:
                return response.json()

            if response.status_code == 404:
                return {"error": "Results not available."}

            return {
                "error": f"Fetch failed with status {response.status_code}",
                "details": response.text[:500],
            }

        except requests.RequestException as e:
            return {"error": f"Request error: {e}"}

    return {"error": "Max retries exceeded"}


class MongoDBHandler:
    """Handles MongoDB operations."""

    def __init__(self, uri: str):
        self.client = MongoClient(uri)
        self.db = self.client["urlscan"]
        self.collection: Collection = self.db["live"]
        logger.info("Connected to MongoDB")

    def get_unscanned_urls(self, limit: int = BATCH_SIZE) -> list[dict]:
        """Get URLs that haven't been scanned yet."""
        cursor = self.collection.find(
            {"vtresults": {"$exists": False}, "page.url": {"$exists": True}},
            {"_id": 1, "page.url": 1, "result": 1},
        ).limit(limit)
        return list(cursor)

    def update_document(self, doc_id, vtresults: dict, urlscanresults: dict = None):
        """Update a document with VirusTotal and urlscan.io results."""
        update_data = {
            "vtresults": vtresults,
            "vtresults_updated_at": datetime.now(timezone.utc),
        }
        if urlscanresults is not None:
            update_data["urlscanresults"] = urlscanresults
            update_data["urlscanresults_updated_at"] = datetime.now(timezone.utc)
        self.collection.update_one(
            {"_id": doc_id},
            {"$set": update_data},
        )

    def mark_error(self, doc_id, error: str):
        """Mark a document with an error."""
        self.collection.update_one(
            {"_id": doc_id},
            {
                "$set": {
                    "vtresults": {"error": error},
                    "vtresults_updated_at": datetime.now(timezone.utc),
                }
            },
        )

    def close(self):
        """Close the MongoDB connection."""
        self.client.close()


def process_batch(
    documents: list[dict],
    scanner: VirusTotalScanner,
    db: MongoDBHandler,
    urlscan_api_key: Optional[str] = None,
) -> int:
    """Process a batch of documents."""
    processed = 0
    submissions = []
    http_session = requests.Session()

    # Submit all URLs in the batch
    for doc in documents:
        doc_id = doc["_id"]
        url = doc.get("page", {}).get("url")
        urlscan_result_url = doc.get("result")

        if not url:
            db.mark_error(doc_id, "No URL found in document")
            continue

        logger.info(f"Submitting URL: {url[:80]}...")
        result = scanner.submit_url(url)

        if "error" in result:
            db.mark_error(doc_id, result["error"])
            logger.error(f"Submit error for {url[:50]}: {result['error']}")
        else:
            submissions.append(
                {
                    "doc_id": doc_id,
                    "url": url,
                    "analysis_id": result["analysis_id"],
                    "urlscan_result_url": urlscan_result_url,
                }
            )

        # Wait between submissions
        time.sleep(SCAN_DELAY_SECONDS)

    # Retrieve results for successful submissions
    for submission in submissions:
        doc_id = submission["doc_id"]
        url = submission["url"]
        analysis_id = submission["analysis_id"]
        urlscan_result_url = submission["urlscan_result_url"]

        logger.info(f"Fetching results for: {url[:80]}...")
        analysis = scanner.get_analysis(analysis_id)

        # Fetch urlscan.io results if result URL exists
        urlscan_results = None
        if urlscan_result_url:
            logger.info(f"Fetching urlscan.io results from: {urlscan_result_url[:80]}...")
            urlscan_results = fetch_urlscan_results(urlscan_result_url, http_session, urlscan_api_key)
            if "error" in urlscan_results:
                logger.warning(f"urlscan.io error for {url[:50]}: {urlscan_results['error']}")

        if "error" in analysis:
            db.mark_error(doc_id, analysis["error"])
            logger.error(f"Analysis error for {url[:50]}: {analysis['error']}")
        else:
            db.update_document(doc_id, analysis, urlscan_results)
            processed += 1
            logger.info(f"Saved results for: {url[:80]}")

        time.sleep(SCAN_DELAY_SECONDS)

    return processed


def main():
    """Main entry point."""
    load_dotenv()

    # Get configuration from environment
    mongo_uri = os.getenv("MONGO_URI")
    if not mongo_uri:
        logger.error("MONGO_URI environment variable not set")
        sys.exit(1)

    keys_file = os.getenv("VT_KEYS_FILE", "VTAPIKEYS.txt")
    urlscan_api_key = os.getenv("URLSCAN_API_KEY")

    logger.info("Starting VirusTotal Scanner")
    if urlscan_api_key:
        logger.info("urlscan.io API key loaded")

    # Initialize components
    try:
        key_manager = APIKeyManager(keys_file)
        scanner = VirusTotalScanner(key_manager)
        db = MongoDBHandler(mongo_uri)
    except Exception as e:
        logger.error(f"Initialization failed: {e}")
        sys.exit(1)

    total_processed = 0

    try:
        while True:
            # Fetch batch of unscanned URLs
            documents = db.get_unscanned_urls(BATCH_SIZE)

            if not documents:
                logger.info(
                    f"No unscanned URLs found. Waiting {POLL_INTERVAL_SECONDS}s..."
                )
                time.sleep(POLL_INTERVAL_SECONDS)
                continue

            logger.info(f"Processing batch of {len(documents)} URLs")
            processed = process_batch(documents, scanner, db, urlscan_api_key)
            total_processed += processed
            logger.info(
                f"Batch complete. Processed: {processed}, Total: {total_processed}"
            )

    except KeyboardInterrupt:
        logger.info("Shutdown requested")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise
    finally:
        db.close()
        logger.info(f"Scanner stopped. Total URLs processed: {total_processed}")


if __name__ == "__main__":
    main()
