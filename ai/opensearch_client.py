"""
opensearch_client.py
Responsible only for communicating with OpenSearch to retrieve live/historical
Wazuh alerts. Administrative/auth operations against the Wazuh Manager itself
live in wazuh_api.py — see architecture note in README.
"""

import os

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INDEXER_URL = os.getenv("OPENSEARCH_URL", "https://127.0.0.1:9200")
USERNAME = os.getenv("OPENSEARCH_USER", "admin")
# Demo default kept so the app runs with zero setup on your VM. Override via
# env var (or .streamlit/secrets.toml) before this repo is ever made public,
# and rotate this password at that point — see USING_DEFAULT_CREDS below.
_DEMO_DEFAULT_PASSWORD = "AlertMind2026*"
PASSWORD = os.getenv("OPENSEARCH_PASSWORD", _DEMO_DEFAULT_PASSWORD)
USING_DEFAULT_CREDS = "OPENSEARCH_PASSWORD" not in os.environ
VERIFY_SSL = os.getenv("OPENSEARCH_VERIFY_SSL", "false").lower() == "true"
INDEX_PATTERN = os.getenv("OPENSEARCH_INDEX", "wazuh-alerts-*")
REQUEST_TIMEOUT = 5  # short timeout so the UI fails fast if OpenSearch is unreachable

# Shared across instances so accidentally creating multiple OpenSearchClient()
# objects doesn't also spin up multiple underlying connection pools.
_session = requests.Session()


class OpenSearchError(Exception):
    """Raised when OpenSearch is unreachable, misconfigured, or returns an error."""


class OpenSearchClient:
    def __init__(self):
        self.auth = (USERNAME, PASSWORD)
        self.session = _session

    def is_reachable(self) -> bool:
        """Cheap health check for the sidebar status indicator."""
        try:
            resp = self.session.get(
                f"{INDEXER_URL}/_cluster/health", auth=self.auth, verify=VERIFY_SSL, timeout=REQUEST_TIMEOUT
            )
            return resp.status_code == 200
        except requests.RequestException:
            return False

    def get_latest_alerts(self, size: int = 20) -> list:
        """Return the most recent `size` Wazuh alerts as a list of dicts."""
        query = {"size": size, "sort": [{"@timestamp": {"order": "desc"}}]}
        try:
            response = self.session.get(
                f"{INDEXER_URL}/{INDEX_PATTERN}/_search",
                auth=self.auth,
                verify=VERIFY_SSL,
                json=query,
                headers={"Content-Type": "application/json"},
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
        except requests.RequestException as e:
            raise OpenSearchError(f"Failed to reach OpenSearch at {INDEXER_URL}: {e}") from e

        hits = response.json().get("hits", {}).get("hits", [])
        # Defensive: skip any malformed hit rather than KeyError-ing the whole page.
        return [hit["_source"] for hit in hits if isinstance(hit, dict) and "_source" in hit]

    def get_latest_alert(self):
        """Convenience wrapper for the common case: just the single newest alert."""
        alerts = self.get_latest_alerts(size=1)
        return alerts[0] if alerts else None
