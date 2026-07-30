"""
wazuh_api.py
Handles authentication and administrative queries against the Wazuh Manager
REST API only: JWT auth, manager info, cluster status, agent status.

Deliberately does NOT retrieve alerts — every Wazuh alert is indexed into
OpenSearch, and live/historical alert retrieval lives in opensearch_client.py.
This split mirrors how Wazuh itself separates the manager API (management/
administration) from the indexer (search/analytics).
"""

import os
import time

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WAZUH_URL = os.getenv("WAZUH_API_URL", "https://127.0.0.1:55000")
USERNAME = os.getenv("WAZUH_API_USER", "wazuh-wui")
# Demo default kept so the app runs with zero setup on your VM. This is
# Wazuh's own published default password — fine for a local, private-repo
# lab demo, but override via env var and rotate it before the repo is public.
PASSWORD = os.getenv("WAZUH_API_PASSWORD", "wazuh-wui")
USING_DEFAULT_CREDS = "WAZUH_API_PASSWORD" not in os.environ
VERIFY_SSL = os.getenv("WAZUH_VERIFY_SSL", "false").lower() == "true"
REQUEST_TIMEOUT = 10
TOKEN_TTL_SECONDS = 800  # Wazuh JWTs default to 900s; refresh a little early


class WazuhAPIError(Exception):
    """Raised when the Wazuh API is unreachable, misconfigured, or returns an error."""


class WazuhAPI:
    def __init__(self):
        self.token = None
        self.token_issued_at = None
        self.session = requests.Session()

    def login(self) -> str:
        try:
            response = self.session.post(
                f"{WAZUH_URL}/security/user/authenticate",
                auth=(USERNAME, PASSWORD),
                verify=VERIFY_SSL,
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
        except requests.RequestException as e:
            raise WazuhAPIError(f"Wazuh authentication failed: {e}") from e

        try:
            self.token = response.json()["data"]["token"]
        except (ValueError, KeyError, TypeError) as e:
            raise WazuhAPIError(
                f"Wazuh authenticated but returned an unexpected response shape: {e}. "
                "Check that WAZUH_API_URL points at the Manager API, not the indexer."
            ) from e

        self.token_issued_at = time.time()
        return self.token

    def _headers(self) -> dict:
        token_stale = self.token is None or (time.time() - (self.token_issued_at or 0)) > TOKEN_TTL_SECONDS
        if token_stale:
            self.login()
        return {"Authorization": f"Bearer {self.token}"}

    def _get(self, path: str, params: dict = None) -> dict:
        try:
            response = self.session.get(
                f"{WAZUH_URL}{path}", headers=self._headers(), params=params, verify=VERIFY_SSL, timeout=REQUEST_TIMEOUT
            )
            if response.status_code == 401:
                # Token expired mid-flight (e.g. manager clock skew) — refresh once and retry.
                self.login()
                response = self.session.get(
                    f"{WAZUH_URL}{path}", headers=self._headers(), params=params, verify=VERIFY_SSL, timeout=REQUEST_TIMEOUT
                )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            raise WazuhAPIError(f"Wazuh API request to {path} failed: {e}") from e

    def get_manager_info(self) -> dict:
        return self._get("/manager/info")

    def get_cluster_status(self) -> dict:
        return self._get("/cluster/status")

    def get_agents_summary(self) -> dict:
        return self._get("/agents/summary/status")
