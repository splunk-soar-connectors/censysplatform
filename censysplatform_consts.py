# File: censysplatform_consts.py
#
# Copyright (c) 2025-2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

# API endpoints
CENSYSPLATFORM_DEFAULT_BASE_URL = "https://api.platform.censys.io"
CENSYSPLATFORM_DEFAULT_UI_URL = "https://platform.censys.io"
CENSYSPLATFORM_CENS_EYE_DEFAULT_PAGE_SIZE = 100
CENSYSPLATFORM_CENS_EYE_DEFAULT_WAIT_TIMEOUT_SECONDS = 300

# Action identifiers
ACTION_ID_TEST_CONNECTIVITY = "test_connectivity"
ACTION_ID_LOOKUP_HOST = "lookup_host"
ACTION_ID_LOOKUP_HOST_ENRICHMENT = "lookup_host_enrichment"
ACTION_ID_LOOKUP_CERT = "lookup_cert"
ACTION_ID_LOOKUP_WEB_PROPERTY = "lookup_web_property"
ACTION_ID_SEARCH = "search"
ACTION_ID_GET_HOST_EVENT_HISTORY = "get_host_event_history"
ACTION_ID_GET_HOST_SERVICE_HISTORY = "get_host_service_history"
ACTION_ID_FIND_RELATED_INFRASTRUCTURE = "find_related_infrastructure"
ACTION_ID_LIVE_RESCAN = "live_rescan"

# Error messages
CENSYSPLATFORM_ERR_CONNECTIVITY_TEST = "Test Connectivity Failed"

# Success messages
CENSYSPLATFORM_SUCC_CONNECTIVITY_TEST = "Test Connectivity Passed"
