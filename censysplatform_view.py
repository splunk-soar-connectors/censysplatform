# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Custom render views for Censys SOAR action widgets."""

from __future__ import annotations

from typing import Any


SEARCH_WIDGET_MAX_HITS = 50


def _safe_get(d: dict[str, Any], dotpath: str, default: Any = None) -> Any:
    """Nested dict access via dot-separated path."""
    current: Any = d
    for key in dotpath.split("."):
        if not isinstance(current, dict):
            return default
        current = current.get(key, default)
    return current


def _ensure_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    return []


def _to_display_string(value: Any, preferred_keys: tuple[str, ...] = ()) -> str | None:
    """Normalize mixed scalar/dict values into widget-friendly strings."""
    if value is None:
        return None

    if isinstance(value, dict):
        for key in preferred_keys:
            candidate = value.get(key)
            if candidate is None or isinstance(candidate, (dict, list)):
                continue
            return str(candidate)

        for key in ("value", "name", "id", "cve_id", "cidr"):
            if key in preferred_keys:
                continue
            candidate = value.get(key)
            if candidate is None or isinstance(candidate, (dict, list)):
                continue
            return str(candidate)

        return None

    if isinstance(value, (list, tuple, set)):
        return None

    return str(value)


def _normalize_display_list(values: Any, preferred_keys: tuple[str, ...] = ()) -> list[str]:
    """Return displayable string values preserving input order."""
    normalized: list[str] = []
    for item in _ensure_list(values):
        display_value = _to_display_string(item, preferred_keys)
        if display_value is None:
            continue
        normalized.append(display_value)
    return normalized


def _flags_from_list(items: Any, keys: tuple[str, ...]) -> dict[str, bool | None]:
    """Collapse a list of classification dicts into host-level boolean flags.

    A key absent from every row means the source never made a claim either way, and is
    reported as None so the widget can distinguish "not asserted" from an asserted False.
    """
    rows = [item for item in _ensure_list(items) if isinstance(item, dict)]
    flags: dict[str, bool | None] = {}
    for key in keys:
        asserted = [row.get(key) for row in rows if row.get(key) is not None]
        flags[key] = any(bool(value) for value in asserted) if asserted else None
    return flags


def _reputation_level(host: dict[str, Any]) -> Any:
    """Reputation verdict, which responses carry as either `score_level` or `label`."""
    return _safe_get(host, "reputation.score_level") or _safe_get(host, "reputation.label")


def _score_display(value: Any) -> Any:
    """Scale the 0-1 reputation score to a whole number for display, truncating the remainder.

    The raw decimal stays in `action_result.data`; only the widget cell is scaled, so 0.647
    reads as 64. Anything non-numeric passes through untouched.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return value
    return int(value * 100)


def _reputation_label_display(host: dict[str, Any]) -> str:
    """Render the reputation verdict on its own, separate from the score."""
    score_level = _reputation_level(host)
    return str(score_level) if score_level else "Unknown"


def _reputation_score_display(host: dict[str, Any]) -> str:
    """Render the reputation score on its own. A score of 0 is meaningful, so test for None."""
    score = _safe_get(host, "reputation.score")
    if score is None:
        return "Not reported"
    # A suppressed score is still reported, so say so rather than presenting it as a verdict.
    suffix = " (suppressed)" if _safe_get(host, "reputation.score_suppressed") else ""
    return f"{_score_display(score)}{suffix}"


def _build_reputation(host: dict[str, Any]) -> dict[str, Any]:
    """Reputation fields for the widget: raw values for playbooks, display strings for cells."""
    return {
        "score": _safe_get(host, "reputation.score"),
        "score_level": _reputation_level(host),
        "model_version": _safe_get(host, "reputation.model_version"),
        "score_suppressed": _safe_get(host, "reputation.score_suppressed"),
        "label_display": _reputation_label_display(host),
        "score_display": _reputation_score_display(host),
    }


def _round_display(value: Any, places: int = 2) -> Any:
    """Shorten a float for display, leaving anything non-numeric untouched."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return value
    return round(value, places)


def _reputation_evidence_rows(host: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten reputation evidence into rows, preserving the API's contribution ordering.

    An entry scores one model feature under `feature`, and may also carry the aggregate
    `category`/`evidence_score` pair alongside it. Whichever the response populates
    collapses into a single row, feature values taking precedence.

    An entry's `threats`, `external_signals`, and `additional_fields` are not rendered; they
    remain in `action_result.data` for playbooks.
    """
    rows = []
    for entry in _ensure_list(_safe_get(host, "reputation.evidence")):
        if not isinstance(entry, dict):
            continue

        feature = entry.get("feature") if isinstance(entry.get("feature"), dict) else {}
        contribution = feature.get("contribution")
        if contribution is None:
            contribution = entry.get("evidence_score")

        row = {
            "name": feature.get("name") or feature.get("id"),
            "value": _to_display_string(feature.get("value")),
            "contribution": _round_display(contribution),
            "category": feature.get("category") or entry.get("category"),
        }
        if all(field is None for field in row.values()):
            continue
        rows.append(row)
    return rows


def _forward_dns_names(host: dict[str, Any]) -> list[str]:
    """Collect names from dns.forward_dns, which is a map keyed by hostname."""
    forward_dns = _safe_get(host, "dns.forward_dns")
    if not isinstance(forward_dns, dict):
        return []

    names = []
    for key, resolution in forward_dns.items():
        name = resolution.get("name") if isinstance(resolution, dict) else None
        display_name = _to_display_string(name if name is not None else key)
        if display_name is not None:
            names.append(display_name)
    return names


def _iter_action_results(all_app_runs: Any):
    """Yield action result objects from SOAR all_app_runs safely."""
    if all_app_runs is None:
        return

    try:
        iterator = iter(all_app_runs)
    except TypeError:
        return

    for app_run in iterator:
        action_results = None

        if isinstance(app_run, dict):
            action_results = app_run.get("action_results")
            if action_results is None:
                action_results = app_run.get("results")
        else:
            try:
                _summary, action_results = app_run
            except Exception:
                continue

        if action_results is None:
            continue

        if isinstance(action_results, (list, tuple)):
            yield from action_results
        else:
            yield action_results


def _first_data_dict(result: Any) -> dict[str, Any] | None:
    """Return first action_result.data object if it is a dict."""
    if result is None or not hasattr(result, "get_data"):
        return None
    try:
        data = result.get_data()
    except Exception:
        return None
    if isinstance(data, list) and data and isinstance(data[0], dict):
        return data[0]
    return None


def _extract_cert_fields(cert: dict[str, Any]) -> dict[str, Any]:
    """Extract cert fields from canonical Censys cert schema."""
    parsed = cert.get("parsed", {})
    common_names = _normalize_display_list(_safe_get(parsed, "subject.common_name", []), ("name", "value"))

    return {
        "fingerprint_sha256": cert.get("fingerprint_sha256"),
        "subject_dn": _safe_get(parsed, "subject_dn"),
        "issuer_dn": _safe_get(parsed, "issuer_dn"),
        "common_names": common_names,
        "valid_from": _safe_get(parsed, "validity_period.not_before"),
        "valid_to": _safe_get(parsed, "validity_period.not_after"),
        "self_signed": _safe_get(parsed, "signature.self_signed"),
    }


def _build_host_result(host: dict[str, Any], services: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    services = _ensure_list(services if services is not None else host.get("services"))

    service_rows = []
    service_labels = []
    service_threat_names = []
    service_vulns = []
    service_scan_times = []

    for svc in services:
        if not isinstance(svc, dict):
            continue

        service_rows.append(
            {
                "port": svc.get("port"),
                "protocol": svc.get("protocol"),
                "transport_protocol": svc.get("transport_protocol"),
                "scan_time": svc.get("scan_time"),
                "labels": _normalize_display_list(svc.get("labels"), ("value", "name", "label")),
                "threat_names": _normalize_display_list(svc.get("threats"), ("name", "value", "id")),
                "vulns": _normalize_display_list(svc.get("vulns"), ("id", "name", "cve_id")),
            }
        )

        if svc.get("scan_time") is not None:
            service_scan_times.append(str(svc.get("scan_time")))

        service_labels.extend(_normalize_display_list(svc.get("labels"), ("value", "name", "label")))
        service_threat_names.extend(_normalize_display_list(svc.get("threats"), ("name", "value", "id")))
        service_vulns.extend(_normalize_display_list(svc.get("vulns"), ("id", "name", "cve_id")))

    host_labels = _normalize_display_list(host.get("labels"), ("value", "name", "label"))
    dns_names = _normalize_display_list(_safe_get(host, "dns.names", []), ("name", "value"))

    forward_dns_names = _forward_dns_names(host)

    reverse_dns_names = _normalize_display_list(_safe_get(host, "dns.reverse_dns.names", []), ("name", "value"))

    location = host.get("location") if isinstance(host.get("location"), dict) else {}
    coordinates = location.get("coordinates") if isinstance(location.get("coordinates"), dict) else {}

    return {
        "ip": host.get("ip"),
        "service_count": host.get("service_count"),
        "services": service_rows,
        "service_scan_times": service_scan_times,
        "host_labels": host_labels,
        "service_labels": service_labels,
        "service_threat_names": service_threat_names,
        "service_vulns": service_vulns,
        "reputation": _build_reputation(host),
        "dns_names": dns_names,
        "forward_dns_names": forward_dns_names,
        "reverse_dns_names": reverse_dns_names,
        "whois_network_name": _safe_get(host, "whois.network.name"),
        "whois_network_cidrs": _normalize_display_list(
            _safe_get(host, "whois.network.cidrs", []),
            ("cidr", "value", "name", "id"),
        ),
        "autonomous_system_name": _safe_get(host, "autonomous_system.name"),
        "autonomous_system_asn": _safe_get(host, "autonomous_system.asn"),
        "location": {
            "city": location.get("city"),
            "province": location.get("province"),
            "postal_code": location.get("postal_code"),
            "country": location.get("country"),
            "country_code": location.get("country_code"),
            "continent": location.get("continent"),
            "latitude": coordinates.get("latitude"),
            "longitude": coordinates.get("longitude"),
        },
    }


def _build_host_enrichment_result(host: dict[str, Any], services: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    services = _ensure_list(services if services is not None else host.get("services"))

    service_rows = []
    service_labels = []
    service_threat_names = []
    service_scan_times = []

    for svc in services:
        if not isinstance(svc, dict):
            continue

        service_rows.append(
            {
                "port": svc.get("port"),
                "protocol": svc.get("protocol"),
                "scan_time": svc.get("scan_time"),
                "labels": _normalize_display_list(svc.get("labels"), ("value", "name", "label")),
                "threat_names": _normalize_display_list(svc.get("threats"), ("name", "value", "id")),
            }
        )

        if svc.get("scan_time") is not None:
            service_scan_times.append(str(svc.get("scan_time")))

        service_labels.extend(_normalize_display_list(svc.get("labels"), ("value", "name", "label")))
        service_threat_names.extend(_normalize_display_list(svc.get("threats"), ("name", "value", "id")))

    host_labels = _normalize_display_list(host.get("labels"), ("value", "name", "label"))
    dns_names = _normalize_display_list(_safe_get(host, "dns.names", []), ("name", "value"))

    forward_dns_names = _forward_dns_names(host)

    reverse_dns_names = _normalize_display_list(_safe_get(host, "dns.reverse_dns.names", []), ("name", "value"))

    location = host.get("location") if isinstance(host.get("location"), dict) else {}
    coordinates = location.get("coordinates") if isinstance(location.get("coordinates"), dict) else {}

    return {
        "ip": host.get("ip"),
        "service_count": host.get("service_count"),
        "services": service_rows,
        "service_scan_times": service_scan_times,
        "host_labels": host_labels,
        "service_labels": service_labels,
        "service_threat_names": service_threat_names,
        "dns_names": dns_names,
        "forward_dns_names": forward_dns_names,
        "reverse_dns_names": reverse_dns_names,
        "whois_network_name": _safe_get(host, "whois.network.name"),
        "whois_network_cidrs": _normalize_display_list(
            _safe_get(host, "whois.network.cidrs", []),
            ("cidr", "value", "name", "id"),
        ),
        "autonomous_system_name": _safe_get(host, "autonomous_system.name"),
        "autonomous_system_asn": _safe_get(host, "autonomous_system.asn"),
        "location": {
            "city": location.get("city"),
            "province": location.get("province"),
            "postal_code": location.get("postal_code"),
            "country": location.get("country"),
            "country_code": location.get("country_code"),
            "continent": location.get("continent"),
            "latitude": coordinates.get("latitude"),
            "longitude": coordinates.get("longitude"),
        },
        # --- enrichment-specific fields (not present on a plain host) ---
        "greynoise": {
            "actor": _safe_get(host, "greynoise.actor"),
            "classification": _safe_get(host, "greynoise.classification"),
            "last_observed_time": _safe_get(host, "greynoise.last_observed_time"),
        },
        "reputation": {
            **_build_reputation(host),
            "evidence": _reputation_evidence_rows(host),
        },
        "privacy": _flags_from_list(host.get("privacy"), ("anonymous", "proxy", "relay", "tor", "vpn")),
        "network": _flags_from_list(host.get("network"), ("hosting", "mobile", "satellite")),
        "third_party_records": _build_third_party_rows(host),
    }


def _build_third_party_rows(host: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten third-party threat intel records into provider/observable/opinion rows.

    The providers under `third_party` (mallory, ...) are an open set and each may carry
    its own fields, so every provider is walked generically and only the shared fields
    the widget targets are surfaced. Providers missing them render blank rather than
    breaking the widget.
    """
    third_party = host.get("third_party")
    if not isinstance(third_party, dict):
        return []

    rows = []
    for provider, records in sorted(third_party.items()):
        for record in _ensure_list([records] if isinstance(records, dict) else records):
            if not isinstance(record, dict):
                continue

            observable = record.get("observable") if isinstance(record.get("observable"), dict) else {}
            rows.append(
                {
                    "provider": provider,
                    "observable_name": observable.get("name"),
                    "observable_uuid": observable.get("uuid"),
                    "opinions": [
                        {"source": opinion.get("source"), "verdict": opinion.get("verdict")}
                        for opinion in _ensure_list(record.get("opinions"))
                        if isinstance(opinion, dict)
                    ],
                }
            )
    return rows


def _build_web_property_result(web_property: dict[str, Any]) -> dict[str, Any]:
    endpoints = []
    for endpoint in _ensure_list(web_property.get("endpoints")):
        if isinstance(endpoint, dict):
            endpoints.append(
                {
                    "endpoint_type": endpoint.get("endpoint_type"),
                    "path": endpoint.get("path"),
                }
            )

    software = []
    for sw in _ensure_list(web_property.get("software")):
        if isinstance(sw, dict):
            software.append(
                {
                    "vendor": sw.get("vendor"),
                    "product": sw.get("product"),
                    "version": sw.get("version"),
                }
            )

    labels = _normalize_display_list(web_property.get("labels"), ("value", "name", "label"))
    threats = _normalize_display_list(web_property.get("threats"), ("name", "value", "id"))
    vulns = _normalize_display_list(web_property.get("vulns"), ("id", "name", "cve_id"))
    cert = web_property.get("cert") if isinstance(web_property.get("cert"), dict) else {}

    return {
        "hostname": web_property.get("hostname"),
        "port": web_property.get("port"),
        "scan_time": web_property.get("scan_time"),
        "endpoints": endpoints,
        "labels": labels,
        "threats": threats,
        "vulns": vulns,
        "software": software,
        "cert": _extract_cert_fields(cert) if cert else {},
    }


def _extract_search_hit_resource(hit: dict[str, Any], *dotpaths: str) -> dict[str, Any]:
    for dotpath in dotpaths:
        resource = _safe_get(hit, dotpath, {})
        if isinstance(resource, dict) and resource:
            return resource
    return {}


def _service_match_key(service: dict[str, Any]) -> tuple[Any, Any, Any] | None:
    if not isinstance(service, dict):
        return None

    key = (service.get("port"), service.get("protocol"), service.get("transport_protocol"))
    if key == (None, None, None):
        return None
    return key


def _extract_search_host_services(hit: dict[str, Any], host: dict[str, Any]) -> list[dict[str, Any]]:
    all_services = [svc for svc in _ensure_list(host.get("services")) if isinstance(svc, dict)]
    matched_services = [svc for svc in _ensure_list(_safe_get(hit, "host_v1.matched_services", [])) if isinstance(svc, dict)]

    if not matched_services:
        return all_services

    services_by_key = {}
    for service in all_services:
        key = _service_match_key(service)
        if key is not None and key not in services_by_key:
            services_by_key[key] = service

    enriched_services = []
    seen_keys = set()
    for matched_service in matched_services:
        key = _service_match_key(matched_service)
        if key is not None and key in seen_keys:
            continue

        full_service = services_by_key.get(key, {})
        enriched_service = dict(full_service) if isinstance(full_service, dict) else {}
        enriched_service.update(matched_service)
        enriched_services.append(enriched_service if enriched_service else dict(matched_service))

        if key is not None:
            seen_keys.add(key)

    return enriched_services or all_services


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def _truncate_list(values: list[Any], limit: int = 5) -> list[Any]:
    if limit < 1:
        return []
    return values[:limit]


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _build_search_summary_primary(
    total_hits: Any,
    returned_hits: int,
    host_count: int,
    cert_count: int,
    web_property_count: int,
) -> str:
    total_hits_int = _safe_int(total_hits, returned_hits)
    if total_hits_int < 1:
        total_hits_int = returned_hits

    non_zero_counts = []
    if host_count:
        non_zero_counts.append((host_count, "host", "hosts"))
    if cert_count:
        non_zero_counts.append((cert_count, "certificate", "certificates"))
    if web_property_count:
        non_zero_counts.append((web_property_count, "web property", "web properties"))

    if returned_hits == total_hits_int and len(non_zero_counts) == 1:
        count, singular, plural = non_zero_counts[0]
        return f"{count:,} {singular if count == 1 else plural} matched"

    return f"{total_hits_int:,} {'asset' if total_hits_int == 1 else 'assets'} matched"


def _build_search_summary_secondary(total_hits: Any, processed_hits: int, returned_hits: int) -> str:
    total_hits_int = _safe_int(total_hits, returned_hits)
    if total_hits_int < processed_hits:
        total_hits_int = processed_hits
    return f"Showing {processed_hits:,} of {total_hits_int:,} hits."


def _get_result_param(result: Any, key: str) -> Any:
    if result is None or not hasattr(result, "get_param"):
        return None

    try:
        params = result.get_param()
    except TypeError:
        try:
            return result.get_param(key)
        except Exception:
            return None
    except Exception:
        return None

    if isinstance(params, dict):
        return params.get(key)
    return None


def _extract_censeye_result_rows(job_results: dict[str, Any], limit: int = 100) -> tuple[list[dict[str, Any]], bool]:
    rows: list[dict[str, Any]] = []
    raw_results = _ensure_list(job_results.get("results"))
    truncated = len(raw_results) > limit

    for item in raw_results[:limit]:
        if not isinstance(item, dict):
            continue

        field_rows = []
        value_rows = []
        for pair in _ensure_list(item.get("field_value_pairs")):
            if not isinstance(pair, dict):
                continue
            field_name = pair.get("field")
            field_value = pair.get("value")
            if field_name in (None, "") and field_value in (None, ""):
                continue
            field_rows.append(field_name)
            value_rows.append(field_value)

        rows.append(
            {
                "count": item.get("count"),
                "field_rows": field_rows or ["N/A"],
                "value_rows": value_rows or ["N/A"],
            }
        )

    return rows, truncated


def display_host(provides, all_app_runs, context):
    _ = provides
    context["results"] = results = []

    for result in _iter_action_results(all_app_runs):
        d = _first_data_dict(result)
        if not isinstance(d, dict):
            continue

        try:
            results.append(_build_host_result(d))
        except Exception:
            continue

    return "views/lookup_host.html"


def display_host_enrichment(provides, all_app_runs, context):
    _ = provides
    context["results"] = results = []

    for result in _iter_action_results(all_app_runs):
        d = _first_data_dict(result)
        if not isinstance(d, dict):
            continue

        try:
            results.append(_build_host_enrichment_result(d))
        except Exception:
            continue

    return "views/lookup_host_enrichment.html"


def display_cert(provides, all_app_runs, context):
    _ = provides
    context["results"] = results = []

    for result in _iter_action_results(all_app_runs):
        d = _first_data_dict(result)
        if not isinstance(d, dict):
            continue
        try:
            results.append(_extract_cert_fields(d))
        except Exception:
            continue

    return "views/lookup_cert.html"


def display_web_property(provides, all_app_runs, context):
    _ = provides
    context["results"] = results = []

    for result in _iter_action_results(all_app_runs):
        d = _first_data_dict(result)
        if not isinstance(d, dict):
            continue

        try:
            results.append(_build_web_property_result(d))
        except Exception:
            continue

    return "views/lookup_web_property.html"


def display_search(provides, all_app_runs, context):
    _ = provides
    context["results"] = results = []

    for result in _iter_action_results(all_app_runs):
        d = _first_data_dict(result)
        if not isinstance(d, dict):
            continue

        try:
            raw_hits = _ensure_list(d.get("hits"))
            host_results = []
            cert_results = []
            web_property_results = []
            host_count = 0
            cert_count = 0
            web_property_count = 0

            for index, hit in enumerate(raw_hits):
                if not isinstance(hit, dict):
                    continue

                host_resource = _extract_search_hit_resource(hit, "host_v1.resource")
                if host_resource:
                    host_count += 1
                    if index < SEARCH_WIDGET_MAX_HITS:
                        host_results.append(_build_host_result(host_resource, _extract_search_host_services(hit, host_resource)))
                    continue

                cert_resource = _extract_search_hit_resource(hit, "certificate_v1.resource", "cert_v1.resource")
                if cert_resource:
                    cert_count += 1
                    if index < SEARCH_WIDGET_MAX_HITS:
                        cert_results.append(_extract_cert_fields(cert_resource))
                    continue

                web_property_resource = _extract_search_hit_resource(
                    hit,
                    "webproperty_v1.resource",
                    "web_property_v1.resource",
                )
                if web_property_resource:
                    web_property_count += 1
                    if index < SEARCH_WIDGET_MAX_HITS:
                        web_property_results.append(_build_web_property_result(web_property_resource))

            results.append(
                {
                    "query": d.get("query") or _get_result_param(result, "query"),
                    "query_duration_millis": d.get("query_duration_millis"),
                    "total_hits": d.get("total_hits"),
                    "returned_hits": len(raw_hits),
                    "processed_hits": min(len(raw_hits), SEARCH_WIDGET_MAX_HITS),
                    "hits_truncated": len(raw_hits) > SEARCH_WIDGET_MAX_HITS,
                    "summary_primary": _build_search_summary_primary(
                        d.get("total_hits"),
                        len(raw_hits),
                        host_count,
                        cert_count,
                        web_property_count,
                    ),
                    "summary_secondary": _build_search_summary_secondary(
                        d.get("total_hits"),
                        min(len(raw_hits), SEARCH_WIDGET_MAX_HITS),
                        len(raw_hits),
                    ),
                    "platform_search_url": d.get("platform_search_url"),
                    "host_results": host_results,
                    "cert_results": cert_results,
                    "web_property_results": web_property_results,
                }
            )
        except Exception:
            continue

    return "views/search_results.html"


def display_live_rescan(provides, all_app_runs, context):
    _ = provides
    context["results"] = results = []

    for result in _iter_action_results(all_app_runs):
        d = _first_data_dict(result)
        if not isinstance(d, dict):
            continue

        try:
            initial_scan = d.get("initial_tracked_scan") if isinstance(d.get("initial_tracked_scan"), dict) else {}
            final_scan = d.get("final_tracked_scan") if isinstance(d.get("final_tracked_scan"), dict) else {}
            pre_lookup = d.get("pre_lookup") if isinstance(d.get("pre_lookup"), dict) else {}
            post_lookup = d.get("post_lookup") if isinstance(d.get("post_lookup"), dict) else {}
            diff_entries = []

            for entry in _ensure_list(d.get("diff_entries")):
                if not isinstance(entry, dict):
                    continue
                diff_entries.append(
                    {
                        "change_type": entry.get("change_type"),
                        "path": entry.get("path"),
                        "before": entry.get("before"),
                        "after": entry.get("after"),
                    }
                )

            tracked_scan_id = final_scan.get("tracked_scan_id") or initial_scan.get("tracked_scan_id")
            results.append(
                {
                    "tracked_scan_id": tracked_scan_id,
                    "target_type": d.get("target_type"),
                    "poll_count": d.get("poll_count"),
                    "duration_seconds": d.get("duration_seconds"),
                    "diff_truncated": bool(d.get("diff_truncated")),
                    "change_count": len(diff_entries),
                    "pre_lookup_type": pre_lookup.get("lookup_type"),
                    "post_lookup_type": post_lookup.get("lookup_type"),
                    "diff_entries": diff_entries,
                }
            )
        except Exception:
            continue

    return "views/live_rescan.html"


def display_host_event_history(provides, all_app_runs, context):
    _ = provides
    context["results"] = results = []

    for result in _iter_action_results(all_app_runs):
        d = _first_data_dict(result)
        if not isinstance(d, dict):
            continue

        try:
            request = _as_dict(d.get("request"))
            events = _ensure_list(d.get("events"))

            service_scan_count = 0
            endpoint_scan_count = 0
            dns_update_count = 0
            event_rows: list[dict[str, Any]] = []

            for event in events[:100]:
                if not isinstance(event, dict):
                    continue
                resource = _as_dict(event.get("resource"))
                payload = resource if resource else event

                event_types: list[str] = []
                details = "N/A"

                service_scanned = _as_dict(payload.get("service_scanned"))
                if service_scanned:
                    service_scan_count += 1
                    event_types.append("service_scanned")
                    scan = _as_dict(service_scanned.get("scan"))
                    if scan:
                        scan_ip = scan.get("ip")
                        scan_port = scan.get("port")
                        scan_protocol = scan.get("protocol")
                        scan_transport = scan.get("transport_protocol")
                        details = f"{scan_ip}:{scan_port}/{scan_protocol}/{scan_transport}"

                endpoint_scanned = payload.get("endpoint_scanned")
                if endpoint_scanned:
                    endpoint_scan_count += 1
                    event_types.append("endpoint_scanned")

                if payload.get("forward_dns_resolved") or payload.get("reverse_dns_resolved"):
                    dns_update_count += 1
                    event_types.append("dns_updated")

                event_rows.append(
                    {
                        "event_time": payload.get("event_time"),
                        "event_type": ", ".join(event_types) if event_types else "other",
                        "details": details,
                    }
                )

            event_times = [str(row.get("event_time")) for row in event_rows if row.get("event_time")]
            results.append(
                {
                    "host_id": request.get("host_id") or d.get("host_id"),
                    "start_time": request.get("start_time"),
                    "end_time": request.get("end_time"),
                    "event_count": len(events),
                    "displayed_count": len(event_rows),
                    "events_truncated": len(events) > len(event_rows),
                    "service_scan_count": service_scan_count,
                    "endpoint_scan_count": endpoint_scan_count,
                    "dns_update_count": dns_update_count,
                    "first_event_time": min(event_times) if event_times else "N/A",
                    "last_event_time": max(event_times) if event_times else "N/A",
                    "event_rows": event_rows,
                }
            )
        except Exception:
            continue

    return "views/host_event_history.html"


def display_host_service_history(provides, all_app_runs, context):
    _ = provides
    context["results"] = results = []

    for result in _iter_action_results(all_app_runs):
        d = _first_data_dict(result)
        if not isinstance(d, dict):
            continue

        try:
            request = _as_dict(d.get("request"))
            ranges = _ensure_list(d.get("ranges"))
            range_rows = []

            for item in ranges[:100]:
                if not isinstance(item, dict):
                    continue
                range_rows.append(
                    {
                        "ip": item.get("ip"),
                        "port": item.get("port"),
                        "protocol": item.get("protocol"),
                        "transport_protocol": item.get("transport_protocol"),
                        "start_time": item.get("start_time"),
                        "end_time": item.get("end_time"),
                        "vulns": ", ".join(_truncate_list(_normalize_display_list(item.get("vulns"), ("id", "name", "cve_id")), 3)) or "N/A",
                        "threats": ", ".join(_truncate_list(_normalize_display_list(item.get("threats"), ("name", "value", "id")), 3)) or "N/A",
                    }
                )

            next_page_token = d.get("next_page_token")
            results.append(
                {
                    "host_id": d.get("host_id"),
                    "range_count": len(ranges),
                    "displayed_count": len(range_rows),
                    "ranges_truncated": len(ranges) > len(range_rows),
                    "next_page_token": next_page_token,
                    "next_page_token_present": bool(next_page_token),
                    "request": {
                        "start_time": request.get("start_time"),
                        "end_time": request.get("end_time"),
                        "page_size": request.get("page_size"),
                        "page_token": request.get("page_token"),
                        "port": request.get("port"),
                        "protocol": request.get("protocol"),
                        "transport_protocol": request.get("transport_protocol"),
                        "order_by": request.get("order_by"),
                    },
                    "range_rows": range_rows,
                }
            )
        except Exception:
            continue

    return "views/host_service_history.html"


def display_related_infrastructure(provides, all_app_runs, context):
    _ = provides
    context["results"] = results = []

    for result in _iter_action_results(all_app_runs):
        d = _first_data_dict(result)
        if not isinstance(d, dict):
            continue
        try:
            job = _as_dict(d.get("job"))
            job_results = _as_dict(d.get("job_results"))
            rows, rows_truncated = _extract_censeye_result_rows(job_results)
            results.append(
                {
                    "result_count": _safe_int(job.get("result_count")),
                    "returned_results": len(_ensure_list(job_results.get("results"))),
                    "displayed_results": len(rows),
                    "results_truncated": rows_truncated,
                    "result_rows": rows,
                }
            )
        except Exception:
            continue

    return "views/related_infrastructure.html"
