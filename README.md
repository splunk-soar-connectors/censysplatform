# Censys for Splunk SOAR

Publisher: Censys <br>
Connector Version: 1.1.1 <br>
Product Vendor: Censys <br>
Product Name: Censys Platform <br>
Minimum Product Version: 6.3.0

This app implements investigative actions to get IP, domain and certificate data from the Censys Platform.

### Configuration variables

This table lists the configuration variables required to operate Censys for Splunk SOAR. These variables are specified when configuring a Censys Platform asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base_url** | optional | string | Base URL for Censys Platform API |
**api_token** | required | password | Personal access token for authentication |
**organization_id** | required | string | Organization UUID used to scope requests |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity <br>
[lookup host](#action-lookup-host) - Retrieve a host by IPv4 or IPv6 address <br>
[lookup host enrichment](#action-lookup-host-enrichment) - Retrieve enrichment data for a single host by IPv4 or IPv6 address <br>
[lookup cert](#action-lookup-cert) - Retrieve a certificate by SHA256 fingerprint <br>
[lookup web property](#action-lookup-web-property) - Retrieve a web property by hostname and port <br>
[get host event history](#action-get-host-event-history) - Retrieve event history for a host <br>
[get host service history](#action-get-host-service-history) - Retrieve historical service observations for a host <br>
[find related infrastructure](#action-find-related-infrastructure) - Create a CensEye job for a host, web property, or certificate target and return related infrastructure pivot results <br>
[live rescan](#action-live-rescan) - Initiate a live rescan and wait for completion, then return a baseline-vs-post change log <br>
[search](#action-search) - Search Censys assets using a CenQL query

## action: 'test connectivity'

Validate the asset configuration for connectivity

Type: **test** <br>
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.message | string | | |

## action: 'lookup host'

Retrieve a host by IPv4 or IPv6 address

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** | required | IPv4 or IPv6 address for lookup | string | `ip` |
**at_time** | optional | Optional ISO 8601 timestamp for historical lookup | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.parameter.ip | string | `ip` | |
action_result.data.\*.ip | string | `ip` | |
action_result.data.\*.service_count | numeric | | |
action_result.data.\*.is_truncated_host | boolean | | |
action_result.data.\*.autonomous_system.asn | numeric | | |
action_result.data.\*.autonomous_system.name | string | | |
action_result.data.\*.greynoise.actor | string | | |
action_result.data.\*.greynoise.classification | string | | |
action_result.data.\*.greynoise.last_observed_time | string | | |
action_result.data.\*.dns.names | string | `domain` | |
action_result.data.\*.dns.reverse_dns.names | string | `domain` | |
action_result.data.\*.whois.network.name | string | | |
action_result.data.\*.whois.network.cidrs | string | | |
action_result.data.\*.location.city | string | | |
action_result.data.\*.location.province | string | | |
action_result.data.\*.location.postal_code | string | | |
action_result.data.\*.location.country | string | | |
action_result.data.\*.location.country_code | string | | |
action_result.data.\*.location.continent | string | | |
action_result.data.\*.location.coordinates.latitude | numeric | | |
action_result.data.\*.location.coordinates.longitude | numeric | | |
action_result.data.\*.labels.\*.value | string | | |
action_result.data.\*.reputation.score | numeric | | |
action_result.data.\*.reputation.score_level | string | | |
action_result.data.\*.reputation.label | string | | |
action_result.data.\*.reputation.model_version | string | | |
action_result.data.\*.reputation.score_suppressed | boolean | | |
action_result.data.\*.reputation.class_probabilities.\*.label | string | | |
action_result.data.\*.reputation.class_probabilities.\*.probability | numeric | | |
action_result.data.\*.reputation.evidence.\*.category | string | | |
action_result.data.\*.reputation.evidence.\*.evidence_score | numeric | | |
action_result.data.\*.reputation.evidence.\*.feature.id | string | | |
action_result.data.\*.reputation.evidence.\*.feature.name | string | | |
action_result.data.\*.reputation.evidence.\*.feature.value | string | | |
action_result.data.\*.reputation.evidence.\*.feature.contribution | numeric | | |
action_result.data.\*.reputation.evidence.\*.feature.category | string | | |
action_result.data.\*.services.\*.port | numeric | `port` | |
action_result.data.\*.services.\*.protocol | string | | |
action_result.data.\*.services.\*.transport_protocol | string | | |
action_result.data.\*.services.\*.scan_time | string | | |
action_result.data.\*.services.\*.banner | string | | |
action_result.data.\*.services.\*.labels.\*.value | string | | |
action_result.data.\*.services.\*.threats.\*.name | string | | |
action_result.data.\*.services.\*.vulns.\*.id | string | | |
action_result.data.\*.services.\*.vulns.\*.severity | string | | |
action_result.data.\*.services.\*.cert.fingerprint_sha256 | string | `sha256` | |
action_result.summary.ip | string | `ip` | |
action_result.summary.service_count | numeric | | |
action_result.summary.ports | string | `port` | |
action_result.summary.scan_time | string | | |
action_result.summary.reputation_score | numeric | | |
action_result.summary.reputation_level | string | | |
action_result.summary.greynoise_classification | string | | |
action_result.message | string | | |
action_result.parameter.at_time | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'lookup host enrichment'

Retrieve enrichment data for a single host by IPv4 or IPv6 address

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** | required | IPv4 or IPv6 address for lookup | string | `ip` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.parameter.ip | string | `ip` | |
action_result.data.\*.ip | string | `ip` | |
action_result.data.\*.autonomous_system.asn | numeric | | |
action_result.data.\*.autonomous_system.name | string | | |
action_result.data.\*.greynoise.actor | string | | |
action_result.data.\*.greynoise.classification | string | | |
action_result.data.\*.greynoise.last_observed_time | string | | |
action_result.data.\*.reputation.score | numeric | | |
action_result.data.\*.reputation.score_level | string | | |
action_result.data.\*.reputation.label | string | | |
action_result.data.\*.reputation.model_version | string | | |
action_result.data.\*.reputation.score_suppressed | boolean | | |
action_result.data.\*.reputation.class_probabilities.\*.label | string | | |
action_result.data.\*.reputation.class_probabilities.\*.probability | numeric | | |
action_result.data.\*.reputation.evidence.\*.feature.id | string | | |
action_result.data.\*.reputation.evidence.\*.feature.name | string | | |
action_result.data.\*.reputation.evidence.\*.feature.value | string | | |
action_result.data.\*.reputation.evidence.\*.feature.contribution | numeric | | |
action_result.data.\*.reputation.evidence.\*.feature.category | string | | |
action_result.data.\*.privacy.\*.anonymous | boolean | | |
action_result.data.\*.privacy.\*.proxy | boolean | | |
action_result.data.\*.privacy.\*.tor | boolean | | |
action_result.data.\*.privacy.\*.vpn | boolean | | |
action_result.data.\*.privacy.\*.relay | boolean | | |
action_result.data.\*.network.\*.hosting | boolean | | |
action_result.data.\*.network.\*.mobile | boolean | | |
action_result.data.\*.network.\*.satellite | boolean | | |
action_result.data.\*.third_party.mallory.\*.observable.name | string | | |
action_result.data.\*.third_party.mallory.\*.observable.uuid | string | | |
action_result.data.\*.third_party.mallory.\*.opinions.\*.source | string | | |
action_result.data.\*.third_party.mallory.\*.opinions.\*.verdict | string | | |
action_result.summary.ip | string | `ip` | |
action_result.summary.service_count | numeric | | |
action_result.summary.ports | string | `port` | |
action_result.summary.scan_time | string | | |
action_result.summary.reputation_score | numeric | | |
action_result.summary.reputation_level | string | | |
action_result.summary.greynoise_classification | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'lookup cert'

Retrieve a certificate by SHA256 fingerprint

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**fingerprint_sha256** | required | Certificate SHA256 fingerprint | string | `sha256` `hash` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.parameter.fingerprint_sha256 | string | `sha256` `hash` | |
action_result.data.\*.fingerprint_sha256 | string | `sha256` `hash` | |
action_result.summary.display_name | string | | |
action_result.summary.fingerprint_sha256 | string | `sha256` `hash` | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'lookup web property'

Retrieve a web property by hostname and port

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hostname** | required | Hostname or IP address for lookup | string | `domain` `ip` |
**port** | required | TCP port value (1-65535) | numeric | |
**at_time** | optional | Optional ISO 8601 timestamp for historical lookup | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.parameter.hostname | string | `domain` `ip` | |
action_result.parameter.port | numeric | | |
action_result.data.\*.hostname | string | `domain` `ip` | |
action_result.data.\*.port | numeric | | |
action_result.summary.endpoint_count | numeric | | |
action_result.summary.hostname | string | `domain` `ip` | |
action_result.summary.port | numeric | | |
action_result.summary.endpoints | string | | |
action_result.summary.scan_time | string | | |
action_result.message | string | | |
action_result.parameter.at_time | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'get host event history'

Retrieve event history for a host

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**host_id** | required | The IP address of a host | string | `ip` |
**start_time** | required | Newer RFC3339 timestamp for the host timeline. Equivalent to the To field in the event history UI | string | |
**end_time** | required | Older RFC3339 timestamp for the host timeline. Equivalent to the From field in the event history UI | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.parameter.host_id | string | `ip` | |
action_result.parameter.start_time | string | | |
action_result.parameter.end_time | string | | |
action_result.data.\*.request.host_id | string | `ip` | |
action_result.data.\*.events.\*.resource.event_time | string | | |
action_result.data.\*.scanned_to | string | | |
action_result.summary.host_id | string | `ip` | |
action_result.summary.event_count | numeric | | |
action_result.summary.first_event_time | string | | |
action_result.summary.last_event_time | string | | |
action_result.summary.has_service_scanned | numeric | | |
action_result.summary.has_endpoint_scanned | numeric | | |
action_result.summary.has_dns_updates | numeric | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'get host service history'

Retrieve historical service observations for a host

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**host_id** | required | The IP address of a host | string | `ip` |
**start_time** | optional | Start of date range in RFC3339 format. If omitted, defaults to the maximum query window back from end_time | string | |
**end_time** | optional | End of date range in RFC3339 format. If omitted, defaults to now. Cannot be in the future | string | |
**page_size** | optional | Number of results per page (max 100) | numeric | |
**page_token** | optional | Pagination token from previous response | string | |
**port** | optional | Filter by port number | numeric | |
**protocol** | optional | Filter by application protocol | string | |
**transport_protocol** | optional | Filter by transport protocol (tcp, udp, quic) | string | |
**order_by** | optional | Comma-separated sort fields, for example port DESC,protocol ASC | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.parameter.host_id | string | `ip` | |
action_result.parameter.start_time | string | | |
action_result.parameter.end_time | string | | |
action_result.parameter.page_size | numeric | | |
action_result.parameter.page_token | string | | |
action_result.parameter.port | numeric | | |
action_result.parameter.protocol | string | | |
action_result.parameter.transport_protocol | string | | |
action_result.parameter.order_by | string | | |
action_result.data.\*.host_id | string | `ip` | |
action_result.data.\*.ranges.\*.ip | string | `ip` | |
action_result.data.\*.ranges.\*.port | numeric | | |
action_result.data.\*.ranges.\*.protocol | string | | |
action_result.data.\*.ranges.\*.transport_protocol | string | | |
action_result.data.\*.ranges.\*.start_time | string | | |
action_result.data.\*.ranges.\*.end_time | string | | |
action_result.data.\*.next_page_token | string | | |
action_result.summary.host_id | string | `ip` | |
action_result.summary.range_count | numeric | | |
action_result.summary.next_page_token_present | numeric | | |
action_result.summary.port_count | numeric | | |
action_result.summary.protocol_count | numeric | | |
action_result.summary.transport_protocol_count | numeric | | |
action_result.summary.min_start_time | string | | |
action_result.summary.max_end_time | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'find related infrastructure'

Create a CensEye job for a host, web property, or certificate target and return related infrastructure pivot results

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**target_type** | required | Target type for the CensEye job | string | |
**target_value** | required | Target value. Use an IP for host, '<hostname>:<port>' for web property, or a SHA256 fingerprint for certificate | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.parameter.target_type | string | | |
action_result.parameter.target_value | string | | |
action_result.data.\*.target_type | string | | |
action_result.data.\*.target_value | string | | |
action_result.data.\*.job.job_id | string | | |
action_result.data.\*.job.state | string | | |
action_result.data.\*.job.at_time | string | | |
action_result.data.\*.job.create_time | string | | |
action_result.data.\*.job.update_time | string | | |
action_result.data.\*.job.delete_time | string | | |
action_result.data.\*.job.result_count | numeric | | |
action_result.data.\*.job_results.results.\*.count | numeric | | |
action_result.data.\*.job_results.results.\*.field_value_pairs.\*.field | string | | |
action_result.data.\*.job_results.results.\*.field_value_pairs.\*.value | string | | |
action_result.data.\*.ui_url | string | | |
action_result.data.\*.poll_count | numeric | | |
action_result.data.\*.duration_seconds | numeric | | |
action_result.summary.target_type | string | | |
action_result.summary.target_value | string | | |
action_result.summary.job_id | string | | |
action_result.summary.state | string | | |
action_result.summary.result_count | numeric | | |
action_result.summary.returned_results | numeric | | |
action_result.summary.poll_count | numeric | | |
action_result.summary.duration_seconds | numeric | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'live rescan'

Initiate a live rescan and wait for completion, then return a baseline-vs-post change log

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** | optional | Service target IP address | string | `ip` |
**hostname** | optional | Web target hostname | string | `domain` `ip` |
**port** | required | Target port | numeric | |
**protocol** | optional | Service protocol (required for service target) | string | |
**transport_protocol** | optional | Service transport protocol (unknown, tcp, udp, icmp, quic) for service target | string | |
**target_type** | optional | Optional explicit target type override: service_id or web_origin | string | |
**wait_timeout_seconds** | optional | Maximum wait time before polling times out | numeric | |
**max_diff_entries** | optional | Maximum number of diff rows to include in the change log | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.parameter.ip | string | `ip` | |
action_result.parameter.hostname | string | `domain` `ip` | |
action_result.parameter.port | numeric | | |
action_result.parameter.protocol | string | | |
action_result.parameter.transport_protocol | string | | |
action_result.parameter.target_type | string | | |
action_result.parameter.wait_timeout_seconds | numeric | | |
action_result.parameter.max_diff_entries | numeric | | |
action_result.data.\*.target_type | string | | |
action_result.data.\*.initial_tracked_scan.tracked_scan_id | string | | |
action_result.data.\*.final_tracked_scan.tracked_scan_id | string | | |
action_result.data.\*.final_tracked_scan.completed | numeric | | |
action_result.data.\*.final_tracked_scan.tasks.\*.status | string | | |
action_result.data.\*.pre_lookup.lookup_type | string | | |
action_result.data.\*.post_lookup.lookup_type | string | | |
action_result.data.\*.diff_entries.\*.change_type | string | | |
action_result.data.\*.diff_entries.\*.path | string | | |
action_result.data.\*.diff_entries.\*.before | string | | |
action_result.data.\*.diff_entries.\*.after | string | | |
action_result.data.\*.diff_truncated | numeric | | |
action_result.summary.tracked_scan_id | string | | |
action_result.summary.target_type | string | | |
action_result.summary.completed | numeric | | |
action_result.summary.poll_count | numeric | | |
action_result.summary.duration_seconds | numeric | | |
action_result.summary.latest_task_status | string | | |
action_result.summary.change_count | numeric | | |
action_result.summary.diff_truncated | numeric | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'search'

Search Censys assets using a CenQL query

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** | required | CenQL query string | string | |
**page_size** | optional | Maximum number of results to return | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.parameter.query | string | | |
action_result.summary.query_duration_millis | numeric | | |
action_result.summary.total_hits | numeric | | |
action_result.summary.hit_count | numeric | | |
action_result.message | string | | |
action_result.parameter.page_size | numeric | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2026 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
