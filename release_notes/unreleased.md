**Unreleased**

* Added `lookup_host_enrichment` action backed by the Censys Platform host enrichment API, surfacing reputation, GreyNoise, privacy/network classification, and third-party threat intelligence in a custom widget.
* Upgraded the bundled `censys-platform` SDK from 0.13.2 to 0.16.1, and the transitive `pydantic` dependency from 2.12.5 to 2.13.5.
* Fixed empty `reputation.evidence` entries in the `lookup_host_enrichment` action, and surfaced each evidence feature (name, value, contribution, category) plus the reputation model version in the widget.
* Fixed missing fields in the `lookup_host` action: the previously bundled SDK models did not declare `reputation.evidence` features, `reputation.label`, `score_suppressed`, `class_probabilities`, or a number of service protocol blocks, so they were dropped from `action_result.data`. The 0.16.1 models declare all of them.
* Split the reputation label and score into separate rows in the `lookup_host_enrichment` widget, and added both to the `lookup_host` widget.
* Aligned the `lookup_host` action summary with `lookup_host_enrichment`: both now report the same keys (`reputation_level`, `greynoise_classification`, and `reputation_score` when scored) and the same message format.
