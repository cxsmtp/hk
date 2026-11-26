"""Offline, layered detection of sensitive data (DLP) and prompt injection / jailbreaks.

normalize      Unicode, invisible characters, homoglyphs, leetspeak, spaced-out text, encoded segments
structured     validated detectors (checksums, allocation rules, known prefixes, entropy, context words)
categories     document classification (weighted dictionaries, source-code structure, tenant dictionaries)
fingerprints   exact data match against a tenant's salted digests
dlp_engine     the DLP layers together, for one text
injection_*    the versioned rule set, the offline classifier and the combined risk score
profile        per-tenant settings and the active profile for a decision path
evaluation     precision / recall on the labelled benchmark (tests/fixtures/detection_benchmark)

Nothing here calls a network service.
"""
