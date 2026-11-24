# Source accounting

The owner selected the existing original-worktree lineage for this collaboration
baseline. No newest/largest-file heuristic or automatic historical feature merge
was used. Original repositories, preservation batches, Git history and private
runtime data remain unchanged.

## Included source and provenance

- `source-manifest.json`: 857 initially screened original-worktree files.
- `dependency-manifest.json`: 17 original dependency/configuration files.
- `recovery-manifest.json`: 1,214 later source, test, migration, asset, script and
  documentation restorations, each with an original hash and review basis.
- `reviewed-changes.json`: exact original-to-current hashes for reviewed edits,
  including portable setup corrections, explicitly approved application repairs,
  dependency locks and reference-document status notices.

These ledgers cover 2,088 paths. `tools/collaboration/check_import.py` checks their
exact bytes and parses Python without executing the application. That check is
provenance evidence, not runtime acceptance. New collaboration files and generated
dependency locks are reviewed in their Git commits rather than misrepresented as
byte-for-byte original imports.

The API lock resolves the unchanged 27 direct requirements into a complete
109-package universal graph. The endpoint lock resolves 18 package entries across
its supported optional extras. Platform markers select smaller installed subsets.
Fresh Python 3.12 installations, compatibility checks, 36 API connector tests and
66 endpoint tests passed. The hash-locked Python 3.11 Linux Docker image also built.
Full API CI and integration results remain separately recorded.

## Documentation disposition

`documentation-disposition.json` accounts for all 462 document/export candidates:
71 reference documents are included (12 earlier restorations plus 59 reviewed in
this change), 69 historical reports remain preserved outside Git, 174 historical
plans/session policies/commercial records remain preserved outside the active
baseline, and 148 generated visual/export files are excluded. No context-review
queue remains. The 59 new references carry explicit historical-status notices;
prior deployment, provider-version and test claims are not current acceptance.
Personal checkout examples are replaced by portable placeholders.

This is a publication disposition, not a certification of every historical
statement. Imported instructions never authorize service, credential or production
changes. Use the collaboration README and exact-commit tests for current status.

## Exclusions and variants

The local metadata ledger accounts for 16,790 entries without reading private
runtime contents. It explicitly excludes local secret configuration, private
runtime evidence, generated/personal artifacts, tool state and brainstorm scratch.
Fifteen tool-session/support files and two noncanonical `.orig` backups remain
preserved with reasons. Exclusion does not delete or rewrite their originals.

On 22 October 2026 the owner approved finishing this current-worktree baseline
while retaining historical capability variants as unresolved. The 49 historical-only
paths and hashes are listed in `historical-variants.json`; they are not proven
missing files from the selected worktree and are not represented as implemented.
Historical migrations cannot safely be merged as one bundle. The selected graph
has 92 revisions, zero missing parents and one head (0092), exercised only against
disposable PostgreSQL 16 databases.

The independently reviewed 69 product recommendations remain a separate backlog.
The held simulation transaction-recovery patch is not part of published source.
All-root historical feature parity, live-provider controls, target OS enrollment
and production readiness are not claimed by current-worktree source completion.
