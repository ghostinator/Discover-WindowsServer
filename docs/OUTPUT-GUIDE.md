# Output guide

Every run writes one folder:

```
<OutputRoot>\Discover-WindowsServer_<HOST>_<yyyyMMdd_HHmmss>\
```

Inside it there are **two** top-level folders and a README. That is deliberate. The
previous layout put roughly thirty files and ten sibling directories at the run root,
which meant the first question anyone asked on receiving a run was "which of these am I
supposed to read?" - and the second was "which of these can I forward?". Both questions
now answer themselves.

```
README.txt                                  The map. Read first if you have never seen one of these.

reports\                                    What a human reads.
    internal-engineering-report.html        INTERNAL ONLY - start here, reads top to bottom (print-friendly)
    internal-dashboard-report.html          INTERNAL ONLY - same data, sidebar nav + scrollable tables for onscreen use
    internal-engineering-report.md          Same content, paste-ready
    client-discovery-report.html            SEND THIS TO THE CLIENT
    client-discovery-report.md              Same content, paste-ready
    supporting\                             Everything the two reports draw on
        summary.md / summary.txt
        decommission-readiness.md
        scream-test-plan.md
        migration-complexity.md
        downtime-cutover-considerations.md
        draft-scope-language.md
        scope-assumptions.md
        scope-exclusions.md
        client-interview-questions.md
        follow-up-questions.md
        unknowns-that-matter.md
        licensing-validation.md
        vendor-dependencies.md
        dependency-graph.csv
        wbs-inputs.csv
        application-validation-matrix.csv
        workbook.xml                        All datasets, one worksheet each
        client-safe\                        Audience-scoped copies
        internal\

evidence\                                   Everything the reports were built from.
    collection-metadata.json                What ran, with which resolved settings
    discovery-plan.md                       What the toolkit intended to do, written before it did it
    data\csv\<Dataset>.csv                  One file per dataset
    data\json\<Dataset>.json                One file per dataset, always a JSON array
    logs\summary.txt                        INFO / WARN / ERROR, live during the run
    logs\errors.txt                         ERROR only - should be empty
    logs\warnings.txt                       WARN only
    logs\debug.log                          Only with -VerboseLogging
    logs\limitations.txt                    What the run could not collect, and why
    logs\scoping-risks.txt                  Flat findings list, severity-ordered
    raw\                                    Raw captures (only when explicitly requested)
    status\                                 Live status JSON written during the run
    manifest\                               SHA256 evidence manifest (-GenerateEvidenceManifest)

archive\                                    ZIP of the whole run (unless -SkipZip)
```

## Datasets added after the first release

Exported like every other dataset (one CSV and one JSON each under `evidence\data\`):
`CertificateAuthority` (configured AD CS CA and whether its CRL/AIA URLs hard-code this server),
`ClusterNodes`, `ClusterNetworks`, `ClusterGroups`, `ClusterSharedVolumes`,
`IscsiTargets`, `IscsiVirtualDisks`, `IscsiInitiatorConnections`, and richer `HyperVVMs` /
`HyperVDisks` (disk type, sizes, parent chain, switch mapping, checkpoint count). Field lists are
in [FIELD-USAGE.md](FIELD-USAGE.md).

## The two reports

### `reports\internal-engineering-report.html` (and `.md`)

The full engineering picture. Every finding with its **evidence string**, the dependency
map, migration complexity rubric, decommission readiness, WBS inputs, draft scope
language, unknowns, limitations, and an appendix indexing every dataset and module.

This file contains service account names, file paths, listening ports, certificate
subjects and share paths. **It is internal.** It was previously called
`internal-report.html`; it was renamed because a filename is the last warning anyone
reads before they hit forward.

### `reports\internal-dashboard-report.html`

The same model as the engineering report above (identical findings, identical dataset
sections - both are built from `Get-InternalReportModel` in `Output.psm1` so the two can
never drift apart), rendered as an interactive Command Center instead of one long page: a
sidebar jumps straight to a severity band or a dataset section, and each table sits in its
own scrollable, filterable box. Use this one on screen; use the plain report above to print
or hand to someone reading start to finish. Same internal-only handling applies - it carries
the same evidence detail.

### `reports\client-discovery-report.html` (and `.md`)

The client deliverable. Plain English, no jargon, no evidence strings: what the server
appears to do, the business applications recognised on it, what connects to it, the
handful of things worth the client's attention, the questions only they can answer, and
suggested next steps.

Its safety properties are enforced in code, not by convention:

* it reads **only** datasets whose `Visibility` is `ClientSafe` or `Both`;
* it reads **only** questions whose `Audience` is `ClientSafe` or `Both`;
* it **never** renders a finding's `Evidence` field - client-facing text comes from
  `Title` and `WhyItMattersForScoping`, which are authored in the rule files rather than
  collected from the machine;
* headline items are capped at High/Critical severity and deduplicated by title, so a
  per-row rule that fires forty times does not bury the three things that matter.

If you extend the client report, keep those four properties. They are the reason the
document can be sent without a review pass.

## Fleet Discovery output (multi-server engagements)

`tools\Invoke-FleetDiscovery.ps1` pulls each target's own run folder back into one
engagement folder (`<OutputRoot>\FleetRuns\<name>\`), alongside `fleet-run-results.json`
(one entry per target it was asked to run, win or lose - the only record of a target that
never produced a folder at all) and `fleet-status\progress.json`. Building the rollup
(`tools\Merge-FleetDiscoveryResults.ps1`, or the GUI's Fleet tab "Build Rollup Report"
button) writes to `<engagement>\rollup\`:

* **`fleet-rollup.html`** - the printable rollup: KPI tiles, a server-by-server status
  table (failed/unreachable targets shown with their real error message, never silently
  dropped), findings grouped by severity across the whole fleet, possible migration-wave
  groupings. Same visual language as `internal-engineering-report.html`. Reads top to
  bottom.
* **`fleet-dashboard-report.html`** - the same data (both are built from
  `Get-FleetRollupModel`, so they can't drift apart), as an interactive Command Center:
  sidebar nav, scrollable/filterable tables. Same layout and behavior as
  `internal-dashboard-report.html`, applied to the whole engagement instead of one server.
* **`fleet-rollup.json`** - the combined model as data, for scripting against.
* **`fleet-rollup-risks.csv`** - the combined risk register only, one row per finding
  across every server, for pivoting in Excel.
* **`fleet-client-summary.html`** (and `.md`) - the client-safe fleet equivalent of
  `client-discovery-report.html`, generated every time alongside the two internal formats.
  Same safety contract: a dataset only appears if that *specific server's own*
  `collection-metadata.json` recorded it as `ClientSafe`/`Both`, and findings are reduced to
  Title + WhyItMattersForScoping only (never `Evidence`), grouped by title across the fleet
  ("SMBv1 enabled - affects SRV-A, SRV-B" as one line, not one per server). A failed/unreachable
  target is counted in the server total but never shown with its internal error detail - that
  belongs in the internal rollup, not a client-facing document.

Every file inside an individual target's own pulled-back folder follows the same
single-server contract documented above - the fleet layer only adds the rollup on top.

## Filenames are a contract

Folder and file names are fixed in code rather than exposed as configuration. The
verifier (`tools\Verify-DiscoveryRun.ps1`), the evidence manifest, the README generator
and `config\output-settings.json` all agree on them; making them configurable would
turn a documented contract into four things that can silently disagree.

`config\output-settings.json` → `requiredOutputFiles` is the authoritative list, and the
verifier fails a run that is missing any of them.

## Backwards compatibility

`tools\Verify-DiscoveryRun.ps1` understands both the current two-folder layout and the
older flat one. Run folders produced before this change still verify. Everything else in
the toolkit writes the new layout only.
