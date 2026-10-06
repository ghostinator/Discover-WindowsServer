# Risk Scoring & the Finding Model

Collectors collect **facts**. The `RiskEngine` analyzes facts into **findings**. This
separation keeps collectors simple and makes risk logic data-driven and auditable.

## The standard finding object

```powershell
[pscustomobject]@{
    FindingId                   = 'FIND-0001'
    Category                    = 'Service Account'
    Severity                    = 'Medium'         # Info | Low | Medium | High | Critical
    Confidence                  = 'Confirmed'      # Confirmed | Likely | Possible | NotDetected | Unknown
    Title                       = 'Service runs as domain account'
    EvidenceSource              = 'Services'
    Evidence                    = "Service 'AcmeAppSvc' runs as 'DOMAIN\svc-acme'"
    WhyItMattersForScoping      = '...'
    PotentialProjectImpact      = @('Labor','Cutover Complexity','Vendor Dependency')
    SuggestedValidationQuestion = 'Who owns DOMAIN\svc-acme, and is the password/gMSA documented?'
    SuggestedScopeLanguage      = '> {Brand} assumes required service account credentials ...'
    LikelyAffectedWBSAreas      = @('Application Migration','Cutover Validation')
    ComplianceRelevance         = @()              # populated by the compliance lens
    Subject                     = 'AcmeAppSvc'     # the row's primary identifier
    IsEmphasized                = $false           # prioritised for the active -ProjectType
    EmphasisReason              = ''               # why, when IsEmphasized is true
    SourceModule                = 'ServicesTasks'
    SourceDataset               = 'Services'
}
```

`FindingId` is assigned sequentially by `Add-Finding` (`FIND-0001`, `FIND-0002`, …).

### Subject

For a per-row rule (`emitPerRow: true`), `Subject` carries the value of the rule's
`evidenceField` from the matched row — the service name, task name, application, share, and
so on. It makes a finding machine-readable without parsing the `Evidence` prose, and it is
what `wbs-inputs.csv` groups by.

### Project-type emphasis

A rule may declare which project types it matters most for:

```json
"projectTypeEmphasis": ["Decommission", "ServerRefresh", "AzureMigration"]
```

When the active `-ProjectType` appears in that list, findings from the rule get
`IsEmphasized = $true` and an `EmphasisReason`. The reports then lead with them: the HTML
report gains a *Priority For This Project Type* section, emphasised findings sort first
within their severity band, `scoping-risks.txt` marks them `[PRIORITY]`, and
`wbs-inputs.csv` carries a `PriorityForProject` column.

**Emphasis is presentation only.** It never changes `Severity` or `Confidence`, and it never
changes which rules fire — the finding set is byte-for-byte identical across project types.
That is what "same data, different emphasis" means, and it is why emphasis must not be
implemented as a severity bump: inflating `High` to `Critical` to draw the eye would break
the "do not exaggerate severity" rule below and corrupt every downstream consumer that
reasons about severity. `GeneralDiscovery` matches nothing by design — it is the no-lens
default.

### Severity

`Info` < `Low` < `Medium` < `High` < `Critical`. Do not exaggerate severity.

### Confidence — evidence discipline

| Value | Meaning |
|---|---|
| `Confirmed` | Directly detected |
| `Likely` | Strong indicators exist |
| `Possible` | Weak indicators exist |
| `NotDetected` | Not found — **but not proof of absence** |
| `Unknown` | Could not determine |

Never say "the server is not used for DHCP" merely because DHCP was not detected — say
DHCP was **not detected**.

### PotentialProjectImpact (allowed values)

`Labor`, `Licensing`, `Downtime`, `Vendor Dependency`, `Security/Compliance`,
`Data Migration`, `Cutover Complexity`, `Client Coordination`,
`Architecture Decision`, `Rollback Planning`.

## The data-driven rule engine

Rules live in `config/risk-rules.json`. There is **no arbitrary expression
evaluator** — only these explicit, safe condition types:

| Condition | Fires when |
|---|---|
| `datasetNotEmpty` | Dataset exists and has ≥ 1 row |
| `datasetMissingOrEmpty` | Dataset absent or 0 rows (for *NotDetected*-style findings) |
| `datasetRowCountAtLeast` | Row count ≥ `count` |
| `anyRowFieldEquals` / `anyRowFieldNotEquals` | Any row's `field` (does not) equal `value` |
| `anyRowFieldMatches` | Any row's `field` matches `pattern` (.NET regex) |
| `anyRowFieldGreaterThan` / `anyRowFieldLessThan` | Numeric comparison against `value` |

A rule with `emitPerRow: true` produces one finding per matching row and substitutes
`{FieldName}` tokens in `evidenceTemplate` and `suggestedValidationQuestion` from the
matched row. To keep output sane, per-row rules are capped (currently 200 rows per
rule); truncation is logged as a limitation.

### Rules added from real-server testing

`RULE-SQL-007` (user database with no full backup in msdb; never raised for WID) and `RULE-SQL-008`
(`xp_cmdshell` enabled); `RULE-HV-006` (VM config version behind the host default) and `RULE-HV-007`
(differencing / checkpoint disk chain); `RULE-CL-002` (cluster node not Up) and `RULE-CL-003`
(cluster network not Up); `RULE-ISCSI-001` (an iSCSI target serves LUNs to other servers) and
`RULE-ISCSI-002` (this server uses disks on an external iSCSI target). A rule can test only ONE field,
so multi-condition logic is computed by the collector into a boolean (`NoFullBackup`,
`XpCmdShellEnabled`, `VersionBehindHostDefault`, `IsDifferencing`) that the rule then tests.

### Adding or editing a rule

Add an object to `rules[]`:

```json
{
  "id": "RULE-XYZ-001",
  "enabled": true,
  "category": "Security",
  "severity": "High",
  "confidence": "Confirmed",
  "title": "Short finding title",
  "condition": { "type": "anyRowFieldEquals", "dataset": "SecurityPosture", "field": "Smb1Enabled", "value": true },
  "whyItMattersForScoping": "...",
  "potentialProjectImpact": ["Security/Compliance"],
  "suggestedValidationQuestion": "...",
  "complianceRelevance": ["Insecure protocol review"],
  "sourceModule": "SecurityPosture",
  "sourceDataset": "SecurityPosture"
}
```

Reference dataset field names exactly as documented in
[FIELD-USAGE.md](FIELD-USAGE.md). If a dataset/field is missing at runtime, the rule
silently does not fire (no error).

## Synthesis derived from findings

- **Migration complexity** — a transparent rubric mapping finding categories/impacts
  to `None`/`Low`/`Medium`/`High`/`Unknown` per category (Identity, Network, Database,
  Application, File/print, Certificate, Service account, Vendor, Data volume, Downtime,
  Backup/rollback, Documentation, Security/compliance, Licensing).
- **WBS inputs** — one row per non-Info finding (WBS area, labor driver, complexity,
  evidence, scope note, validation question).
- **Dependency graph** — edges contributed by collectors via `Add-DependencyEdge`.
- **Decommission readiness** — per-factor apparent-dependency assessment + overall
  classification (`Low` / `Medium` / `High apparent dependency` / `Manual validation
  required`). Never an absolute "safe to shut down".

## Compliance lens (interpretive only)

`-ComplianceLens CMMC|GeneralSecurity` (config: `config/compliance-lenses.json`) adds
relevance notes (e.g., *Privileged access review*, *Insecure protocol review*,
*Encryption validation*) to findings by category and by keyword. It **does not claim
compliance, noncompliance, or certification readiness** — notes are for human review.
