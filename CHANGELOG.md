# Changelog

Release notes. The detailed defect-by-defect history lives in [HISTORY.md](HISTORY.md).

## 1.1.0 - migration scoping

Read-only discovery for MSP migration, consolidation and decommission projects, built into the
existing collectors, reports, CLI, GUI and fleet rollup. Full guide:
[docs/MIGRATION-SCOPING.md](docs/MIGRATION-SCOPING.md).

### New collectors
- **ExchangeSmtp** - Exchange version/support, roles, services, receive/send connectors (with
  anonymous-relay detection), accepted/remote domains, hybrid, certificates, queues, log settings,
  Exchange IIS apps and shares. Summarises EXISTING message-tracking and SMTP receive protocol logs
  (and IIS SMTP service logs) into correlated relay clients, and states the evidence condition
  (logging disabled, logs unavailable/aged out, permission failure, cmdlets unavailable). Never
  enables logging and never reports SMTP as unused.
- **ApplicationStacks** - config-driven (`config\application-stacks.json`) server/client/driver/
  DSN/service/task/share/SQL/IIS/process evidence with per-record evidence IDs and confidence.
  Ships Sage 300 Construction and Real Estate and Actian Zen / Pervasive PSQL definitions.
- **WorkloadProfile** - per-server resources and workload footprint for target-capacity comparison.
- **HypervisorInventory** - imports a VMware/RMM VM inventory (CSV/JSON) without any hypervisor
  credential; free-text columns are dropped; VM-count conflicts between sources are reported.

### Extended collectors
- **SQL** - SQL services (engine/agent/browser/full-text/VSS writer/SSIS/SSRS/SSAS), installed
  components, ports and dynamic ports, cluster flag, patch/product level, version support dates,
  service identity type, evidence-based instance classification, per-instance connection status,
  database file locations, server-level readiness summary, ODBC drivers (32/64-bit) and richer
  system DSNs (credential attributes dropped; bitness duplicates, file paths, local-server and
  application hints, driver presence). Per-user DSNs gained the same fields.
- **IIS** - binding IP/port/host header, certificate store, SNI flags, site id/auto-start/state,
  path checks (missing, UNC, outside web roots), app-pool state/auto-start/LocalSystem flag,
  per-site authentication modes; appcmd fallback now maps sites, apps and vdirs to paths and pools.
- **FileShares** - share migration flags, root NTFS ACL shape, SMB sessions (user names withheld by
  default), open-file activity, Azure File Sync indicators, DFS replicated folders, and a streaming
  deep scan with oldest/newest write, long paths, access-denied, reparse/offline counts, duration
  and Complete/DepthLimited/Incomplete status.
- **PrintServer** - port host/number/protocol, SNMP enabled (never the community), driver INF/type,
  print processor, direct-IP/MFP/universal/legacy flags, PrintService-log activity counts,
  printer connections, scan-to-email/folder verification item, print-management agents.
- **AzureHybrid** - Entra Connect detail: version, ADSync service and identity, staging mode and
  scheduler, last run, PTA agent, updater, Health agents, Seamless SSO indicator, sync errors.
- **ActiveDirectory** - DC inventory over LDAP (OS, site, GC, RODC, support status), FSMO per role,
  repadmin replication summary, SYSVOL replication engine, dcdiag (Deep), single-DC and all-FSMO flags.
- **DHCP** (options, failover, lease counts, AD authorization), **DNS** (conditional-forwarder
  targets, static zones), **EventLogs** (errors/warnings per workload area), **HyperV**
  (unattached VHD/ISO files), **VendorAgents** (print management, more RMMs), **BackupDR**
  (Backup Exec), **DecommissionReadiness** (Exchange, SMTP, application engine and Entra Connect
  factors; named decommission states).

### Findings, reports and fleet
- 68 new risk rules; findings carry `RiskCategory` (17 normalized categories), `ClientSafe` and
  `SourceServer`, appended to `ScopingRisks` and `wbs-inputs.csv` after the original columns.
- Internal HTML/dashboard/Markdown reports gained sections for every new area; the Markdown report
  numbers its sections automatically. The client report lists application components and, for
  `-ProjectType Decommission`, what must happen before retirement - never IPs, accounts or paths.
- Fleet rollup: `-RetiringServers` / `-TargetServers`, `fleet-correlations.json`, and correlation
  sections (stack versions and candidate source/target, target capacity, SQL, ODBC/UNC references,
  DNS references to retiring servers, SMTP clients, DCs, Entra Connect, guest/host relationships).

### CLI and GUI
- New parameters: `-ExchangeLogDays`, `-CopyExchangeRawLogs` (privacy-sensitive, off),
  `-IncludeSensitiveEvidence` (privacy-sensitive, off), `-HypervisorInventoryPath`. All 1.0
  parameters are unchanged.
- GUI Options tab: Migration scoping group (privacy options in red, warning on raw-log copy),
  inventory file picker, Exchange/SMTP lookback; the deep file scan is labelled expensive.

### Fixes found while building this
- Share names such as `Data_old` were not recognised by word-boundary regexes (underscore is a word
  character); repadmin `>60 days` deltas broke a whitespace-delimited parse.
