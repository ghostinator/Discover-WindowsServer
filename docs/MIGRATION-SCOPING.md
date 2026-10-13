# Migration scoping: workloads, dependencies and decommission readiness

Version 1.1.0 extended the toolkit for MSP migration, consolidation and decommission projects.
Everything below is **read-only** and runs through the same engine, CLI, GUI, fleet runner and
reports as the rest of the toolkit. Nothing here is specific to one client: application
families are data (`config\application-stacks.json`), and no server, share, DSN or IP is
hard-coded anywhere.

## What each area collects, and where it is useful

| Area | Collector (module) | Useful on | Key datasets |
|---|---|---|---|
| SQL Server | `SQL` | Any server with SQL / WID | `SqlInstances`, `SqlServices`, `SqlServerSummary`, `SqlDatabases`, `SqlDatabaseFiles`, `SqlComponents` |
| ODBC | `SQL` (system DSNs, drivers), `UserProfiles` (per-user DSNs) | App servers, RDS hosts, workstations-as-servers | `OdbcDsns`, `UserOdbcDsns`, `OdbcDrivers` |
| IIS | `IIS` | Web / app servers | `IisSites`, `IisBindings`, `IisAppPools`, `IisApplications`, `IisVirtualDirectories`, `IisAuthentication` |
| Exchange & SMTP relay | `ExchangeSmtp` (new) | Exchange servers, IIS SMTP relays, anything listening on 25/465/587 | `ExchangeServer`, `ExchangeReceiveConnectors`, `ExchangeSendConnectors`, `SmtpRelayClients`, `SmtpRelayAssessment`, `SmtpConnections`, ... |
| Application stacks (Sage 300 CRE, Actian / Pervasive, ...) | `ApplicationStacks` (new) | App servers, RDS hosts, file servers holding app data | `AppStackEvidence`, `AppStackSummary` |
| File-server readiness | `FileShares` | File servers, DFS members, Azure File Sync servers | `SmbShares`, `ShareRootAcl`, `SmbSessions`, `ShareActivity`, `NtfsAclSummary`, `DfsDiscovery`, `AzureFileSync` |
| Printing | `PrintServer` | Print servers, RDS hosts | `Printers`, `PrintPorts`, `PrinterDrivers`, `PrintActivity`, `PrinterConnections`, `PrintServerSummary` |
| Entra Connect | `AzureHybrid` | The sync server, PTA agent hosts | `EntraConnectDetail`, `HybridIdentity` |
| AD readiness | `ActiveDirectory` (+ `DNS`, `DHCP`, `TimeSync`) | DCs (most detail), any domain member (DC inventory) | `DomainContext`, `AdDomainControllers`, `AdFsmoRoles`, `AdReplicationSummary`, `AdHealthChecks`, `DnsZones`, `DhcpServerSummary`, `DhcpOptions`, `DhcpFailover`, `TimeSync` |
| Group Policy content | `ActiveDirectory` | DCs (always), domain members in Deep mode | `GpoInventory`, `GpoServerReferences` |
| Workload / target capacity | `WorkloadProfile` (new, runs last) | Every server | `WorkloadProfile` |
| Services, tasks, ports, events | `ServicesTasks`, `Network`, `EventLogs` | Every server | `Services`, `ScheduledTasks`, `ListeningPorts`, `EstablishedConnections`, `EventLogDependencyAreas` |
| Hypervisor decommissioning | `HyperV`, `HypervisorInventory` (new, import only) | Hyper-V hosts; any host with an exported VMware/RMM inventory | `HyperVVMs`, `HyperVUnattachedFiles`, `ExternalHypervisorVMs`, `HypervisorInventorySummary`, `DecommissionStates` |

Role-gated collectors (IIS, DNS, DHCP, Hyper-V, ExchangeSmtp, HypervisorInventory) record a clean
`NotApplicable` skip where the role is absent - never fake rows, never an error.

## Running it

```powershell
# Decommission scoping, SQL database inventory over local Windows auth, 30 days of Exchange/SMTP logs
.\Discover-WindowsServer.ps1 -Mode Deep -ProjectType Decommission -AttemptSqlIntegratedAuth -ExchangeLogDays 30

# Only the migration-scoping collectors
.\Discover-WindowsServer.ps1 -Mode Custom -IncludeModules SQL,IIS,ExchangeSmtp,FileShares,PrintServer,AzureHybrid,ActiveDirectory,ApplicationStacks,WorkloadProfile

# Import an exported VMware / RMM VM inventory for host decommissioning
.\Discover-WindowsServer.ps1 -Mode Fast -ProjectType Decommission -HypervisorInventoryPath C:\Exports\vcenter-vms.csv

# Fleet rollup with explicit source (retiring) and target servers
.\tools\Merge-FleetDiscoveryResults.ps1 -EngagementFolder C:\Temp\FleetRuns\Client_2026 -RetiringServers APP01,FS01 -TargetServers APP02
```

| New parameter | Default | Notes |
|---|---|---|
| `-ExchangeLogDays` | 7 (Fast) / 14 (Deep) | Lookback for existing message-tracking and SMTP protocol logs. Config key `exchangeLogDays`. |
| `-CopyExchangeRawLogs` | off | **Privacy-sensitive.** Copies the in-window raw logs to `evidence\raw\exchange-logs` (2 GB cap). They contain email addresses and message metadata. |
| `-IncludeSensitiveEvidence` | off | **Privacy-sensitive.** Keeps full sample sender/recipient addresses, message IDs, SMB session user names and the collection account name. Off: addresses become `*@domain`, user names are withheld. |
| `-HypervisorInventoryPath` | none | CSV/JSON inventory to import (schema below). |
| `-DeepFileShareScan` (existing) | off in Fast, on in Deep | **Expensive.** Metadata-only crawl of every user share, bounded by `-MaxDepth` and a per-share time budget (`fileScanShareTimeoutSeconds`, 180 s). |
| `-AttemptSqlIntegratedAuth` (existing) | off | Local Windows integrated auth only, 5 s connect timeout, SELECT-only. |

In the GUI these are on the **Options** tab under *Migration scoping*; the two privacy options
are shown in red, are off by default, and the raw-log option shows a warning when ticked.
Individual collectors are picked on the **Custom Modules** tab as before.

Fleet runs (`tools\Invoke-FleetDiscovery.ps1`) run every applicable new collector on each target
with that mode's defaults. The privacy-sensitive switches are deliberately **not** passed to
fleet targets: collect raw Exchange logs with a single-server run on the server concerned.

## Requirements and permissions

| Need | Why | Without it |
|---|---|---|
| Elevation | SMB sessions/open files, Security log, dcdiag, some registry | Limitations are recorded; everything else still runs |
| Exchange Management Shell snap-in (installed with Exchange or its management tools) | Connectors, certificates, queues, log settings | `Exchange cmdlets unavailable` is recorded; logs are still analysed at default paths |
| `ADSyncAdmins` membership | Entra Connect staging mode / last sync | Staging mode reported as `Unknown` (and a finding says so) |
| SQL `VIEW SERVER STATE` / `VIEW ANY DEFINITION` | Database sizes, file paths, msdb backups | The instance shows `ConnectionStatus=Failed` or partial data, with the error |
| `WebAdministration` module | IIS app-pool identities, auth modes | appcmd fallback gives sites, bindings, apps, vdirs and pools (no identities) |
| DhcpServer / DnsServer modules | DHCP/DNS detail | Role detected, "not enumerable" limitation |

No module or software is ever installed. AD inventory uses plain LDAP reads (no RSAT needed).

## Reading the results honestly

* **Not found** - the collector ran and the thing is not there (e.g. `HostRole` absent for a stack).
* **Not collected** - the collector did not run or could not read the source; see
  `evidence\logs\limitations.txt` and the *Unknowns that matter* list.
* **Logging disabled / logs unavailable / aged out / permission failure** - the SMTP assessment
  names the evidence condition explicitly. `SmtpRelayAssessment.UsageProvenUnused` is always
  `false`: logs can prove use, never non-use.

SMTP relay statuses (`SmtpRelayAssessment.Status`, with every applicable condition in `Conditions`):

| Status | Meaning | Typical recommendation |
|---|---|---|
| Confirmed active SMTP client | Mail was accepted from at least one client in the window | Active relay dependency found; migrate device or application to another SMTP method |
| Possible SMTP client requiring validation | A client connected but no accepted message was seen | Client IP requires identification |
| Protocol logging disabled on the relevant connector | Relay connectors have `ProtocolLoggingLevel None` | Connector logging not sufficient; observation window recommended |
| Logs unavailable / Logs aged out / Permission failure | No usable evidence | Observation window recommended |
| No SMTP usage found in available logs | Logs existed and showed nothing | Observation window recommended (short coverage) or *Safe to continue decommission review* (30+ days, logging on) - never "unused" |

Enabling protocol logging or extending message-tracking retention is a change the client makes;
this toolkit never makes it.

**Application stacks.** Every evidence hit gets an `EvidenceId` (`EV-0001`...) and a confidence:
product-name matches are `Confirmed`, DSN/SQL-name hints `Likely`, name fragments `Possible`.
`AppStackSummary` and the fleet correlation cite the IDs behind each conclusion. Versions are
reported, never judged: differences read *Possible mismatch - vendor validation required*, and
identical numbers still say *confirm compatibility with the vendor*. Add a vendor by adding a stack
to `config\application-stacks.json`; the self-check verifies every dataset/field it names.

**Scan-to-email / scan-to-folder** is never reported as discovered. Multifunction-looking queues
raise a verification item, because those settings live on the device.

**Target capacity** (fleet rollup, needs `-TargetServers`) compares measured source data (SQL +
scanned shares) and memory against each target's free space and RAM. It reports what needs
validating (insufficient known capacity, SQL already present, likely consolidation target, VM
resize may be needed) and never recommends a VM size: the performance data is a snapshot.

## Hypervisor inventory import schema

CSV or JSON array. Column names are case-insensitive; columns not listed are **dropped** (so VM
notes or custom attributes never reach the output).

| RecordType | Columns (`*` = required) |
|---|---|
| `VM` (default) | `VMName*`, `PowerState*`, `HostName`, `Cluster`, `Datastore`, `VMPath`, `GuestOS`, `GuestHostName`, `CpuCount`, `MemoryGB`, `ProvisionedGB`, `UsedGB`, `SnapshotCount`, `IsoAttached`, `Source` |
| `Datastore` | `Name*`, `CapacityGB`, `FreeGB`, `HostName`, `Source` |
| `File` | `Path*`, `Datastore`, `FileType`, `SizeGB`, `IsOrphaned`, `Source` |

Give rows from different systems different `Source` values (`vCenter`, `RMM`); a per-host VM-count
disagreement between sources is reported as a conflict.

## Group Policy references

The ActiveDirectory collector lists every GPO over LDAP (name, enabled state, links - a disabled
link counts as unlinked) and reads its SYSVOL folder **read-only**: Group Policy Preference XML
(drive maps, printers, shortcuts, files, folders, scheduled tasks, ODBC data sources, registry,
environment variables, INI files, services, local groups, network shares), `scripts.ini` /
`psscripts.ini` command lines, folder-redirection `fdeploy*.ini` and `Registry.pol`
(scanned for UNC paths only). Every UNC path or server-valued attribute becomes a
`GpoServerReferences` row; `ReferencesThisServer` is set when it names this server by host
name, FQDN or IP. The fleet rollup resolves the same references against every scanned server and
flags those pointing at retiring servers (deduplicated, because every member sees the same GPOs).

It runs on domain controllers (local SYSVOL) and, in Deep mode, on members (a network read).
Bounds: 1000 GPOs, 5 MB per file, 120 seconds. Never collected: `cpassword`/password attributes
(a non-empty `cpassword` only sets `GpoInventory.HasGppPasswords` and raises RULE-GPO-003)
and script `Parameters` lines. No GPMC or RSAT module is needed, and nothing is written.

## Decommission states

`DecommissionStates` lists which of these apply, with evidence and a next step: *Active VMs
remain*, *Powered-off VMs require disposition*, *Datastore contents require review*, *Hypervisor
inventory conflict*, *Backup dependency remains*, *Monitoring dependency remains*, *SMTP relay
dependency remains*, *Ready for final dependency review*, and - always - *Physical removal or data
destruction requires separate approval*. The best state the tool reports is "ready for final
dependency review", never "safe to power off".

## Risk register

Every finding now carries `RiskCategory` (normalized), `ClientSafe` and `SourceServer` in
addition to its source module, evidence, confidence, project impact and validation question.
Normalized categories: Application compatibility, Database migration, ODBC dependency, IIS
dependency, SMTP relay, Exchange decommissioning, Entra Connect relocation, AD role migration,
DNS cutover, DHCP cutover, File migration, Printer migration, Target capacity, Backup readiness,
Unsupported software, Hypervisor decommissioning, Incomplete discovery, Group Policy dependency. See
[RISK-SCORING.md](RISK-SCORING.md).

## Privacy and safety notes

* No Exchange, SQL, IIS, ODBC, share, AD, DNS, DHCP, time or Entra Connect setting is changed;
  no service is started or stopped; nothing is installed.
* Never collected: passwords, ODBC `PWD`/`UID`/`LastUser` and other credential attributes (dropped,
  not redacted), SQL login hashes, connector credentials, product keys, private keys, SNMP
  community strings, DHCP lease host names/MACs (counts only), print-job document/user names.
* Raw logs are only copied with `-CopyExchangeRawLogs`; full addresses only with
  `-IncludeSensitiveEvidence`. Both are recorded in `limitations.txt` when used.
* The client report shows application-stack names and server roles, and decommission next steps
  for `-ProjectType Decommission` - never IPs, accounts, paths or evidence IDs.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `Exchange cmdlets unavailable` | Run elevated on the Exchange server with the management tools installed; the snap-in loads in a child Windows PowerShell even under PowerShell 7. |
| SMTP status `Logs aged out` | Message-tracking/protocol-log retention is shorter than `-ExchangeLogDays`; ask the client for an observation window. |
| SQL `ConnectionStatus=Failed` | The run account has no SQL login; run as a sysadmin-mapped account or have a DBA supply the inventory. |
| `NtfsAclSummary.ScanStatus=Incomplete` | Access denied on some folders or the per-share time budget was hit; raise `fileScanShareTimeoutSeconds` in `config\default.discovery.json`. |
| Entra Connect staging `Unknown` | Run as a member of ADSyncAdmins. |
| Capacity comparison says `capacity unknown` | The target was not scanned with 1.1.0+ (no `WorkloadProfile`). |
