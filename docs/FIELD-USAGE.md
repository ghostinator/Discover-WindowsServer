# Field Usage — Canonical Datasets and Fields

This document is the **contract between collectors and the RiskEngine**. Collector
modules normalize their raw data into named datasets (`Add-DataSet`). The RiskEngine
(`config/risk-rules.json`) and the synthesis/report layers read specific fields by
name. If a collector emits a differently-named field, the corresponding rule will
simply not fire — it will not error, but the finding will be missing.

> **Golden rule:** produce the exact field names and types below. Booleans must be
> real `$true`/`$false` (not the strings "true"/"false").

## How datasets flow

```
Collector.Invoke-DiscoveryCollection  ->  raw objects
Collector.ConvertTo-DiscoveryDatasets  ->  Add-DataSet (normalized rows)
RiskEngine (rules)                     ->  reads dataset fields  ->  Findings
Synthesis (Decommission/Scope/etc.)    ->  reads datasets + findings
Output                                 ->  CSV / JSON / workbook / HTML / Markdown
```

## Canonical datasets and the fields consumers rely on

| Dataset | Owner module | Fields consumed by rules/reports (type) |
|---|---|---|
| `ExecutionContext` | SystemInventory | `IsAdmin`(bool) |
| `OperatingSystem` | SystemInventory | `Caption`, `BuildNumber`, `IsEndOfLifeOrNear`(bool) |
| `PendingReboot` | SystemInventory | `RebootPending`(bool) |
| `RolesFeatures` | RolesFeatures | `Name`, `DisplayName`, `InstallState` (rules regex-match `Name`) |
| `Services` | ServicesTasks | `Name`, `DisplayName`, `StartName`, `PathName`, `PathExists`(bool), `UnquotedPathWithSpaces`(bool), `IsNonMicrosoftAutoStart`(bool) |
| `ScheduledTasks` | ServicesTasks | `TaskName`, `Principal`, `ActionsText`, `LastTaskResult`, `UsesUncPath`(bool), `LastRunFailed`(bool), `RunsAsDomainAccount`(bool) |
| `ApplicationFingerprints` | Applications | `ApplicationName`, `Vendor`, `EvidenceSource`, `Confidence`, `LikelyDependencyType` — **built after all collectors run**, not during the Applications module, because matchers reference `ListeningPorts` (Network), `IisSites` (IIS) and `SqlInstances` (SQL), which are collected later. See `Invoke-DiscoveryFingerprintSynthesis`. |
| `IPConfiguration` | Network | `InterfaceAlias`, `IPv4Address`, `IsStatic`(bool) |
| `ListeningPorts` | Network | `LocalPort`, `Process`, `ServiceName` |
| `FirewallProfiles` | SecurityPosture | `Name`, `Enabled`(bool) |
| `SecurityPosture` | SecurityPosture | `Smb1Enabled`(bool), `RdpEnabledNoNla`(bool), `AnyAvOrEdrDetected`(bool), `LocalAdminCount`(number), `Tls11Enabled`(bool), `GuestAccountEnabled`(bool), `SmbServerSigningRequired`(bool), `LmCompatibilityLevel`(number, nullable — absent ⇒ not explicitly configured, never treated as weak), `NtlmLegacyCompatibilityAllowed`(bool) |
| `LocalAccountsWithNonExpiringPasswords` | SecurityPosture | `Name` — pre-filtered to enabled accounts with a non-expiring password only (`Get-NonExpiringPasswordAccounts`); *(absent/empty ⇒ no finding)* |
| `SensitiveUserRightsGrants` | SecurityPosture | `Right`, `UnexpectedPrincipals`, `AllPrincipals` — pre-filtered to sensitive rights (SeDebugPrivilege and similar) granted beyond the expected well-known-SID baseline (`Get-SensitiveUserRightsGrants`); *(absent/empty ⇒ no finding)* |
| `Volumes` | Storage | `DriveLetter`, `PercentFree`(number), `FreeGB`, `SizeGB` |
| `IscsiVirtualDisks` | Storage | `Path`, `SizeGB`, `Status` |
| `IscsiTargets` | Storage | `TargetName`, `Status`, `LunCount`(number), `LunPaths`, `InitiatorCount`(number), `InitiatorIds` |
| `IscsiInitiatorConnections` | Storage | `TargetNodeAddress`, `PortalAddresses`, `IsConnected`(bool), `IsPersistent`(bool) |
| `SmbShares` | FileShares | `Name`, `Path`, `IsUserShare`(bool) |
| `FileShareSummary` | FileShares | `DeepScanPerformed`(bool) |
| `NtfsAclSummary` | FileShares | `Share`, `Path`, `TotalSizeGB`(number), `FileCount`(number), `TopLevelFolders`(number), `LargeFilesOverThreshold`(number), `OldFilesOverYears`(number), `RecentlyModified30d`(number), `MaxDepthScanned`(number), `RecycleBinIncluded`(bool), `RecycleBinFilesFound`(number), `RecycleBinSizeGB`(number) — *only populated when the deep file-share scan runs.* **`TotalSizeGB` and the file-age counts exclude `$Recycle.Bin` contents unless `-IncludeRecycleBin` is passed**, so they reflect migration payload rather than raw disk usage; the recycled volume is reported separately in `RecycleBinSizeGB`. |
| `Printers` | PrintServer | `Name`, `DriverName`, `PortName`, `Shared`(bool) |
| `SqlInstances` | SQL | `InstanceName`, `ServiceName`, `Version`, `Edition`, `DeepQueryPerformed`(bool), `BinaryPath`, `IsWindowsInternalDatabase`(bool), `XpCmdShellEnabled`(bool), `HostLogicalProcessors`(number — total across all sockets, for per-core Enterprise licensing) |
| `SqlDatabases` | SQL | `Instance`, `Name`, `State`, `RecoveryModel`, `SizeGB`, `LastBackup`, `NoFullBackup`(bool - user DB, msdb readable, no full backup; never set for WID) |
| `OtherDatabaseEngines` | SQL | `Engine`, `Evidence` |
| `OdbcDsns` | SQL | `DsnName`, `Server`, `Database`, `Driver` |
| `IisSites` | IIS | `Name`, `State` |
| `IisAppPools` | IIS | `Name`, `IdentityType`, `UserName`, `UsesCustomIdentity`(bool) |
| `HyperVVMs` | HyperV | `Name`, `State`, `Generation`, `Version`, `VersionBehindHostDefault`(bool), `HasCheckpoints`(bool), `CheckpointCount`, `SwitchNames`, `MemoryMinimumGB`, `MemoryMaximumGB`, `VMPath` |
| `HyperVDisks` | HyperV | `VMName`, `Path`, `PassThrough`(bool), `VhdType`, `MaxSizeGB`, `FileSizeGB`, `ParentPath`, `IsDifferencing`(bool) |
| `ClusterDiscovery` | Cluster | *(any rows ⇒ cluster present)* |
| `ClusterGroups` | Cluster | `Name`, `GroupType`, `OwnerNode`, `State` |
| `ClusterSharedVolumes` | Cluster | `Name`, `OwnerNode`, `State`, `Path` |
| `ClusterNodes` | Cluster | `Name`, `State`, `NodeWeight`, `DynamicWeight` |
| `ClusterNetworks` | Cluster | `Name`, `Address`, `Role`, `State` |
| `RdsDiscovery` | RDS | *(any rows ⇒ RDS present)* |
| `NpsRadiusDiscovery` | NPS_RADIUS | *(any rows ⇒ NPS/RADIUS present)* |
| `Certificates` | Certificates | `Subject`, `NotAfter`, `Thumbprint`, `ExpiringSoon`(bool), `HasPrivateKey`(bool) |
| `CertificateAuthority` | Certificates | `CAName`, `CAType`, `CAServerName`, `ServiceStatus`, `PublicationUrls`, `UrlsReferenceThisServer`(bool) |
| `BackupDiscovery` | BackupDR | `Product`, `Evidence` *(absent/empty ⇒ "no backup detected")* |
| `ConfigDependencyHints` | ConfigDependencyScan | `FilePath`, `IndicatorType`, `RedactedLine` *(absent ⇒ "scan not performed")* |
| `VendorAgents` | VendorAgents | `AgentName`, `Category` |
| `PerformanceSnapshot` | PerformanceSnapshot | `CpuPercent`(number) |
| `Licensing` | Licensing | *(rows ⇒ licensing indicators)* |
| `DomainContext` | ActiveDirectory | `IsDomainController`(bool), `HoldsFsmoRole`(bool), `DomainFunctionalLevel`, `ForestFunctionalLevel` — from `RootDSE` (`domainFunctionality`/`forestFunctionality`), no RSAT needed; `LdapSigningNotEnforced`(bool), `LdapChannelBindingNotEnforced`(bool) — DC-only (`NTDS\Parameters`), always `$false` on a non-DC regardless of registry state |
| `AppliedGroupPolicy` | ActiveDirectory | *(absent/empty ⇒ "GPO data unavailable")* |
| `DnsRecordsReferencingThisServer` | DNS | `ZoneName`, `RecordType`, `RecordName`, `PointsTo` — A/CNAME records (forward zones only) whose target is this server's own hostname/IP |
| `AuditPolicySettings` | EventLogs | `Category`, `Subcategory`, `Setting` — every `auditpol /get /category:*` subcategory, parsed live (`Get-AuditPolicySettings`) |
| `AuditPolicyGaps` | EventLogs | `Category`, `Subcategory`, `Setting` — pre-filtered to a curated critical-subcategory list set to `No Auditing`; *(absent/empty ⇒ no finding)* |

## Rule condition types (safe, explicit)

`config/risk-rules.json` uses only these condition types — there is **no arbitrary
expression evaluation**:

- `datasetNotEmpty` / `datasetMissingOrEmpty`
- `datasetRowCountAtLeast` (`count`)
- `anyRowFieldEquals` / `anyRowFieldNotEquals` (`field`, `value`)
- `anyRowFieldMatches` (`field`, `pattern` — .NET regex)
- `anyRowFieldGreaterThan` / `anyRowFieldLessThan` (`field`, numeric `value`)

Rules with `emitPerRow: true` produce one finding per matching row and expand
`{FieldName}` tokens in `evidenceTemplate` / `suggestedValidationQuestion` from the
matched row.

## "NotDetected" is not "does not exist"

A rule that fires on `datasetMissingOrEmpty` reports that something was **not
detected** — never that it does not exist. Collectors follow the same discipline via
the `Confidence` field (`Confirmed` / `Likely` / `Possible` / `NotDetected` /
`Unknown`).
