# Mock Outputs

Illustrative reference snippets of what the toolkit produces, for developers writing
or updating tests. These are **examples**, not fixtures asserted byte-for-byte (real
output varies by server).

## Example dependency-graph.csv row

```
SourceType,SourceName,DependencyType,Target,Evidence,Confidence,SourceDataset,ProjectImpact,ValidationQuestion
Service,AcmeAppSvc,RunsAs,DOMAIN\svc-acme,Service logon account,Confirmed,Services,Cutover Complexity,Who owns this service account?
ConfigFile,C:\Program Files\Acme\app.config,ConnectsTo,SQL01,Redacted connection string,Likely,ConfigDependencyHints,Data Migration,Is SQL01 still the production database server?
```

## Example finding (JSON shape)

```json
{
  "FindingId": "FIND-0001",
  "Category": "Service Account",
  "Severity": "Medium",
  "Confidence": "Confirmed",
  "Title": "Service runs as a domain account",
  "Evidence": "Service 'AcmeAppSvc' (Acme Application Service) runs as 'DOMAIN\\svc-acme'",
  "WhyItMattersForScoping": "Service accounts require password/gMSA coordination during migration...",
  "PotentialProjectImpact": ["Labor", "Cutover Complexity", "Vendor Dependency", "Client Coordination"],
  "SuggestedValidationQuestion": "Who owns the service account used by 'AcmeAppSvc', and is the password or gMSA configuration documented?",
  "SourceModule": "ServicesTasks",
  "SourceDataset": "Services"
}
```

## Example decommission-readiness row

```
Factor,Status,Confidence,Evidence,WhyItMatters,ValidationNeeded
File shares,Present,Confirmed,Non-administrative SMB shares detected.,Users/apps may depend on the server name and UNC paths.,Confirm who uses shares and how they are referenced.
```
