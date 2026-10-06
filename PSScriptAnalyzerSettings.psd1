# PSScriptAnalyzer settings for this repo:
#   Invoke-ScriptAnalyzer -Path . -Recurse -Settings .\PSScriptAnalyzerSettings.psd1
# Every Error-severity rule stays on, as does PSAvoidUsingPlainTextForPassword. Where string-only
# credential input is unavoidable (NinjaOne parameters, the fleet stdin hand-off, a store key
# name) it is suppressed in place with a Justification. The rules
# below are excluded because they contradict a deliberate design choice, not to hide bugs.
@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # Fail-soft is the toolkit's core contract: a collector that can't read something records a
        # limitation (or nothing) and moves on, rather than aborting a run on a client server.
        'PSAvoidUsingEmptyCatchBlock'
        # Dataset/collection function names are plural on purpose (Get-DiscoveryDatasets returns many).
        'PSUseSingularNouns'
        # The entry script, GUI launcher and tools are interactive/console tools; Ninja reads Write-Host.
        'PSAvoidUsingWriteHost'
        # Runspace values are passed with AddArgument/param(), not captured from the outer scope.
        'PSUseUsingScopeModifierInNewRunspaces'
        # Contract functions (Test-DiscoveryPrerequisites, ConvertTo-DiscoveryDatasets, ...) must keep
        # the same parameter list across all ~30 modules even when one module ignores a parameter.
        'PSReviewUnusedParameter'
        # The only "state" these New-/Set-/Add- helpers change is the in-memory run context or the
        # run's own output folder; nothing on the server is modified, so -WhatIf would be meaningless.
        'PSUseShouldProcessForStateChangingFunctions'
        # Internal helpers (Redact-, Normalize-, Ensure-, Escape-) are used across every module;
        # renaming them is churn with no user-visible benefit. None are exported from the root module.
        'PSUseApprovedVerbs'
        # Write-Log is the toolkit's own module-scoped logger. The analyzer's command list includes a
        # Write-Log from one PowerShell 6.1 build; neither 5.1 nor 7 ships one, so nothing collides.
        'PSAvoidOverwritingBuiltInCmdlets'
        # Get-WmiObject is the deliberate fallback when CIM is unavailable (PowerShell 4 on 2012 R2).
        'PSAvoidUsingWMICmdlet'
    )
}
