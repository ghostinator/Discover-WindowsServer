<#
.SYNOPSIS
    Optional WPF launcher for Discover-WindowsServer.ps1 - pick options, watch progress,
    and optionally email or upload the result when it's done.

.DESCRIPTION
    This is a convenience layer, not a replacement for the CLI: it builds a normal
    Discover-WindowsServer.ps1 command line from what you pick, launches it as a separate
    process, and polls the run's own evidence\status\progress.json (written by the engine
    for exactly this purpose - see Update-StatusFile in modules\Core\Core.psm1) to show
    live progress. The underlying engine's safety contract is unchanged: still strictly
    read-only, still writes only inside its own output folder.

    Many target servers run Server Core and have no desktop at all - this window is not how
    the toolkit runs there, and never will be. Use Discover-WindowsServer.ps1 directly on
    those; this launcher is for the boxes (or the workstation you RDP from) that have one.

    WPF needs a Single-Threaded Apartment. If you didn't launch this with -Sta, it
    transparently relaunches itself in an STA child process once - you don't need to
    remember the flag.

    Delivery (the "Delivery" tab) is entirely optional and dot-sources
    tools\Send-DiscoveryOutput.ps1 to reuse its four delivery methods and its DPAPI
    credential store - nothing about credential handling is reimplemented here.

    Build-DiscoveryArgumentList below is deliberately a pure function - given plain values,
    not WPF control objects - both so it's independently unit-testable (Pester dot-sources
    this file; see tests\Pester\Discover-WindowsServer-GUI.Tests.ps1) and so the "read what's
    on screen" and "build the command line from it" concerns stay separate. Everything that
    touches WPF (STA relaunch, Add-Type, the XAML, event wiring, ShowDialog) is gated behind
    the same "only run when invoked directly, not dot-sourced" guard
    tools\Send-DiscoveryOutput.ps1 uses - critical here specifically because the STA-relaunch
    branch calls `exit`, which would kill a test runner's entire process if it ever ran while
    this file was being dot-sourced for its functions.

.EXAMPLE
    .\Discover-WindowsServer-GUI.ps1
#>
[CmdletBinding()]
param()

function Build-DiscoveryArgumentList {
    <#
        Pure: builds the Discover-WindowsServer.ps1 argument list from plain values, with no
        dependency on any WPF control. Numeric values are passed as their raw text (as a
        TextBox would hold them) and silently omitted if not parseable, rather than the
        engine seeing a bad value - the engine then just uses its own built-in default.
    #>
    param(
        [Parameter(Mandatory)][string]$EngineScriptPath,
        [Parameter(Mandatory)][string]$Mode,
        [Parameter(Mandatory)][string]$ProjectType,
        [Parameter(Mandatory)][string]$ComplianceLens,
        [Parameter(Mandatory)][string]$OutputRoot,
        [string[]]$IncludedModules = @(),
        [bool]$DeepFileShareScan,
        [bool]$FullEventLogExport,
        [bool]$IncludeConfigDependencyScan,
        [bool]$IncludeUserProfiles,
        [bool]$IncludeRecycleBin,
        [bool]$IncludeWindowsFolder,
        [bool]$AttemptSqlIntegratedAuth,
        [bool]$GenerateEvidenceManifest,
        [bool]$SkipZip,
        [bool]$VerboseLogging,
        [string]$MaxDepthText,
        [string]$LargeFileThresholdGBText,
        [string]$OldFileYearsText,
        [string]$EventLogDaysText,
        [string]$MaxEventSamplesText,
        [string]$ConfigScanMaxFileSizeMBText,
        [switch]$WhatIfOnly
    )
    $argList = [System.Collections.Generic.List[string]]::new()
    $argList.Add('-NoProfile'); $argList.Add('-File'); $argList.Add("`"$EngineScriptPath`"")
    $argList.Add('-Mode'); $argList.Add($Mode)
    $argList.Add('-ProjectType'); $argList.Add($ProjectType)
    $argList.Add('-ComplianceLens'); $argList.Add($ComplianceLens)
    $argList.Add('-OutputRoot'); $argList.Add("`"$OutputRoot`"")

    if ($Mode -eq 'Custom' -and $IncludedModules.Count -gt 0) {
        $argList.Add('-IncludeModules'); $argList.Add(($IncludedModules -join ','))
    }

    if ($DeepFileShareScan)           { $argList.Add('-DeepFileShareScan') }
    if ($FullEventLogExport)          { $argList.Add('-FullEventLogExport') }
    if ($IncludeConfigDependencyScan) { $argList.Add('-IncludeConfigDependencyScan') }
    if ($IncludeUserProfiles)         { $argList.Add('-IncludeUserProfiles') }
    if ($IncludeRecycleBin)           { $argList.Add('-IncludeRecycleBin') }
    if ($IncludeWindowsFolder)        { $argList.Add('-IncludeWindowsFolder') }
    if ($AttemptSqlIntegratedAuth)    { $argList.Add('-AttemptSqlIntegratedAuth') }
    if ($GenerateEvidenceManifest)    { $argList.Add('-GenerateEvidenceManifest') }
    if ($SkipZip)                     { $argList.Add('-SkipZip') }
    if ($VerboseLogging)              { $argList.Add('-VerboseLogging') }

    $numericPairs = @(
        @{ Text = $MaxDepthText;                Arg = '-MaxDepth' }
        @{ Text = $LargeFileThresholdGBText;     Arg = '-LargeFileThresholdGB' }
        @{ Text = $OldFileYearsText;             Arg = '-OldFileYears' }
        @{ Text = $EventLogDaysText;             Arg = '-EventLogDays' }
        @{ Text = $MaxEventSamplesText;          Arg = '-MaxEventSamplesPerLog' }
        @{ Text = $ConfigScanMaxFileSizeMBText;  Arg = '-ConfigScanMaxFileSizeMB' }
    )
    foreach ($pair in $numericPairs) {
        $val = 0
        if ([int]::TryParse($pair.Text, [ref]$val)) { $argList.Add($pair.Arg); $argList.Add([string]$val) }
    }

    if ($WhatIfOnly) { $argList.Add('-WhatIf') }
    return ,@($argList.ToArray())
}

function ConvertTo-DiscoveryLauncherScript {
    <#
        Takes a flat CLI-style argument list (as Build-DiscoveryArgumentList produces - starting
        with -NoProfile -File "<scriptPath>" followed by the target script's own arguments) and
        writes a temp .ps1 "launcher" that invokes that script with those arguments as real,
        parsed PowerShell syntax instead. Returns the launcher's path.

        WHY THIS EXISTS: launching a script via `-File` treats every trailing token as a plain,
        literal string - PowerShell does NOT re-parse it as script syntax the way it would
        something typed at an interactive prompt. Confirmed live: `pwsh -File s.ps1 -Foo a,b,c`
        binds a ONE-element array holding the literal text "a,b,c", not three elements, for a
        `[string[]]$Foo` parameter - the exact shape Build-DiscoveryArgumentList produces for
        -IncludeModules. That silently broke Custom Mode for any 2+ module selection (it always
        "worked" for exactly one checked module, which is almost certainly why nobody had caught
        it - and why Fleet Discovery's own -TargetComputerNames hit the identical bug the first
        time an operator picked more than one server). $ArrayParameterNames lists which -Flag
        tokens in $ArgList are followed by a comma-joined value that needs to become a real
        @('a','b','c') literal instead of one glued string, once it's inside a real script file
        that gets properly parsed rather than passed as raw trailing command-line text.
    #>
    param(
        [Parameter(Mandatory)][string[]]$ArgList,
        [string[]]$ArrayParameterNames = @()
    )
    $fileIndex = [array]::IndexOf($ArgList, '-File')
    if ($fileIndex -lt 0 -or $fileIndex + 1 -ge $ArgList.Count) { throw 'ArgList must contain -File "<scriptPath>".' }
    $scriptPath = $ArgList[$fileIndex + 1].Trim('"')
    $realArgs = @($ArgList[($fileIndex + 2)..($ArgList.Count - 1)])

    $quote = { param($s) "'" + ([string]$s).Trim('"').Replace("'", "''") + "'" }
    $parts = [System.Collections.Generic.List[string]]::new()
    $i = 0
    while ($i -lt $realArgs.Count) {
        $token = $realArgs[$i]
        if ($token.StartsWith('-') -and ($ArrayParameterNames -contains $token.Substring(1)) -and ($i + 1 -lt $realArgs.Count)) {
            $items = @($realArgs[$i + 1] -split ',')
            $parts.Add($token)
            $parts.Add('@(' + (($items | ForEach-Object { & $quote $_ }) -join ',') + ')')
            $i += 2
            continue
        }
        if ($token.StartsWith('-')) { $parts.Add($token) } else { $parts.Add((& $quote $token)) }
        $i++
    }
    $command = "& $(& $quote $scriptPath) " + ($parts -join ' ')
    # NOT self-deleting - cleanup is the caller's job (see the completion-timer code at both call
    # sites), which is what actually matters here: both the single-server and Fleet launches now
    # run their child process under THIS SAME identity (Fleet stopped using
    # Start-Process -Credential - see Invoke-FleetDiscovery.ps1's header for why), so there's no
    # cross-account permission question to design around anymore. The current user's own %TEMP%
    # is fine.
    $launcherDir = [System.IO.Path]::GetTempPath()
    if (-not (Test-Path -LiteralPath $launcherDir)) { New-Item -ItemType Directory -Path $launcherDir -Force | Out-Null }
    $launcherPath = Join-Path $launcherDir ("discover-launch-{0}.ps1" -f ([guid]::NewGuid().ToString('N')))
    Set-Content -LiteralPath $launcherPath -Value $command -Encoding UTF8
    return $launcherPath
}

function Get-DiscoveryModuleSummary {
    <#
        Pure: pulls DisplayName/Category/DefaultInFast/DefaultInDeep out of a module's own
        Get-DiscoveryModuleMetadata block (see modules\*\*.psm1) so the Custom Modules tab can
        show Fast/Deep membership for comparison without importing all ~30 module files (that's
        what the real engine's Get-AllModuleMetadata does, and it needs a full run Context to do
        it - overkill just to read a picklist). Takes the module's raw source text, not a path,
        so it's testable with plain strings.

        Returns $null when the file has no such function (Core, Output - infra, not collectors)
        or when the module declares itself synthesis-only (IsSynthesis=$true - RiskEngine,
        ReportBuilder, etc. run unconditionally every time and are never a valid Custom Mode
        -IncludeModules target; see $synthesisOrder in Discover-WindowsServer.psm1's
        Invoke-Discovery, which never filters that list by Include/Exclude at all).
    #>
    param([Parameter(Mandatory)][string]$ModuleName, [Parameter(Mandatory)][string]$ModuleSource)

    if ($ModuleSource -notmatch '(?s)function\s+Get-DiscoveryModuleMetadata\s*\{(?<body>.*?)\n\}') { return $null }
    $body = $Matches['body']
    if ($body -match 'IsSynthesis\s*=\s*\$true') { return $null }

    $displayName = if ($body -match "DisplayName\s*=\s*'([^']*)'") { $Matches[1] } else { $ModuleName }
    $category    = if ($body -match "Category\s*=\s*'([^']*)'")    { $Matches[1] } else { 'Other' }
    [pscustomobject]@{
        ModuleName    = $ModuleName
        DisplayName   = $displayName
        Category      = $category
        DefaultInFast = [bool]($body -match 'DefaultInFast\s*=\s*\$true')
        DefaultInDeep = [bool]($body -match 'DefaultInDeep\s*=\s*\$true')
    }
}

# Everything below only runs when this file is executed directly (.\Discover-WindowsServer-GUI.ps1
# or pwsh -File ...) - not when dot-sourced, which is how Pester reaches Build-DiscoveryArgumentList
# above without ever touching WPF, STA, or (critically) the `exit` in the STA-relaunch branch below.
if ($MyInvocation.InvocationName -ne '.') {

#region STA relaunch (WPF requirement) -----------------------------------------

if ([System.Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
    $hostExe = (Get-Process -Id $PID).Path
    Start-Process -FilePath $hostExe -ArgumentList @('-NoProfile', '-Sta', '-File', "`"$PSCommandPath`"") -Wait
    exit
}

#endregion

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms

$scriptRoot = $PSScriptRoot
if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }
$engineScript   = Join-Path $scriptRoot 'Discover-WindowsServer.ps1'
$deliveryScript = Join-Path $scriptRoot 'tools\Send-DiscoveryOutput.ps1'
$fleetScript    = Join-Path $scriptRoot 'tools\Invoke-FleetDiscovery.ps1'
$fleetRollupScript = Join-Path $scriptRoot 'tools\Merge-FleetDiscoveryResults.ps1'
$driftScript    = Join-Path $scriptRoot 'tools\Compare-DiscoveryRuns.ps1'

# Reuses Send-DiscoveryOutput.ps1's functions (credential store, all four senders) without
# duplicating any of that logic. Dot-sourcing only defines functions - see that script's own
# "only run when invoked directly" guard.
. $deliveryScript
# Same reasoning for the Fleet tab: dot-sourcing pulls in Get-AdServerCandidate/
# Invoke-SubnetWinRmScan/Merge-DiscoveryCandidate/ConvertTo-CidrHostRange for the in-process
# picker, without running that file's own remote-execution loop (guarded the same way).
. $fleetScript
. $fleetRollupScript
# Compare-DiscoveryRuns.ps1 itself dot-sources $fleetRollupScript again at its own top level -
# harmless (defines the same functions a second time), not worth special-casing here.
. $driftScript

#region XAML --------------------------------------------------------------------

[xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Discover-WindowsServer" Height="640" Width="760" MinHeight="480" MinWidth="620" WindowStartupLocation="CenterScreen">
  <Grid Margin="10">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <TextBlock Grid.Row="0" Text="Ultimate Modular Windows Server Discovery Toolkit" FontSize="16" FontWeight="Bold" Margin="0,0,0,10"/>

    <TabControl Grid.Row="1" Name="MainTabs">
      <TabItem Header="Basics">
        <StackPanel Margin="10">
          <Label Content="Mode"/>
          <ComboBox Name="ModeCombo" SelectedIndex="0">
            <ComboBoxItem Content="Fast"/>
            <ComboBoxItem Content="Deep"/>
            <ComboBoxItem Content="Custom"/>
          </ComboBox>

          <Label Content="Project type" Margin="0,10,0,0"/>
          <ComboBox Name="ProjectTypeCombo" SelectedIndex="0">
            <ComboBoxItem Content="GeneralDiscovery"/>
            <ComboBoxItem Content="ServerRefresh"/>
            <ComboBoxItem Content="HyperVRefresh"/>
            <ComboBoxItem Content="Decommission"/>
            <ComboBoxItem Content="AzureMigration"/>
            <ComboBoxItem Content="AppMigration"/>
            <ComboBoxItem Content="CMMCReadiness"/>
          </ComboBox>

          <Label Content="Compliance lens" Margin="0,10,0,0"/>
          <ComboBox Name="ComplianceLensCombo" SelectedIndex="0">
            <ComboBoxItem Content="None"/>
            <ComboBoxItem Content="CMMC"/>
            <ComboBoxItem Content="GeneralSecurity"/>
          </ComboBox>

          <Label Content="Output folder" Margin="0,10,0,0"/>
          <DockPanel>
            <Button Name="BrowseOutputButton" Content="Browse..." DockPanel.Dock="Right" Width="80" Margin="5,0,0,0"/>
            <TextBox Name="OutputRootBox" Text="C:\Temp"/>
          </DockPanel>
        </StackPanel>
      </TabItem>

      <TabItem Header="Options">
        <ScrollViewer VerticalScrollBarVisibility="Auto">
          <StackPanel Margin="10">
            <CheckBox Name="DeepFileShareScanCheck" Content="Deep file share scan" Margin="0,4"/>
            <CheckBox Name="FullEventLogExportCheck" Content="Full event log export" Margin="0,4"/>
            <CheckBox Name="IncludeConfigDependencyScanCheck" Content="Scan config files for hardcoded dependencies" Margin="0,4"/>
            <CheckBox Name="IncludeUserProfilesCheck" Content="Include user profile folders" Margin="0,4"/>
            <CheckBox Name="IncludeRecycleBinCheck" Content="Include recycle bin" Margin="0,4"/>
            <CheckBox Name="IncludeWindowsFolderCheck" Content="Include C:\Windows folder" Margin="0,4"/>
            <CheckBox Name="AttemptSqlIntegratedAuthCheck" Content="Attempt SQL integrated-auth enumeration (Deep database inventory)" Margin="0,4"/>
            <CheckBox Name="GenerateEvidenceManifestCheck" Content="Generate evidence manifest (SHA-256 hashes)" Margin="0,4"/>
            <CheckBox Name="SkipZipCheck" Content="Skip building the zip archive" Margin="0,4"/>
            <CheckBox Name="VerboseLoggingCheck" Content="Verbose logging" Margin="0,4"/>

            <TextBlock Text="Tuning" FontWeight="Bold" Margin="0,14,0,4"/>
            <Grid>
              <Grid.ColumnDefinitions>
                <ColumnDefinition Width="220"/>
                <ColumnDefinition Width="100"/>
              </Grid.ColumnDefinitions>
              <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
              </Grid.RowDefinitions>
              <Label Grid.Row="0" Grid.Column="0" Content="Max share scan depth"/>
              <TextBox  Grid.Row="0" Grid.Column="1" Name="MaxDepthBox" Text="3"/>
              <Label Grid.Row="1" Grid.Column="0" Content="Large file threshold (GB)"/>
              <TextBox  Grid.Row="1" Grid.Column="1" Name="LargeFileThresholdGBBox" Text="5"/>
              <Label Grid.Row="2" Grid.Column="0" Content="Old file age (years)"/>
              <TextBox  Grid.Row="2" Grid.Column="1" Name="OldFileYearsBox" Text="7"/>
              <Label Grid.Row="3" Grid.Column="0" Content="Event log days"/>
              <TextBox  Grid.Row="3" Grid.Column="1" Name="EventLogDaysBox" Text="14"/>
              <Label Grid.Row="4" Grid.Column="0" Content="Max event samples per log"/>
              <TextBox  Grid.Row="4" Grid.Column="1" Name="MaxEventSamplesBox" Text="50"/>
              <Label Grid.Row="5" Grid.Column="0" Content="Config scan max file size (MB)"/>
              <TextBox  Grid.Row="5" Grid.Column="1" Name="ConfigScanMaxFileSizeMBBox" Text="10"/>
            </Grid>
          </StackPanel>
        </ScrollViewer>
      </TabItem>

      <TabItem Header="Custom Modules">
        <DockPanel Margin="10">
          <TextBlock DockPanel.Dock="Top" TextWrapping="Wrap" Margin="0,0,0,4"
                     Text="Only editable when Mode = Custom (Basics tab). Check the modules to include; if nothing is checked, Custom mode falls back to Fast."/>
          <TextBlock DockPanel.Dock="Top" TextWrapping="Wrap" Margin="0,0,0,8" FontStyle="Italic" Foreground="Gray"
                     Text="Picking Fast or Deep up on the Basics tab checks the boxes below to preview what that mode runs, so you can compare them before switching to Custom to fine-tune."/>
          <ScrollViewer VerticalScrollBarVisibility="Auto">
            <ItemsControl Name="ModuleListItems">
              <ItemsControl.ItemsPanel>
                <ItemsPanelTemplate>
                  <UniformGrid Columns="3"/>
                </ItemsPanelTemplate>
              </ItemsControl.ItemsPanel>
            </ItemsControl>
          </ScrollViewer>
        </DockPanel>
      </TabItem>

      <TabItem Header="Delivery">
        <StackPanel Margin="10">
          <TextBlock TextWrapping="Wrap" Margin="0,0,0,10"
                     Text="Optional. Discovery output contains real client infrastructure detail - only send it where you mean to. Nothing here changes the discovery run itself; it happens afterward, against the finished run's zip in its archive\ folder."/>
          <Label Content="After the run finishes"/>
          <ComboBox Name="DeliveryMethodCombo" SelectedIndex="0">
            <ComboBoxItem Content="None (just save locally)"/>
            <ComboBoxItem Content="Smtp"/>
            <ComboBoxItem Content="Smtp2Go"/>
            <ComboBoxItem Content="SendGrid"/>
            <ComboBoxItem Content="Postal"/>
            <ComboBoxItem Content="Upload"/>
          </ComboBox>

          <StackPanel Name="EmailFieldsPanel" Margin="0,10,0,0">
            <Label Content="From"/>
            <TextBox Name="FromBox"/>
            <Label Content="To (comma-separated)" Margin="0,6,0,0"/>
            <TextBox Name="ToBox"/>
            <Label Content="Subject" Margin="0,6,0,0"/>
            <TextBox Name="SubjectBox" Text="Discover-WindowsServer output"/>
          </StackPanel>

          <StackPanel Name="SmtpFieldsPanel" Margin="0,10,0,0">
            <Label Content="SMTP server"/>
            <TextBox Name="SmtpServerBox"/>
            <Label Content="Port" Margin="0,6,0,0"/>
            <TextBox Name="SmtpPortBox" Text="587"/>
            <CheckBox Name="UseSslCheck" Content="Use SSL/TLS" IsChecked="True" Margin="0,6,0,0"/>
          </StackPanel>

          <StackPanel Name="PostalFieldsPanel" Margin="0,10,0,0">
            <Label Content="Postal server URL"/>
            <TextBox Name="PostalServerUrlBox"/>
          </StackPanel>

          <StackPanel Name="UploadFieldsPanel" Margin="0,10,0,0">
            <Label Content="Upload URL"/>
            <TextBox Name="UploadUrlBox"/>
            <Label Content="Method" Margin="0,6,0,0"/>
            <ComboBox Name="UploadMethodCombo" SelectedIndex="0">
              <ComboBoxItem Content="Put"/>
              <ComboBoxItem Content="Post"/>
            </ComboBox>
          </StackPanel>

          <StackPanel Name="CredentialFieldsPanel" Margin="0,10,0,0">
            <Label Content="Credential name (used to save/reuse it - e.g. 'SendGrid')"/>
            <DockPanel>
              <Button Name="SetCredentialButton" Content="Set / update credential..." DockPanel.Dock="Right" Width="170" Margin="5,0,0,0"/>
              <TextBox Name="CredentialNameBox"/>
            </DockPanel>
            <TextBlock Name="CredentialStatusText" Margin="0,4,0,0" FontStyle="Italic" Foreground="Gray"/>
          </StackPanel>
        </StackPanel>
      </TabItem>

      <TabItem Header="Fleet">
        <DockPanel Margin="10">
          <TextBlock DockPanel.Dock="Top" TextWrapping="Wrap" Margin="0,0,0,8"
                     Text="Run discovery against several servers at once: query Active Directory and/or scan a subnet for candidates, pick which ones, then run. Uses the Mode/ProjectType/Compliance lens selected on the Basics tab. Needs WinRM already reachable on each target and a domain admin credential with rights to run there - see the option below if a target doesn't have WinRM enabled yet."/>

          <StackPanel DockPanel.Dock="Top" Margin="0,0,0,8">
            <Label Content="Domain credential (held in memory only for this session - never saved to disk)"/>
            <DockPanel>
              <Button Name="SetFleetCredentialButton" Content="Set credential..." DockPanel.Dock="Left" Width="130"/>
              <Button Name="ClearFleetCredentialButton" Content="Clear" DockPanel.Dock="Left" Width="70" Margin="6,0,0,0"/>
              <TextBlock Name="FleetCredentialStatusText" Margin="10,0,0,0" VerticalAlignment="Center" FontStyle="Italic" Foreground="Gray" Text="Not set."/>
            </DockPanel>
          </StackPanel>

          <StackPanel DockPanel.Dock="Top" Margin="0,0,0,8">
            <Label Content="Find servers"/>
            <DockPanel Margin="0,0,0,4">
              <Button Name="QueryAdButton" Content="Query Active Directory" DockPanel.Dock="Left" Width="160"/>
              <TextBlock Text="  or scan a subnet:" DockPanel.Dock="Left" VerticalAlignment="Center" Margin="10,0,0,0"/>
              <Button Name="ScanSubnetButton" Content="Scan" DockPanel.Dock="Right" Width="70" Margin="6,0,0,0"/>
              <TextBox Name="FleetCidrBox" Text="10.0.0.0/24" Margin="6,0,0,0"/>
            </DockPanel>
          </StackPanel>

          <StackPanel DockPanel.Dock="Top" Margin="0,0,0,8">
            <CheckBox Name="EnableWinRmCheck" Content="Enable WinRM on unreachable targets, then disable it again right after each one finishes" IsChecked="False"/>
            <TextBlock TextWrapping="Wrap" Margin="20,2,0,0" FontStyle="Italic" Foreground="Gray"
                       Text="Off by default. Bootstraps WinRM over WMI/DCOM (not WinRM itself - it isn't reachable yet, that's the point), which is also a known lateral-movement technique signature security monitoring tools watch for. Fine for your own lab; on a real client engagement, this is worth mentioning in the scoping conversation before you turn it on. Never touches a target that's already reachable, and reverts (service stopped, firewall rule closed) immediately after that target's results are pulled back."/>
          </StackPanel>

          <StackPanel DockPanel.Dock="Top" Orientation="Horizontal" Margin="0,0,0,8">
            <Label Content="Run up to" Padding="0,5,4,5" VerticalAlignment="Center"/>
            <ComboBox Name="FleetConcurrencyCombo" Width="60" SelectedIndex="2" VerticalAlignment="Center">
              <ComboBoxItem Content="1"/>
              <ComboBoxItem Content="2"/>
              <ComboBoxItem Content="3"/>
              <ComboBoxItem Content="5"/>
              <ComboBoxItem Content="10"/>
              <ComboBoxItem Content="20"/>
            </ComboBox>
            <TextBlock Text="at once" Padding="4,5,0,5" VerticalAlignment="Center"/>
            <TextBlock Text="  (each one opens its own remote session and staging copy from this machine - higher isn't always faster)"
                       FontStyle="Italic" Foreground="Gray" VerticalAlignment="Center" TextWrapping="Wrap"/>
          </StackPanel>

          <StackPanel DockPanel.Dock="Bottom" Margin="0,8,0,0">
            <ProgressBar Name="FleetProgressBar" Height="18" Minimum="0" Maximum="100"/>
            <TextBlock Name="FleetStatusText" Margin="0,4,0,8" TextWrapping="Wrap" Text="Set a credential, then find servers below."/>
            <DockPanel>
              <Button Name="RunFleetButton" Content="Run on Selected" DockPanel.Dock="Left" Width="130" FontWeight="Bold"/>
              <Button Name="CompareRunsButton" Content="Compare vs another engagement..." DockPanel.Dock="Right" Width="200" IsEnabled="False" Margin="6,0,0,0"/>
              <Button Name="BuildRollupButton" Content="Build Rollup Report" DockPanel.Dock="Right" Width="150" IsEnabled="False"/>
              <TextBlock/>
            </DockPanel>
          </StackPanel>

          <DockPanel DockPanel.Dock="Top" Margin="0,0,0,4">
            <Button Name="SelectAllCandidatesButton" Content="Select all" DockPanel.Dock="Left" Width="80"/>
            <Button Name="SelectNoCandidatesButton" Content="Select none" DockPanel.Dock="Left" Width="80" Margin="6,0,0,0"/>
          </DockPanel>

          <ScrollViewer VerticalScrollBarVisibility="Auto">
            <ItemsControl Name="FleetCandidateItems">
              <ItemsControl.ItemsPanel>
                <ItemsPanelTemplate>
                  <UniformGrid Columns="2"/>
                </ItemsPanelTemplate>
              </ItemsControl.ItemsPanel>
            </ItemsControl>
          </ScrollViewer>
        </DockPanel>
      </TabItem>

      <TabItem Header="Branding">
        <StackPanel Margin="10">
          <TextBlock TextWrapping="Wrap" Margin="0,0,0,10"
                     Text="Puts your company's name, accent color and logo on every generated report (internal and client, single-server and fleet). Saved to %ProgramData%\Discover-WindowsServer\branding (outside the toolkit folder, so updates keep it) - the engine reads it from there directly, so this applies to every future run, not just the next one."/>

          <Label Content="Company / brand name"/>
          <TextBox Name="BrandNameBox"/>

          <Label Content="Accent color (hex, e.g. #1F4E79)" Margin="0,10,0,0"/>
          <DockPanel>
            <Rectangle Name="AccentPreviewSwatch" DockPanel.Dock="Right" Width="26" Height="26" Margin="8,0,0,0" Stroke="Gray" StrokeThickness="1"/>
            <TextBox Name="AccentColorBox"/>
          </DockPanel>

          <Label Content="Logo" Margin="0,10,0,0"/>
          <DockPanel>
            <Button Name="ChooseLogoButton" Content="Choose logo..." DockPanel.Dock="Left" Width="120"/>
            <Button Name="ClearLogoButton" Content="Remove logo" DockPanel.Dock="Left" Width="100" Margin="6,0,0,0"/>
            <TextBlock Name="LogoStatusText" Margin="10,0,0,0" VerticalAlignment="Center" FontStyle="Italic" Foreground="Gray" Text="No logo set."/>
          </DockPanel>
          <Image Name="LogoPreviewImage" Height="50" HorizontalAlignment="Left" Margin="0,8,0,0"/>

          <DockPanel Margin="0,16,0,0">
            <Button Name="SaveBrandingButton" Content="Save branding settings" DockPanel.Dock="Left" Width="170" FontWeight="Bold"/>
          </DockPanel>
          <TextBlock Name="BrandingStatusText" Margin="0,6,0,0" TextWrapping="Wrap" FontStyle="Italic" Foreground="Gray"/>
        </StackPanel>
      </TabItem>
    </TabControl>

    <StackPanel Grid.Row="2" Orientation="Horizontal" Margin="0,8,0,0">
      <CheckBox Name="AutoOpenReportCheck" Content="Open report automatically when finished" VerticalAlignment="Center" IsChecked="True"/>
      <ComboBox Name="AutoOpenReportCombo" Width="150" Margin="10,0,0,0" SelectedIndex="0">
        <ComboBoxItem Content="Internal report"/>
        <ComboBoxItem Content="Client report"/>
      </ComboBox>
    </StackPanel>
    <Grid Grid.Row="3" Margin="0,10,0,0">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="Auto"/>
        <ColumnDefinition Width="Auto"/>
      </Grid.ColumnDefinitions>
      <StackPanel Grid.Column="0" VerticalAlignment="Center" Margin="0,0,12,0">
        <ProgressBar Name="RunProgressBar" Height="18" Minimum="0" Maximum="100"/>
        <TextBlock Name="StatusText" Margin="0,4,0,0" TextTrimming="CharacterEllipsis" Text="Ready."/>
      </StackPanel>
      <Button Grid.Column="1" Name="WhatIfButton" Content="Preview (-WhatIf)" Width="130" Margin="0,0,8,0"/>
      <Button Grid.Column="2" Name="RunButton" Content="Run" Width="100" FontWeight="Bold"/>
    </Grid>
  </Grid>
</Window>
'@

#endregion

$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [Windows.Markup.XamlReader]::Load($reader)

# Pull every named element into a flat table instead of one $window.FindName(...) call per
# control - this file has ~30 named controls and repeating FindName that many times invites
# a typo that only shows up at runtime.
$ui = @{}
foreach ($name in @(
    'ModeCombo', 'ProjectTypeCombo', 'ComplianceLensCombo', 'OutputRootBox', 'BrowseOutputButton',
    'DeepFileShareScanCheck', 'FullEventLogExportCheck', 'IncludeConfigDependencyScanCheck', 'IncludeUserProfilesCheck',
    'IncludeRecycleBinCheck', 'IncludeWindowsFolderCheck', 'AttemptSqlIntegratedAuthCheck', 'GenerateEvidenceManifestCheck',
    'SkipZipCheck', 'VerboseLoggingCheck', 'MaxDepthBox', 'LargeFileThresholdGBBox', 'OldFileYearsBox', 'EventLogDaysBox',
    'MaxEventSamplesBox', 'ConfigScanMaxFileSizeMBBox', 'ModuleListItems',
    'DeliveryMethodCombo', 'EmailFieldsPanel', 'SmtpFieldsPanel', 'PostalFieldsPanel', 'UploadFieldsPanel', 'CredentialFieldsPanel',
    'FromBox', 'ToBox', 'SubjectBox', 'SmtpServerBox', 'SmtpPortBox', 'UseSslCheck', 'PostalServerUrlBox',
    'UploadUrlBox', 'UploadMethodCombo', 'CredentialNameBox', 'SetCredentialButton', 'CredentialStatusText',
    'RunProgressBar', 'StatusText', 'WhatIfButton', 'RunButton', 'MainTabs',
    'AutoOpenReportCheck', 'AutoOpenReportCombo',
    'SetFleetCredentialButton', 'ClearFleetCredentialButton', 'FleetCredentialStatusText',
    'QueryAdButton', 'ScanSubnetButton', 'FleetCidrBox', 'FleetCandidateItems', 'EnableWinRmCheck',
    'FleetConcurrencyCombo', 'SelectAllCandidatesButton', 'SelectNoCandidatesButton',
    'FleetProgressBar', 'FleetStatusText', 'RunFleetButton', 'BuildRollupButton', 'CompareRunsButton',
    'BrandNameBox', 'AccentColorBox', 'AccentPreviewSwatch', 'ChooseLogoButton', 'ClearLogoButton',
    'LogoStatusText', 'LogoPreviewImage', 'SaveBrandingButton', 'BrandingStatusText'
)) { $ui[$name] = $window.FindName($name) }

#region Populate dynamic content -------------------------------------------------

# Fast/Deep's real tuning, straight from the same files the engine itself reads
# (Get-DiscoveryConfigBundle in modules\Core\Core.psm1) - so the Basics-tab Mode combo can
# preview both what modules run (below) and how thoroughly (Update-OptionsForMode) without
# duplicating those numbers here. Custom has no such file; $modeConfigs['Custom'] is just absent.
$modeConfigs = @{}
foreach ($name in 'Fast', 'Deep') {
    $path = Join-Path $scriptRoot ("config\{0}.discovery.json" -f $name.ToLowerInvariant())
    if (Test-Path -LiteralPath $path) { $modeConfigs[$name] = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json }
}

# Custom-mode module checklist: read straight from modules\* so this never drifts out of
# sync with the actual collector set (no hardcoded list to maintain here). Modules with no
# Get-DiscoveryModuleMetadata (Core, Output) or that are synthesis-only (RiskEngine,
# ReportBuilder, ...) are skipped - see Get-DiscoveryModuleSummary above for why those aren't
# valid Custom Mode picks in the first place. Grouped by Category, then tiled into columns by
# the UniformGrid in the XAML instead of one long single-column list.
$moduleCheckboxes = [System.Collections.Generic.List[object]]::new()
$moduleSummaries = [System.Collections.Generic.List[object]]::new()
foreach ($dir in (Get-ChildItem -LiteralPath (Join-Path $scriptRoot 'modules') -Directory | Sort-Object Name)) {
    $psm1Path = Join-Path $dir.FullName ("{0}.psm1" -f $dir.Name)
    if (-not (Test-Path -LiteralPath $psm1Path)) { continue }
    $summary = Get-DiscoveryModuleSummary -ModuleName $dir.Name -ModuleSource (Get-Content -LiteralPath $psm1Path -Raw)
    if ($summary) { $moduleSummaries.Add($summary) }
}
foreach ($summary in ($moduleSummaries | Sort-Object Category, DisplayName)) {
    $cb = New-Object System.Windows.Controls.CheckBox
    $cb.Content = $summary.DisplayName
    # Tag is what Start-DiscoveryRun reads back into -IncludeModules - has to be the real
    # module name, not the display label. The Default* NoteProperties are read by
    # Update-ModuleCheckboxesForMode below to preview Fast/Deep's picks by (un)checking the
    # box - not by printing a tag on the label, which is the whole point of checking it.
    $cb.Tag = $summary.ModuleName
    Add-Member -InputObject $cb -NotePropertyName DefaultInFast -NotePropertyValue $summary.DefaultInFast
    Add-Member -InputObject $cb -NotePropertyName DefaultInDeep -NotePropertyValue $summary.DefaultInDeep
    $defaults = if ($summary.DefaultInFast -and $summary.DefaultInDeep) { 'Fast and Deep' }
                elseif ($summary.DefaultInDeep) { 'Deep only' }
                elseif ($summary.DefaultInFast) { 'Fast only' }
                else { 'neither Fast nor Deep' }
    $cb.ToolTip = "Category: $($summary.Category)`nOn by default in: $defaults"
    $cb.Margin = '4,3'
    $moduleCheckboxes.Add($cb)
}
$ui['ModuleListItems'].ItemsSource = $moduleCheckboxes

function Update-ModuleCheckboxesForMode {
    <#
        Custom Modules tab doubles as a Fast/Deep preview: picking Fast or Deep on the Basics
        tab (un)checks each box to match that mode's real DefaultInFast/DefaultInDeep, then
        layers on that mode's forceEnableModules/forceDisableModules (e.g. Deep force-enables
        ConfigDependencyScan) - the same two-step Resolve-ModuleSelection itself does in
        Discover-WindowsServer.psm1, so this preview can't drift out of sync with what a real
        run would pick. Boxes grey out since they're not editable outside Custom mode anyway
        (see the tab's own help text). Switching to Custom leaves whatever was last shown
        checked, rather than resetting to nothing - so a common flow is "preview Deep, switch to
        Custom, uncheck the two things I don't want".
    #>
    $mode = $ui['ModeCombo'].SelectedItem.Content
    $isCustom = ($mode -eq 'Custom')
    $modeCfg = $modeConfigs[$mode]
    foreach ($cb in $moduleCheckboxes) {
        $cb.IsEnabled = $isCustom
        if ($mode -eq 'Fast') { $cb.IsChecked = $cb.DefaultInFast }
        elseif ($mode -eq 'Deep') { $cb.IsChecked = $cb.DefaultInDeep }
        if ($modeCfg) {
            if (@($modeCfg.forceEnableModules) -contains $cb.Tag)  { $cb.IsChecked = $true }
            if (@($modeCfg.forceDisableModules) -contains $cb.Tag) { $cb.IsChecked = $false }
        }
    }
}
$ui['ModeCombo'].Add_SelectionChanged({ Update-ModuleCheckboxesForMode })
Update-ModuleCheckboxesForMode

# Options tab tuning: Resolve-EffValue in Discover-WindowsServer.ps1 already falls back to
# Fast/Deep's parameterDefaults whenever a value isn't explicitly passed - but
# Build-DiscoveryArgumentList always sends a value for every numeric field here (they always
# hold parseable text), which makes the engine treat them as explicitly bound and never fall
# through. Left alone, that meant picking "Deep" never actually got you Deep's real 30-day/
# 100-sample event log tuning - the GUI silently kept sending Fast's numbers no matter what
# Mode said. Pre-filling these fields from the same JSON on every Mode change fixes that, and
# incidentally makes the checkboxes stop lying about what Deep will actually turn on.
$boolOptionControls = @{
    deepFileShareScan           = 'DeepFileShareScanCheck'
    includeConfigDependencyScan = 'IncludeConfigDependencyScanCheck'
    attemptSqlIntegratedAuth    = 'AttemptSqlIntegratedAuthCheck'
    fullEventLogExport          = 'FullEventLogExportCheck'
    includeUserProfiles         = 'IncludeUserProfilesCheck'
    includeRecycleBin           = 'IncludeRecycleBinCheck'
    includeWindowsFolder        = 'IncludeWindowsFolderCheck'
}
$numericOptionControls = @{
    maxDepth                = 'MaxDepthBox'
    largeFileThresholdGB    = 'LargeFileThresholdGBBox'
    oldFileYears             = 'OldFileYearsBox'
    eventLogDays             = 'EventLogDaysBox'
    maxEventSamplesPerLog    = 'MaxEventSamplesBox'
    configScanMaxFileSizeMB  = 'ConfigScanMaxFileSizeMBBox'
}

function Update-OptionsForMode {
    $mode = $ui['ModeCombo'].SelectedItem.Content
    $modeCfg = $modeConfigs[$mode]
    if (-not $modeCfg -or -not $modeCfg.parameterDefaults) { return }  # Custom: nothing to preview
    $pd = $modeCfg.parameterDefaults
    foreach ($key in $boolOptionControls.Keys) {
        if ($pd.PSObject.Properties[$key]) { $ui[$boolOptionControls[$key]].IsChecked = [bool]$pd.$key }
    }
    foreach ($key in $numericOptionControls.Keys) {
        if ($pd.PSObject.Properties[$key]) { $ui[$numericOptionControls[$key]].Text = [string]$pd.$key }
    }
}
$ui['ModeCombo'].Add_SelectionChanged({ Update-OptionsForMode })
Update-OptionsForMode

#endregion

#region Fleet tab -----------------------------------------------------------------

# Memory-only, deliberately not the DPAPI store tools\Send-DiscoveryOutput.ps1 uses for delivery
# credentials - a leaked domain admin credential is a much bigger blast radius than a leaked
# SendGrid key, so this one is never written to disk. Cleared on window close (best effort - see
# the Fleet tab's own help text; PowerShell can't guarantee prior in-memory copies are scrubbed).
$script:FleetCredential = $null
$script:FleetAdResults = @()
$script:FleetScanResults = @()
$script:FleetCandidateCheckboxes = [System.Collections.Generic.List[object]]::new()
$script:FleetEngagementFolder = $null
$script:FleetRunProcess = $null

$ui['SetFleetCredentialButton'].Add_Click({
    $cred = Get-Credential -Message 'Domain admin credential for AD query + remote runs (e.g. CORP\Administrator). Held in memory only for this session - never saved to disk.'
    if ($cred) {
        $script:FleetCredential = $cred
        $ui['FleetCredentialStatusText'].Text = "Set: $($cred.UserName)"
    }
})
$ui['ClearFleetCredentialButton'].Add_Click({
    $script:FleetCredential = $null
    $ui['FleetCredentialStatusText'].Text = 'Not set.'
})
$window.Add_Closing({ $script:FleetCredential = $null })

function Update-FleetCandidateList {
    <#
        Rebuilds the picker from whatever AD/scan results are currently held, deduping via
        Merge-DiscoveryCandidate. A 'Scan'/'Both' entry is reachable by definition - that's what
        Invoke-SubnetWinRmScan returns in the first place - but a pure 'AD' entry has never been
        probed, so picking one that's actually down (powered off, WinRM not enabled, firewalled)
        used to look identical to a healthy one right up until "Run on Selected" finished in
        under a second with nothing to show for it. Probing AD-only entries here means that
        shows up as a visible warning before the click, not a confusing empty rollup after it.

        Also probes every WinRM-reachable candidate for whether it can actually run the engine
        (PowerShell 5.1+, or PowerShell 7 installed as a fallback) once a credential is set - the
        same gap LABSRV12 exposed live: a target can answer WinRM and still fail every run
        because of its own PowerShell version, and that's worth knowing before the click too.
    #>
    $merged = Merge-DiscoveryCandidate -AdResults $script:FleetAdResults -ScanResults $script:FleetScanResults
    $adOnlyFqdns = @($merged | Where-Object { $_.Source -eq 'AD' -and $_.FQDN } | ForEach-Object { $_.FQDN })
    $reachableAdOnly = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if ($adOnlyFqdns.Count -gt 0) {
        # .IPAddress (not .FQDN) on a scan-result row is the exact string that was probed and
        # found reachable - untouched by that function's own reverse-DNS display-name lookup -
        # so it's the reliable key to match back against what was just sent in here.
        foreach ($hit in (Invoke-SubnetWinRmScan -HostList $adOnlyFqdns)) { [void]$reachableAdOnly.Add($hit.IPAddress) }
    }

    # PS-version probe needs a real authenticated session per host, unlike the anonymous TCP
    # check above - only worth doing once a credential exists, and only against candidates
    # already known to answer on WinRM (probing a dead host here would just add a timeout).
    $psInfoByTarget = @{}
    if ($script:FleetCredential) {
        $reachableTargets = @($merged | Where-Object { ($_.Source -ne 'AD') -or $reachableAdOnly.Contains($_.FQDN) } |
            ForEach-Object { if ($_.FQDN) { $_.FQDN } else { $_.Name } } | Select-Object -Unique)
        if ($reachableTargets.Count -gt 0) {
            foreach ($info in (Get-FleetTargetPowerShellInfo -HostList $reachableTargets -Credential $script:FleetCredential)) {
                $psInfoByTarget[$info.ComputerName] = $info
            }
        }
    }

    $script:FleetCandidateCheckboxes = [System.Collections.Generic.List[object]]::new()
    foreach ($c in ($merged | Sort-Object Name)) {
        $reachable = if ($c.Source -ne 'AD') { $true } else { $reachableAdOnly.Contains($c.FQDN) }
        $target = if ($c.FQDN) { $c.FQDN } else { $c.Name }
        $psInfo = $psInfoByTarget[$target]
        $needsPs7 = $reachable -and $psInfo -and $psInfo.EngineCompatible -eq $false
        $cb = New-Object System.Windows.Controls.CheckBox
        $label = "$($c.Name)  [$($c.Source)]"
        if (-not $reachable) { $label = "$($c.Name)  [$($c.Source), WinRM not responding]" }
        elseif ($needsPs7) { $label = "$($c.Name)  [$($c.Source), needs PowerShell 7]" }
        $cb.Content = $label
        # Tag is the real target name Invoke-FleetDiscovery.ps1 connects to - prefer the FQDN
        # (needed for Kerberos) over the bare display name.
        $cb.Tag = $target
        $psNote = if ($psInfo) { "`nTarget PowerShell: $($psInfo.WindowsPowerShellVersion)$(if ($psInfo.Pwsh7Present) { ' (PowerShell 7 also installed)' })" } else { '' }
        $cb.ToolTip = "FQDN/IP: $($c.FQDN)`nOS: $($c.OperatingSystem)`nSource: $($c.Source)`nWinRM reachable: $reachable$psNote"
        $cb.Margin = '4,3'
        if (-not $reachable) { $cb.Foreground = 'Gray' }
        elseif ($needsPs7) { $cb.Foreground = 'Chocolate' }
        $script:FleetCandidateCheckboxes.Add($cb)
    }
    $ui['FleetCandidateItems'].ItemsSource = $script:FleetCandidateCheckboxes
}

$ui['SelectAllCandidatesButton'].Add_Click({
    foreach ($cb in $script:FleetCandidateCheckboxes) { $cb.IsChecked = $true }
})
$ui['SelectNoCandidatesButton'].Add_Click({
    foreach ($cb in $script:FleetCandidateCheckboxes) { $cb.IsChecked = $false }
})

$ui['QueryAdButton'].Add_Click({
    if (-not $script:FleetCredential) {
        [System.Windows.MessageBox]::Show('Set a domain credential first.', 'Discover-WindowsServer', 'OK', 'Warning') | Out-Null
        return
    }
    $ui['FleetStatusText'].Text = 'Querying Active Directory, then checking which ones answer on WinRM...'
    try {
        $script:FleetAdResults = Get-AdServerCandidate -DomainCredential $script:FleetCredential
        Update-FleetCandidateList
        $unreachableCount = @($script:FleetCandidateCheckboxes | Where-Object { $_.Content -like '*WinRM not responding*' }).Count
        $needsPs7Count = @($script:FleetCandidateCheckboxes | Where-Object { $_.Content -like '*needs PowerShell 7*' }).Count
        $ui['FleetStatusText'].Text = "AD query found $(@($script:FleetAdResults).Count) server(s)$(if ($unreachableCount -gt 0) { ", $unreachableCount not answering on WinRM right now (greyed out)" })$(if ($needsPs7Count -gt 0) { ", $needsPs7Count need PowerShell 7 installed before they can run (shown in orange)" })."
    } catch {
        $ui['FleetStatusText'].Text = "AD query failed: $($_.Exception.Message)"
    }
})

$ui['ScanSubnetButton'].Add_Click({
    # Runs on the UI thread and blocks for the scan's duration (a /24 takes a few seconds) -
    # acceptable for a one-off button click; not worth the cross-thread Dispatcher complexity a
    # background runspace would add here.
    $ui['FleetStatusText'].Text = 'Scanning subnet...'
    try {
        $hosts = ConvertTo-CidrHostRange -Cidr $ui['FleetCidrBox'].Text
        $script:FleetScanResults = Invoke-SubnetWinRmScan -HostList $hosts
        Update-FleetCandidateList
        $needsPs7Count = @($script:FleetCandidateCheckboxes | Where-Object { $_.Content -like '*needs PowerShell 7*' }).Count
        $ui['FleetStatusText'].Text = "Subnet scan found $(@($script:FleetScanResults).Count) WinRM-reachable host(s)$(if ($needsPs7Count -gt 0) { ", $needsPs7Count need PowerShell 7 installed before they can run (shown in orange)" })."
    } catch {
        $ui['FleetStatusText'].Text = "Subnet scan failed: $($_.Exception.Message)"
    }
})

$fleetTimer = New-Object System.Windows.Threading.DispatcherTimer
$fleetTimer.Interval = [TimeSpan]::FromSeconds(2)
$fleetTimer.Add_Tick({
    $statusPath = Join-Path $script:FleetEngagementFolder 'fleet-status\progress.json'
    if (Test-Path -LiteralPath $statusPath) {
        try {
            $p = Get-Content -LiteralPath $statusPath -Raw | ConvertFrom-Json
            $ui['FleetProgressBar'].Value = [double]$p.PercentComplete
            # Per-target detail (e.g. "SRV1 [Synthesizing: RiskEngine 62%]") when
            # Invoke-RemoteDiscoveryRun's poll loop has already relayed that target's own
            # evidence\status\status.json back - a target still staging/reaching has no entry
            # yet and just shows its bare name, same as before this existed.
            $phaseByName = @{}
            foreach ($tp in @($p.TargetPhases)) { if ($tp.ComputerName) { $phaseByName[$tp.ComputerName] = $tp } }
            $running = (@($p.CurrentTargets) | ForEach-Object {
                $tp = $phaseByName[$_]
                if ($tp -and $tp.CurrentModule) { "$_ [$($tp.Phase): $($tp.CurrentModule) $($tp.PercentComplete)%]" }
                elseif ($tp -and $tp.Phase) { "$_ [$($tp.Phase)]" }
                else { $_ }
            }) -join ', '
            $ui['FleetStatusText'].Text = "$($p.Phase): $running ($($p.CompletedTargets)/$($p.TotalTargets) targets)"
        } catch { }
    }
    if ($script:FleetRunProcess -and $script:FleetRunProcess.HasExited) {
        $fleetTimer.Stop()
        $ui['RunFleetButton'].IsEnabled = $true
        $ui['BuildRollupButton'].IsEnabled = $true
        $ui['CompareRunsButton'].IsEnabled = $true
        Disable-MainRunControlsForFleet -Running $false
        $ui['FleetProgressBar'].Value = 100
        # Deleted here, under this same (GUI) identity, rather than left to the launcher's own
        # (removed) self-delete line - confirmed live that a domain-credentialed run can read but
        # not necessarily delete a launcher file this identity created; see
        # ConvertTo-DiscoveryLauncherScript's comment for the full ACL story.
        if ($script:FleetLauncherPath) { Remove-Item -LiteralPath $script:FleetLauncherPath -Force -ErrorAction SilentlyContinue; $script:FleetLauncherPath = $null }
        # Read fleet-run-results.json rather than declaring success just because the process
        # exited - the process launches hidden (-WindowStyle Hidden), so a target that's
        # Unreachable/Failed/TimedOut finishes in well under a second with no error visible
        # anywhere, and a naive "Fleet run finished!" message here looks identical to a real
        # success while the rollup silently has nothing to show. Caught by hand: an unreachable
        # target finishes in ~1s and produces zero output folders, which is exactly what "the
        # run finished immediately and the report is empty" looks like from the outside.
        $resultsPath = Join-Path $script:FleetEngagementFolder 'fleet-run-results.json'
        if (Test-Path -LiteralPath $resultsPath) {
            try {
                # Assign BEFORE wrapping in @() - Windows PowerShell 5.1's ConvertFrom-Json
                # emits a JSON array as ONE pipeline object rather than enumerating it (PS6+
                # does enumerate), so @() around the pipeline expression directly collapses
                # every target's real result into a single nested blob on 5.1, and this status
                # text would silently read "1/1 succeeded" no matter how many targets actually
                # ran. See the matching fix/comment in Merge-FleetDiscoveryResults.ps1.
                $parsedResults = Get-Content -LiteralPath $resultsPath -Raw | ConvertFrom-Json
                $results = @($parsedResults)
                $succeeded = @($results | Where-Object { $_.Status -eq 'Succeeded' })
                # A revert failure (WinRM enabled by this tool, but Disable-RemoteWinRm itself
                # failed afterward) lands in ErrorMessage on an otherwise-Succeeded result - check
                # for that regardless of Status, since "all N succeeded" would otherwise silently
                # hide that a target was left with WinRM enabled on real client infrastructure.
                $revertFailures = @($results | Where-Object { $_.WinRmEnabledByThisTool -and $_.ErrorMessage -match 'WinRM revert failed' })
                if ($succeeded.Count -eq $results.Count -and $revertFailures.Count -eq 0) {
                    $ui['FleetStatusText'].Text = "Fleet run finished: $($succeeded.Count)/$($results.Count) succeeded. Click `"Build Rollup Report`" for the combined results."
                } else {
                    $problems = ($results | Where-Object { $_.Status -ne 'Succeeded' -or $_.ErrorMessage } | ForEach-Object { "$($_.ComputerName): $($_.Status) - $($_.ErrorMessage)" }) -join ' | '
                    $ui['FleetStatusText'].Text = "Fleet run finished: $($succeeded.Count)/$($results.Count) succeeded - $problems"
                }
            } catch {
                $ui['FleetStatusText'].Text = "Fleet run finished, but fleet-run-results.json could not be read: $($_.Exception.Message)"
            }
        } else {
            $exitNote = if ($script:FleetRunProcess.ExitCode -ne 0) { " (exit code $($script:FleetRunProcess.ExitCode))" } else { '' }
            $ui['FleetStatusText'].Text = "Fleet run process exited without producing fleet-run-results.json$exitNote - check that the domain credential is valid and can log on locally on this machine."
        }
    }
})

$ui['RunFleetButton'].Add_Click({
    $selected = @($script:FleetCandidateCheckboxes | Where-Object { $_.IsChecked } | ForEach-Object { $_.Tag })
    if ($selected.Count -eq 0) {
        [System.Windows.MessageBox]::Show('Check at least one server first.', 'Discover-WindowsServer', 'OK', 'Warning') | Out-Null
        return
    }
    if (-not $script:FleetCredential) {
        [System.Windows.MessageBox]::Show('Set a domain credential first.', 'Discover-WindowsServer', 'OK', 'Warning') | Out-Null
        return
    }

    $engagementName = 'Fleet_{0}' -f (Get-Date -Format 'yyyyMMdd_HHmmss')
    $script:FleetEngagementFolder = Join-Path $ui['OutputRootBox'].Text (Join-Path 'FleetRuns' $engagementName)
    $argList = @(
        '-NoProfile', '-File', "`"$fleetScript`"",
        '-TargetComputerNames', ($selected -join ','),
        '-EngagementFolder', "`"$($script:FleetEngagementFolder)`"",
        '-Mode', $ui['ModeCombo'].SelectedItem.Content,
        '-ProjectType', $ui['ProjectTypeCombo'].SelectedItem.Content,
        '-ComplianceLens', $ui['ComplianceLensCombo'].SelectedItem.Content,
        '-MaxConcurrency', $ui['FleetConcurrencyCombo'].SelectedItem.Content,
        '-CredentialFromStdin'
    )
    if ($ui['EnableWinRmCheck'].IsChecked) { $argList += '-EnableWinRmIfUnreachable' }
    $hostExe = (Get-Process -Id $PID).Path
    $ui['RunFleetButton'].IsEnabled = $false
    $ui['BuildRollupButton'].IsEnabled = $false
    $ui['CompareRunsButton'].IsEnabled = $false
    Disable-MainRunControlsForFleet -Running $true
    $ui['FleetProgressBar'].Value = 0
    $ui['FleetStatusText'].Text = 'Launching fleet run...'
    try {
        # Via a launcher script, not -ArgumentList $argList directly - see
        # ConvertTo-DiscoveryLauncherScript's own comment: -File does not re-parse trailing
        # arguments as PowerShell syntax, which is exactly what glued all 7 selected servers'
        # FQDNs into one unresolvable "hostname" the first time this was tried against more than
        # one target at once.
        $script:FleetLauncherPath = ConvertTo-DiscoveryLauncherScript -ArgList $argList -ArrayParameterNames @('TargetComputerNames')

        # NOT Start-Process -Credential: that runs the child process itself as the domain admin
        # (ambient identity), which tested live against this lab and reliably failed WinRM's
        # New-PSSession with "Access is denied" - the identical account/target/auth mode
        # succeeded immediately with an EXPLICIT credential every time (see Invoke-FleetDiscovery.ps1's
        # own header for the full story). So instead: launch as THIS process's own identity (no
        # cross-account complexity for the launcher file either - see
        # ConvertTo-DiscoveryLauncherScript's comment on that), and hand the credential to the
        # child over its STANDARD INPUT once it's running - in memory only, never a file, never a
        # command-line argument (unlike a launched process's command line, its stdin isn't
        # visible to Get-Process/WMI or anything else that can merely list processes).
        $psi = [System.Diagnostics.ProcessStartInfo]::new()
        $psi.FileName = $hostExe
        $psi.Arguments = '-NoProfile -File "{0}"' -f $script:FleetLauncherPath
        $psi.UseShellExecute = $false
        $psi.RedirectStandardInput = $true
        $psi.WorkingDirectory = $scriptRoot
        $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
        $psi.CreateNoWindow = $true
        $script:FleetRunProcess = [System.Diagnostics.Process]::Start($psi)
        $plainPassword = $script:FleetCredential.GetNetworkCredential().Password
        $script:FleetRunProcess.StandardInput.WriteLine($script:FleetCredential.UserName)
        $script:FleetRunProcess.StandardInput.WriteLine([Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($plainPassword)))
        $script:FleetRunProcess.StandardInput.Close()
        # Best-effort only - a .NET string's prior contents can't be reliably scrubbed from
        # memory (immutable, may have been copied by the runtime); not a guarantee, same
        # limitation already noted for the credential object itself elsewhere in this tab.
        $plainPassword = $null
        $fleetTimer.Start()
    } catch {
        $ui['RunFleetButton'].IsEnabled = $true
        Disable-MainRunControlsForFleet -Running $false
        $ui['FleetStatusText'].Text = "Could not launch fleet run: $($_.Exception.Message)"
    }
})

$ui['BuildRollupButton'].Add_Click({
    if (-not $script:FleetEngagementFolder -or -not (Test-Path -LiteralPath $script:FleetEngagementFolder)) {
        [System.Windows.MessageBox]::Show('Run the fleet first.', 'Discover-WindowsServer', 'OK', 'Warning') | Out-Null
        return
    }
    try {
        $report = New-FleetRollupReport -EngagementFolder $script:FleetEngagementFolder
        $ui['FleetStatusText'].Text = "Rollup built: $($report.ServerCount) server(s), $($report.FindingCount) finding(s). Opening the printable report and the interactive dashboard - the client-safe summary is also in the same rollup folder (fleet-client-summary.html) whenever you're ready to send it."
        Invoke-Item -LiteralPath $report.HtmlPath
        Invoke-Item -LiteralPath $report.DashboardPath
    } catch {
        $ui['FleetStatusText'].Text = "Rollup build failed: $($_.Exception.Message)"
    }
})

$ui['CompareRunsButton'].Add_Click({
    if (-not $script:FleetEngagementFolder -or -not (Test-Path -LiteralPath $script:FleetEngagementFolder)) {
        [System.Windows.MessageBox]::Show('Run the fleet first.', 'Discover-WindowsServer', 'OK', 'Warning') | Out-Null
        return
    }
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.Description = 'Select the OLDER (baseline) fleet engagement folder to compare against the run that just finished.'
    if ($dlg.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }
    try {
        $report = New-DriftReport -BaselineEngagementFolder $dlg.SelectedPath -CurrentEngagementFolder $script:FleetEngagementFolder
        $ui['FleetStatusText'].Text = "Drift report built: $($report.ServerCount) server(s), +$($report.TotalAdded) -$($report.TotalRemoved) ~$($report.TotalChanged). Opening it now - the client-safe version (drift-client-summary.html) is in the same drift\ folder."
        Invoke-Item -LiteralPath $report.HtmlPath
    } catch {
        $ui['FleetStatusText'].Text = "Drift comparison failed: $($_.Exception.Message)"
    }
})

#endregion

#region Delivery tab field visibility --------------------------------------------

function Update-DeliveryFieldVisibility {
    $method = ($ui['DeliveryMethodCombo'].SelectedItem.Content)
    $none = [System.Windows.Visibility]::Collapsed
    $show = [System.Windows.Visibility]::Visible

    $ui['EmailFieldsPanel'].Visibility      = if ($method -in 'Smtp', 'Smtp2Go', 'SendGrid', 'Postal') { $show } else { $none }
    $ui['SmtpFieldsPanel'].Visibility       = if ($method -eq 'Smtp') { $show } else { $none }
    $ui['PostalFieldsPanel'].Visibility     = if ($method -eq 'Postal') { $show } else { $none }
    $ui['UploadFieldsPanel'].Visibility     = if ($method -eq 'Upload') { $show } else { $none }
    $ui['CredentialFieldsPanel'].Visibility = if ($method -in 'Smtp', 'Smtp2Go', 'SendGrid', 'Postal') { $show } else { $none }
}
$ui['DeliveryMethodCombo'].Add_SelectionChanged({ Update-DeliveryFieldVisibility })
Update-DeliveryFieldVisibility

$ui['SetCredentialButton'].Add_Click({
    $name = $ui['CredentialNameBox'].Text
    if ([string]::IsNullOrWhiteSpace($name)) {
        [System.Windows.MessageBox]::Show('Enter a credential name first.', 'Discover-WindowsServer', 'OK', 'Warning') | Out-Null
        return
    }
    $cred = Get-Credential -UserName 'ApiKey' -Message "Credential for '$name' (username is ignored for API-key providers - put the key in the password field)"
    if ($cred) {
        Save-DeliveryCredential -Name $name -Credential $cred
        $ui['CredentialStatusText'].Text = "Saved '$name' (encrypted, this Windows user/machine only)."
    }
})

#endregion

#region Browse for output folder -------------------------------------------------

$ui['BrowseOutputButton'].Add_Click({
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.SelectedPath = $ui['OutputRootBox'].Text
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $ui['OutputRootBox'].Text = $dlg.SelectedPath
    }
})

#endregion

#region Branding tab --------------------------------------------------------------

# Branding is saved to %ProgramData%\Discover-WindowsServer\branding\branding.local.json - never in
# the repo or the Gallery package - and the engine overlays it onto the
# tracked output-settings.json defaults (Merge-LocalBranding in Core.psm1, and
# Merge-FleetDiscoveryResults.ps1's Get-FleetBranding for fleet reports).
$script:BrandingDefaultsPath = Join-Path $scriptRoot 'config\output-settings.json'
# Same path as Core.psm1's Get-DiscoveryBrandingDirectory: outside the module folder, so saving
# needs no write access to Program Files and the brand survives Update-Module's new version folder.
$script:BrandingConfigDir    = Join-Path $env:ProgramData 'Discover-WindowsServer\branding'
$script:BrandingConfigPath   = Join-Path $BrandingConfigDir 'branding.local.json'
# One-time copy (never a move) of branding saved by an older version into config\.
$legacyBrandingDir = Join-Path $scriptRoot 'config'
if (-not (Test-Path -LiteralPath $script:BrandingConfigPath) -and (Test-Path -LiteralPath (Join-Path $legacyBrandingDir 'branding.local.json'))) {
    try {
        New-Item -ItemType Directory -Path $script:BrandingConfigDir -Force | Out-Null
        Get-ChildItem -LiteralPath $legacyBrandingDir -File -ErrorAction Stop |
            Where-Object { $_.Name -eq 'branding.local.json' -or $_.Name -like 'branding-logo.*' } |
            Copy-Item -Destination $script:BrandingConfigDir -ErrorAction Stop
    } catch { } # stays readable from config\ via the engine's fallback; the next Save writes the new location
}
# Holds the config-dir-relative logo filename that will be saved on the next "Save branding
# settings" click - set from the config at load time, and updated immediately (before Save)
# by Choose/Remove logo, since the logo FILE itself is copied/deleted right away rather than
# staged, matching how SetFleetCredentialButton commits immediately rather than on a save step.
$script:PendingLogoRelativePath = ''

function Update-BrandingLogoPreview {
    param([string]$RelativePath)
    if ([string]::IsNullOrWhiteSpace($RelativePath)) {
        $ui['LogoPreviewImage'].Source = $null
        $ui['LogoStatusText'].Text = 'No logo set.'
        return
    }
    $fullPath = Join-Path $script:BrandingConfigDir $RelativePath
    if (-not (Test-Path -LiteralPath $fullPath)) {
        $ui['LogoPreviewImage'].Source = $null
        $ui['LogoStatusText'].Text = "Logo file '$RelativePath' is missing from $($script:BrandingConfigDir) - choose one again."
        return
    }
    try {
        $bmp = New-Object System.Windows.Media.Imaging.BitmapImage
        $bmp.BeginInit()
        $bmp.CacheOption = [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad
        $bmp.UriSource = New-Object System.Uri($fullPath, [System.UriKind]::Absolute)
        $bmp.EndInit()
        $ui['LogoPreviewImage'].Source = $bmp
        $ui['LogoStatusText'].Text = (Split-Path $RelativePath -Leaf)
    } catch {
        $ui['LogoPreviewImage'].Source = $null
        $ui['LogoStatusText'].Text = "Could not preview '$RelativePath': $($_.Exception.Message)"
    }
}

# Populate the tab from whatever is already saved, so opening the GUI never shows blank
# fields for a brand that's already configured.
try {
    # Defaults first, then the local overlay on top - the same precedence the engine uses.
    foreach ($brandingPath in @($script:BrandingDefaultsPath, $script:BrandingConfigPath)) {
        if (-not (Test-Path -LiteralPath $brandingPath)) { continue }
        $existingBranding = Get-Content -LiteralPath $brandingPath -Raw | ConvertFrom-Json
        if (-not $existingBranding.html) { continue }
        $props = $existingBranding.html.PSObject.Properties.Name
        if ($props -contains 'brandName')      { $ui['BrandNameBox'].Text = [string]$existingBranding.html.brandName }
        if ($props -contains 'accentColorHex') { $ui['AccentColorBox'].Text = [string]$existingBranding.html.accentColorHex }
        if ($props -contains 'logoPath')       { $script:PendingLogoRelativePath = [string]$existingBranding.html.logoPath }
    }
} catch {
    $ui['BrandingStatusText'].Text = "Could not read existing branding settings: $($_.Exception.Message)"
}
Update-BrandingLogoPreview -RelativePath $script:PendingLogoRelativePath

function Update-AccentSwatch {
    try {
        $ui['AccentPreviewSwatch'].Fill = [System.Windows.Media.BrushConverter]::new().ConvertFromString($ui['AccentColorBox'].Text)
    } catch { } # invalid/incomplete hex while typing - leave the swatch as it was
}
$ui['AccentColorBox'].Add_TextChanged({ Update-AccentSwatch })
# Paint the saved color now. The box was filled above, before this handler existed, and
# re-assigning the same Text (the old approach) raises no TextChanged in WPF - so the swatch
# stayed blank until the color was edited.
Update-AccentSwatch

$ui['ChooseLogoButton'].Add_Click({
    $dlg = New-Object Microsoft.Win32.OpenFileDialog
    $dlg.Filter = 'Image files|*.png;*.jpg;*.jpeg;*.gif;*.svg'
    if ($dlg.ShowDialog() -ne $true) { return }
    try {
        # Remove any previously-saved logo first, regardless of extension, so switching from a
        # .png to a .jpg doesn't leave the old file behind alongside the new one.
        Get-ChildItem -LiteralPath $script:BrandingConfigDir -Filter 'branding-logo.*' -File -ErrorAction SilentlyContinue |
            Remove-Item -Force -ErrorAction SilentlyContinue
        $destName = 'branding-logo' + [System.IO.Path]::GetExtension($dlg.FileName).ToLowerInvariant()
        $destPath = Join-Path $script:BrandingConfigDir $destName
        New-Item -ItemType Directory -Path $script:BrandingConfigDir -Force | Out-Null
        Copy-Item -LiteralPath $dlg.FileName -Destination $destPath -Force
        $script:PendingLogoRelativePath = $destName
        Update-BrandingLogoPreview -RelativePath $destName
        $ui['BrandingStatusText'].Text = "Logo staged - click 'Save branding settings' to apply it to future reports."
    } catch {
        $ui['BrandingStatusText'].Text = "Could not set logo: $($_.Exception.Message)"
    }
})

$ui['ClearLogoButton'].Add_Click({
    try {
        Get-ChildItem -LiteralPath $script:BrandingConfigDir -Filter 'branding-logo.*' -File -ErrorAction SilentlyContinue |
            Remove-Item -Force -ErrorAction SilentlyContinue
    } catch { }
    $script:PendingLogoRelativePath = ''
    Update-BrandingLogoPreview -RelativePath ''
    $ui['BrandingStatusText'].Text = "Logo removed - click 'Save branding settings' to apply."
})

$ui['SaveBrandingButton'].Add_Click({
    $accent = $ui['AccentColorBox'].Text
    if (-not [string]::IsNullOrWhiteSpace($accent) -and $accent -notmatch '^#[0-9A-Fa-f]{6}$') {
        $ui['BrandingStatusText'].Text = "Accent color must be a 6-digit hex code like #1F4E79 - not saved."
        return
    }
    try {
        # Re-read fresh rather than reusing whatever was loaded at GUI startup, so a hand-edit
        # made to the file while the GUI was open isn't clobbered.
        $current = if (Test-Path -LiteralPath $script:BrandingConfigPath) {
            Get-Content -LiteralPath $script:BrandingConfigPath -Raw | ConvertFrom-Json
        } else {
            [pscustomobject]@{ html = [pscustomobject]@{} }
        }
        if (-not $current.html) { $current | Add-Member -MemberType NoteProperty -Name html -Value ([pscustomobject]@{}) -Force }
        $brandName = $ui['BrandNameBox'].Text
        foreach ($pair in @(
            @{ Name = 'brandName'; Value = $brandName }
            @{ Name = 'accentColorHex'; Value = $accent }
            @{ Name = 'logoPath'; Value = $script:PendingLogoRelativePath }
        )) {
            if ($current.html.PSObject.Properties.Name -contains $pair.Name) { $current.html.($pair.Name) = $pair.Value }
            else { $current.html | Add-Member -MemberType NoteProperty -Name $pair.Name -Value $pair.Value -Force }
        }
        New-Item -ItemType Directory -Path $script:BrandingConfigDir -Force | Out-Null
        ($current | ConvertTo-Json -Depth 10) | Set-Content -LiteralPath $script:BrandingConfigPath -Encoding UTF8
        $ui['BrandingStatusText'].Text = "Saved. Applies to every report generated from now on (internal, client, and fleet)."
    } catch {
        $ui['BrandingStatusText'].Text = "Save failed: $($_.Exception.Message)"
    }
})

#endregion

#region Run + progress polling ---------------------------------------------------

$script:RunProcess    = $null
$script:RunOutputPath = $null
$script:RunStartTime  = $null
$timer = New-Object System.Windows.Threading.DispatcherTimer
$timer.Interval = [TimeSpan]::FromSeconds(2)

function Disable-InputsWhileRunning { param([bool]$Running) $ui['RunButton'].IsEnabled = -not $Running; $ui['WhatIfButton'].IsEnabled = -not $Running; $ui['MainTabs'].IsEnabled = -not $Running }

# The single-server Preview/Run buttons live outside the tab control (a shared bottom action
# bar), so Disable-InputsWhileRunning's own $ui['MainTabs'].IsEnabled = $false (set for a
# single-server run) does NOT reach them while a FLEET run is in progress - confirmed live: with
# no equivalent for the fleet path, an operator could start a single-server run against THIS
# machine while a fleet job was mid-flight remotely, racing the same OutputRoot and this
# process's own state. Deliberately does NOT touch $ui['MainTabs'] itself (unlike the
# single-server case) - the operator is normally sitting on the Fleet tab watching progress and
# still needs the rest of the Fleet tab's own controls (credential, candidate list) usable.
function Disable-MainRunControlsForFleet {
    param([bool]$Running)
    $ui['WhatIfButton'].IsEnabled = -not $Running
    $ui['RunButton'].IsEnabled = -not $Running
    $ui['RunButton'].Content = if ($Running) { 'Fleet job running...' } else { 'Run' }
}

function Start-DiscoveryDeliveryIfConfigured {
    param([string]$OutputPath)
    $method = $ui['DeliveryMethodCombo'].SelectedItem.Content
    if ($method -eq 'None (just save locally)') { return }
    $zip = Find-DiscoveryRunZip -OutputPath $OutputPath
    if (-not $zip) {
        $ui['StatusText'].Text = 'Run finished, but no .zip was found under archive\ - nothing to deliver (was -SkipZip checked?).'
        return
    }
    $ui['StatusText'].Text = "Run finished. Sending via $method..."
    try {
        $deliveryArgs = @{
            ZipPath          = $zip
            Method           = $method
            From             = $ui['FromBox'].Text
            To               = @(($ui['ToBox'].Text -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            Subject          = $ui['SubjectBox'].Text
            SmtpServer       = $ui['SmtpServerBox'].Text
            PostalServerUrl  = $ui['PostalServerUrlBox'].Text
            UploadUrl        = $ui['UploadUrlBox'].Text
            UploadMethod     = $ui['UploadMethodCombo'].SelectedItem.Content
            CredentialName   = $ui['CredentialNameBox'].Text
        }
        $smtpPortVal = 587; [void][int]::TryParse($ui['SmtpPortBox'].Text, [ref]$smtpPortVal)
        $deliveryArgs['SmtpPort'] = $smtpPortVal
        $deliveryArgs['UseSsl']   = [bool]$ui['UseSslCheck'].IsChecked
        Invoke-DiscoveryDelivery @deliveryArgs | Out-Null
        $ui['StatusText'].Text = "Done. Sent via $method and saved locally at $OutputPath"
    } catch {
        $ui['StatusText'].Text = "Run finished and saved locally at $OutputPath - delivery via $method FAILED: $($_.Exception.Message)"
    }
}

function Open-DiscoveryReportIfConfigured {
    <#
        Opens the chosen report format once a run finishes, if the "Open report automatically"
        checkbox is checked. "Internal report" opens BOTH internal-engineering-report.html and
        internal-dashboard-report.html together - the same pairing New-FleetRollupReport's own
        "Build Rollup Report" button already opens together for the fleet case - rather than
        picking just one and leaving the other undiscovered.
    #>
    param([string]$OutputPath)
    if (-not $ui['AutoOpenReportCheck'].IsChecked) { return }
    $reportsDir = Join-Path $OutputPath 'reports'
    $choice = $ui['AutoOpenReportCombo'].SelectedItem.Content
    if ($choice -eq 'Client report') {
        $client = Join-Path $reportsDir 'client-discovery-report.html'
        if (Test-Path -LiteralPath $client) { Invoke-Item -LiteralPath $client }
        else { $ui['StatusText'].Text = 'Run finished, but client-discovery-report.html was not found to open.' }
    } else {
        $internal = Join-Path $reportsDir 'internal-engineering-report.html'
        $dashboard = Join-Path $reportsDir 'internal-dashboard-report.html'
        $foundAny = $false
        if (Test-Path -LiteralPath $internal)  { Invoke-Item -LiteralPath $internal;  $foundAny = $true }
        if (Test-Path -LiteralPath $dashboard) { Invoke-Item -LiteralPath $dashboard; $foundAny = $true }
        if (-not $foundAny) { $ui['StatusText'].Text = 'Run finished, but the internal report(s) were not found to open.' }
    }
}

$timer.Add_Tick({
    if (-not $script:RunOutputPath) {
        # Still waiting to see the output folder the engine creates near the very start of the run.
        $root = $ui['OutputRootBox'].Text
        if (Test-Path -LiteralPath $root) {
            # NOTE: ${env:COMPUTERNAME} (braced) is required here, not $env:COMPUTERNAME_ - an
            # unbraced drive-qualified variable reference greedily consumes trailing word
            # characters as part of the name, so $env:COMPUTERNAME_* would actually look up a
            # nonexistent "COMPUTERNAME_" environment variable (silently empty) instead of
            # $env:COMPUTERNAME followed by a literal underscore.
            $candidate = Get-ChildItem -LiteralPath $root -Directory -Filter "Discover-WindowsServer_${env:COMPUTERNAME}_*" -ErrorAction SilentlyContinue |
                Where-Object { $_.CreationTime -ge $script:RunStartTime } | Sort-Object CreationTime -Descending | Select-Object -First 1
            if ($candidate) { $script:RunOutputPath = $candidate.FullName }
        }
        if (-not $script:RunOutputPath) { $ui['StatusText'].Text = 'Starting...'; return }
    }

    $progressPath = Join-Path $script:RunOutputPath 'evidence\status\progress.json'
    if (Test-Path -LiteralPath $progressPath) {
        try {
            $p = Get-Content -LiteralPath $progressPath -Raw | ConvertFrom-Json
            $ui['RunProgressBar'].Value = [double]$p.PercentComplete
            $ui['StatusText'].Text = "$($p.Phase): $($p.CurrentModule) ($($p.CompletedModules)/$($p.TotalModules) modules)"
        } catch { }
    }

    if ($script:RunProcess.HasExited) {
        $timer.Stop()
        Disable-InputsWhileRunning $false
        $ui['RunProgressBar'].Value = 100
        # Deleted here, under this same (GUI) identity, rather than left to the launcher's own
        # (removed) self-delete line - see ConvertTo-DiscoveryLauncherScript's comment for why.
        if ($script:RunLauncherPath) { Remove-Item -LiteralPath $script:RunLauncherPath -Force -ErrorAction SilentlyContinue; $script:RunLauncherPath = $null }
        if ($script:RunWasWhatIf) {
            # -WhatIf stops the engine right after writing discovery-plan.md - no collector ever
            # runs, so reports\ is never created. Auto-open/delivery would either error on a
            # missing file or (worse) silently do nothing while looking like a real finish -
            # this gets its own distinct message instead of falling into that path at all.
            $ui['StatusText'].Text = 'Preview finished - see discovery-plan.md in the run folder for what would run. No reports were generated.'
        } else {
            # A clear, unmissable "done" signal per the user's own request - the status text
            # alone previously just froze on the last progress-phase line (or, with no delivery
            # configured, was never updated again at all), which did not read as "finished" at a
            # glance. The title-bar change stays visible even from the taskbar/Alt-Tab without
            # needing this window focused; the system sound adds a non-visual cue for the same
            # reason. Both are reset back to normal the next time a run starts (Start-DiscoveryRun).
            $window.Title = '[Run finished] Discover-WindowsServer'
            $ui['StatusText'].Text = "Run finished! Reports are in $script:RunOutputPath\reports"
            try { [System.Media.SystemSounds]::Asterisk.Play() } catch { }
            Open-DiscoveryReportIfConfigured -OutputPath $script:RunOutputPath
            Start-DiscoveryDeliveryIfConfigured -OutputPath $script:RunOutputPath
        }
    }
})

function Start-DiscoveryRun {
    param([switch]$WhatIfOnly)
    $mode = $ui['ModeCombo'].SelectedItem.Content
    $includedModules = @(if ($mode -eq 'Custom') { @($moduleCheckboxes | Where-Object { $_.IsChecked } | ForEach-Object { $_.Tag }) } else { @() })
    $argList = Build-DiscoveryArgumentList -EngineScriptPath $engineScript -Mode $mode `
        -ProjectType $ui['ProjectTypeCombo'].SelectedItem.Content -ComplianceLens $ui['ComplianceLensCombo'].SelectedItem.Content `
        -OutputRoot $ui['OutputRootBox'].Text -IncludedModules $includedModules `
        -DeepFileShareScan ([bool]$ui['DeepFileShareScanCheck'].IsChecked) `
        -FullEventLogExport ([bool]$ui['FullEventLogExportCheck'].IsChecked) `
        -IncludeConfigDependencyScan ([bool]$ui['IncludeConfigDependencyScanCheck'].IsChecked) `
        -IncludeUserProfiles ([bool]$ui['IncludeUserProfilesCheck'].IsChecked) `
        -IncludeRecycleBin ([bool]$ui['IncludeRecycleBinCheck'].IsChecked) `
        -IncludeWindowsFolder ([bool]$ui['IncludeWindowsFolderCheck'].IsChecked) `
        -AttemptSqlIntegratedAuth ([bool]$ui['AttemptSqlIntegratedAuthCheck'].IsChecked) `
        -GenerateEvidenceManifest ([bool]$ui['GenerateEvidenceManifestCheck'].IsChecked) `
        -SkipZip ([bool]$ui['SkipZipCheck'].IsChecked) `
        -VerboseLogging ([bool]$ui['VerboseLoggingCheck'].IsChecked) `
        -MaxDepthText $ui['MaxDepthBox'].Text -LargeFileThresholdGBText $ui['LargeFileThresholdGBBox'].Text `
        -OldFileYearsText $ui['OldFileYearsBox'].Text -EventLogDaysText $ui['EventLogDaysBox'].Text `
        -MaxEventSamplesText $ui['MaxEventSamplesBox'].Text -ConfigScanMaxFileSizeMBText $ui['ConfigScanMaxFileSizeMBBox'].Text `
        -WhatIfOnly:$WhatIfOnly
    $hostExe = (Get-Process -Id $PID).Path
    $script:RunOutputPath = $null
    $script:RunStartTime  = Get-Date
    $script:RunWasWhatIf  = [bool]$WhatIfOnly
    $window.Title = 'Discover-WindowsServer'
    $ui['RunProgressBar'].Value = 0
    $ui['StatusText'].Text = 'Launching...'
    Disable-InputsWhileRunning $true
    # Via a launcher script, not -ArgumentList $argList directly - see
    # ConvertTo-DiscoveryLauncherScript's own comment for why: -File does not re-parse trailing
    # arguments as PowerShell syntax, which silently broke Custom Mode for any 2+ selected module.
    $script:RunLauncherPath = ConvertTo-DiscoveryLauncherScript -ArgList $argList -ArrayParameterNames @('IncludeModules')
    $script:RunProcess = Start-Process -FilePath $hostExe -ArgumentList @('-NoProfile', '-File', "`"$($script:RunLauncherPath)`"") -PassThru -WindowStyle Minimized
    $timer.Start()
}

$ui['RunButton'].Add_Click({ Start-DiscoveryRun })
$ui['WhatIfButton'].Add_Click({ Start-DiscoveryRun -WhatIfOnly })

#endregion

$window.ShowDialog() | Out-Null

}
