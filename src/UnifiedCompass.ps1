# UnifiedCompass.ps1
# Source Code for: Compliance Compass v2.3
# COMPILE INSTRUCTIONS:
# Invoke-PS2EXE -inputFile "UnifiedCompass.ps1" -outputFile "ComplianceCompass.exe" -noConsole -title "Compliance Compass" -version "2.3.0.0"

# --- 1. ADMIN CHECK & RESTART ---
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    try {
        if ($PSScriptRoot) { $ScriptPath = $MyInvocation.MyCommand.Path } 
        else { $ScriptPath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName }
        
        $proc = New-Object System.Diagnostics.ProcessStartInfo
        $proc.FileName = $ScriptPath
        $proc.Verb = "RunAs"
        $proc.UseShellExecute = $true
        [System.Diagnostics.Process]::Start($proc)
        exit
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Admin privileges required for full functionality.", "Warning")
    }
}

# --- 2. LOAD ASSEMBLIES ---
Add-Type -AssemblyName PresentationFramework, System.Windows.Forms, WindowsBase, System.Drawing

# --- 3. EMBEDDED LOGIC ---

function ConvertTo-CimSession {
    param([string]$ComputerName, [int]$Timeout = 15)
    $isLocal = ($ComputerName -eq $env:COMPUTERNAME) -or ($ComputerName -eq 'localhost') -or ($ComputerName -eq '.')
    if ($isLocal) { return $null }
    try {
        return New-CimSession -ComputerName $ComputerName -ErrorAction Stop -OperationTimeoutSec $Timeout
    } catch { throw "Failed to create remote session: $($_.Exception.Message)" }
}

function Get-SystemRole {
    param([string]$ComputerName)
    $cimSession = $null
    try {
        $cimSession = ConvertTo-CimSession -ComputerName $ComputerName -Timeout 5
        $params = @{}; if ($cimSession) { $params.CimSession = $cimSession }
        $osInfo = Get-CimInstance @params -ClassName Win32_OperatingSystem
        if ($osInfo.ProductType -eq 2) { return "Domain Controller" } else { return "Standalone System" }
    } catch { return "Unreachable" } finally { if ($cimSession) { Remove-CimSession -CimSession $cimSession } }
}

function Invoke-MultiFrameworkAudit {
    param([string]$ComputerName, [string]$Mode)
    $allResults = @()
    $cimSession = $null
    
    try {
        $cimSession = ConvertTo-CimSession -ComputerName $ComputerName
        
        # --- TEST 1: AUTHENTICATION ---
        $mapAuth = @{
            "Complexity" = @(@{F="PCI DSS";ID="8.3.6";R="Req 8: Identify & Authenticate";E="Enabled"}, @{F="CMMC";ID="IA.L2-3.5.6";R="Identification and Authentication";E="Enabled"}, @{F="HIPAA";ID="164.308(a)(5)(ii)(D)";R="Technical Safeguards";E="Enabled"})
            "Length" = @(@{F="PCI DSS";ID="8.3.6";R="Req 8: Identify & Authenticate";E="12+"}, @{F="CMMC";ID="IA.L2-3.5.6";R="Identification and Authentication";E="12+"}, @{F="HIPAA";ID="164.308(a)(5)(ii)(D)";R="Technical Safeguards";E="8+"})
            "Lockout" = @(@{F="PCI DSS";ID="8.1.6";R="Req 8: Identify & Authenticate";E="Max 10"}, @{F="CMMC";ID="AC.L2-3.1.8";R="Access Control";E="Max 3"}, @{F="HIPAA";ID="164.308(a)(5)(ii)(C)";R="Technical Safeguards";E="Enabled"})
        }
        
        $scriptAuth = {
            param($m, $map)
            $res = @()
            if ($m -eq 'DomainController') {
                if(Get-Module -ListAvailable ActiveDirectory){
                    $p = Get-ADDefaultDomainPasswordPolicy
                    foreach($r in $map["Complexity"]){ $s=if($p.PasswordComplexityEnabled){"PASS";$sv=3}else{"FAIL";$sv=1}; $res+=[PSCustomObject]@{Requirement=$r.F+" - "+$r.R;CheckID=$r.ID;Description="$($r.F): Password Complexity";Status=$s;Severity=$sv;CurrentValue="Enabled: $($p.PasswordComplexityEnabled)";ExpectedValue=$r.E;Remediation="Enable Password Complexity in GPO."} }
                    foreach($r in $map["Length"]){ $s=if($p.MinPasswordLength -ge 12){"PASS";$sv=3}else{"FAIL";$sv=1}; $res+=[PSCustomObject]@{Requirement=$r.F+" - "+$r.R;CheckID=$r.ID;Description="$($r.F): Min Password Length";Status=$s;Severity=$sv;CurrentValue=$p.MinPasswordLength;ExpectedValue=$r.E;Remediation="Increase Min Length to 12+."} }
                    foreach($r in $map["Lockout"]){ $s=if($p.LockoutThreshold -gt 0 -and $p.LockoutThreshold -le 10){"PASS";$sv=3}else{"FAIL";$sv=1}; $res+=[PSCustomObject]@{Requirement=$r.F+" - "+$r.R;CheckID=$r.ID;Description="$($r.F): Account Lockout";Status=$s;Severity=$sv;CurrentValue=$p.LockoutThreshold;ExpectedValue=$r.E;Remediation="Set Lockout Threshold between 1-10."} }
                }
            } else {
                $f = "$env:TEMP\sec.inf"; secedit /export /cfg $f /quiet; $txt=Get-Content $f; if(Test-Path $f){Remove-Item $f -Force}
                $len = [int]($txt | Select-String "MinimumPasswordLength" | %{$_.ToString().Split('=')[1].Trim()})
                foreach($r in $map["Length"]){ $s=if($len -ge 12){"PASS";$sv=3}else{"FAIL";$sv=1}; $res+=[PSCustomObject]@{Requirement=$r.F+" - "+$r.R;CheckID=$r.ID;Description="$($r.F): Local Min Password Length";Status=$s;Severity=$sv;CurrentValue=$len;ExpectedValue=$r.E;Remediation="Set Local Policy length to 12+."} }
            }
            return $res
        }
        if ($cimSession) { $allResults += Invoke-Command -Session $cimSession -ScriptBlock $scriptAuth -ArgumentList $Mode,$mapAuth } 
        else { $allResults += & $scriptAuth -m $Mode -map $mapAuth }

        # --- TEST 2: FIREWALL ---
        $mapFw = @(@{F="PCI DSS";ID="1.4.2";R="Req 1"}, @{F="CMMC";ID="SC.L1-3.13.1";R="System & Comm"}, @{F="HIPAA";ID="164.312(a)(1)";R="Access Control"})
        $scriptFw = {
            param($map)
            $res=@(); Get-NetFirewallProfile | %{ $p=$_; $e=$p.Enabled; foreach($r in $map){ $s=if($e){"PASS";$sv=3}else{"FAIL";$sv=1}; $res+=[PSCustomObject]@{Requirement=$r.F+" - "+$r.R;CheckID=$r.ID;Description="$($r.F): Windows Firewall ($($p.Name) Profile)";Status=$s;Severity=$sv;CurrentValue="Enabled:$e";ExpectedValue="Enabled";Remediation="Enable Windows Firewall for the $($p.Name) profile."} } }
            return $res
        }
        if ($cimSession) { $allResults += Invoke-Command -Session $cimSession -ScriptBlock $scriptFw -ArgumentList $mapFw }
        else { $allResults += & $scriptFw -map $mapFw }

        # --- TEST 3: CRYPTO ---
        $mapCry = @(@{F="PCI DSS";ID="4.2.1";R="Req 4"}, @{F="CMMC";ID="SC.L2-3.13.11";R="System & Comm"}, @{F="HIPAA";ID="164.312(e)(1)";R="Transmission Security"})
        $protos = @{ "SSL 2.0"=$false; "SSL 3.0"=$false; "TLS 1.0"=$false; "TLS 1.2"=$true }
        $scriptCry = {
            param($map,$pr)
            $res=@(); $base="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
            foreach($k in $pr.Keys){
                $path = Join-Path $base "$k\Server"
                $en = if(Test-Path $path){(Get-ItemProperty $path "Enabled" -EA SilentlyContinue).Enabled -eq 1}else{$true} 
                $comp = ($en -eq $pr[$k])
                foreach($r in $map){ $s=if($comp){"PASS";$sv=3}else{"FAIL";$sv=1}; $res+=[PSCustomObject]@{Requirement=$r.F+" - "+$r.R;CheckID=$r.ID;Description="$($r.F): Protocol Check - $k";Status=$s;Severity=$sv;CurrentValue="Enabled: $en";ExpectedValue="Enabled: $($pr[$k])";Remediation="Configure Schannel registry keys for $k."} }
            }
            return $res
        }
        if ($cimSession) { $allResults += Invoke-Command -Session $cimSession -ScriptBlock $scriptCry -ArgumentList $mapCry,$protos }
        else { $allResults += & $scriptCry -map $mapCry -pr $protos }

        # --- TEST 4: AV & LOGGING ---
        $mapLog = @(@{F="PCI DSS";ID="10.2.1";R="Req 10"}, @{F="CMMC";ID="AU.L2-3.3.1";R="Audit"}, @{F="HIPAA";ID="164.312(b)";R="Audit Controls"})
        $scriptLog = {
            param($map)
            $res=@(); $pol = auditpol /get /category:* | Select-String "Logon/Logoff"; $good = ($pol -match "Success and Failure")
            foreach($r in $map){ $s=if($good){"PASS";$sv=3; $v="Success/Failure"}else{"FAIL";$sv=1; $v="Incomplete"}; $res+=[PSCustomObject]@{Requirement=$r.F+" - "+$r.R;CheckID=$r.ID;Description="$($r.F): Audit Policy (Logon/Logoff)";Status=$s;Severity=$sv;CurrentValue=$v;ExpectedValue="Success & Failure";Remediation="Enable Success/Failure auditing."} }
            return $res
        }
        if ($cimSession) { $allResults += Invoke-Command -Session $cimSession -ScriptBlock $scriptLog -ArgumentList $mapLog }
        else { $allResults += & $scriptLog -map $mapLog }

    } catch {
        $allResults += [PSCustomObject]@{ Requirement="Error"; CheckID="ERR"; Description="Audit Failed"; Status="ERROR"; Severity=2; CurrentValue=$_.Exception.Message; ExpectedValue="-"; Remediation="Check connection" }
    } finally {
        if($cimSession){ Remove-CimSession $cimSession }
    }
    return $allResults
}

function Invoke-FileAccessAudit {
    param ([string]$Path, [string]$AuthorizedGroups, [int]$Hours = 24)
    $res = @()
    $grps = $AuthorizedGroups -split ',' | %{ $_.Trim() }
    
    if (-not ((auditpol /get /subcategory:"File System") -match "Success")) {
        return @([PSCustomObject]@{Status="FAIL";Timestamp=Get-Date;UserName="SYSTEM";FilePath="Audit Policy Check";Reason="CRITICAL: 'Audit File System' success logging is NOT enabled. Enable via GPO."})
    }

    try {
        $evts = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4663;StartTime=(Get-Date).AddHours(-$Hours)} -ErrorAction Stop
        foreach ($e in $evts) {
            $f = $e.Properties[6].Value; $u = $e.Properties[1].Value
            if ($f -and $f.StartsWith($Path)) {
                $reas = @()
                if ($e.TimeCreated.Hour -lt 7 -or $e.TimeCreated.Hour -gt 18) { $reas += "After-Hours" }
                if ($grps -notcontains $u -and $u -notmatch "SYSTEM|machine") { $reas += "Potential Unauthorized" }
                
                $st = if($reas.Count -gt 0){"WARNING"}else{"PASS"}; $rt = if($reas.Count -gt 0){$reas -join ", "}else{"Normal"}
                $res += [PSCustomObject]@{Status=$st;Timestamp=$e.TimeCreated;UserName=$u;FilePath=$f;Reason=$rt}
            }
        }
    } catch {
        if($_.Exception.Message -like "*No events*") { return @([PSCustomObject]@{Status="INFO";Timestamp=Get-Date;UserName="-";FilePath=$Path;Reason="No file access events found in logs."}) }
    }
    if ($res.Count -eq 0) { $res += [PSCustomObject]@{Status="INFO";Timestamp=Get-Date;UserName="-";FilePath=$Path;Reason="No matching events found."} }
    return $res
}

# --- 4. EMBEDDED GUI ---
[xml]$xaml = @"
<Window 
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="CainCyberSolution Compliance Compass (Version 2.3)" Height="768" Width="1024"
        WindowStartupLocation="CenterScreen"
        Background="#0a192f">
    <Window.Resources>
        <Style TargetType="TabItem">
            <Setter Property="Background" Value="#112240"/>
            <Setter Property="Foreground" Value="#8892b0"/>
            <Setter Property="Padding" Value="12,6"/>
            <Setter Property="FontWeight" Value="Bold"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="TabItem">
                        <Border Name="Border" BorderThickness="1,1,1,0" BorderBrush="#233554" CornerRadius="4,4,0,0" Margin="2,0">
                            <ContentPresenter x:Name="ContentSite" VerticalAlignment="Center" HorizontalAlignment="Center" ContentSource="Header" Margin="12,2,12,2"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsSelected" Value="True">
                                <Setter TargetName="Border" Property="Background" Value="#233554" />
                                <Setter Property="Foreground" Value="#64ffda" />
                            </Trigger>
                            <Trigger Property="IsSelected" Value="False">
                                <Setter TargetName="Border" Property="Background" Value="#112240" />
                                <Setter Property="Foreground" Value="#8892b0" />
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <Style TargetType="DataGridRow">
            <Style.Triggers>
                <DataTrigger Binding="{Binding Status}" Value="FAIL"><Setter Property="Background" Value="#553c3c"/><Setter Property="Foreground" Value="#ffc1c1"/></DataTrigger>
                <DataTrigger Binding="{Binding Status}" Value="PASS"><Setter Property="Background" Value="#2f483a"/><Setter Property="Foreground" Value="#c1ffc1"/></DataTrigger>
                <DataTrigger Binding="{Binding Status}" Value="WARNING"><Setter Property="Background" Value="#55453c"/><Setter Property="Foreground" Value="#ffd1b3"/></DataTrigger>
            </Style.Triggers>
        </Style>
    </Window.Resources>
    
    <Grid>
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <Border Grid.Row="0" Background="#112240" Padding="10" BorderBrush="#233554" BorderThickness="0,0,0,1">
            <StackPanel Orientation="Horizontal">
                <Label Content="Target:" VerticalAlignment="Center" Foreground="#ccd6f6"/>
                <TextBox x:Name="TargetComputerTextBox" VerticalAlignment="Center" Width="150" Margin="5,0"/>
                <Label Content="Role:" VerticalAlignment="Center" Margin="10,0,0,0" Foreground="#ccd6f6"/>
                <TextBlock x:Name="SystemRoleTextBlock" Text="[Detecting...]" VerticalAlignment="Center" Width="120" Margin="5,0" Foreground="#8892b0" FontStyle="Italic"/>
            </StackPanel>
        </Border>

        <TabControl Grid.Row="1" Margin="10" Background="Transparent" BorderThickness="0">
            <TabItem Header="Configuration Audit">
                <Grid>
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                    </Grid.RowDefinitions>
                    <StackPanel Orientation="Horizontal" Margin="0,0,0,10">
                        <Button x:Name="RunAuditButton" Content="Run Config Audit" Width="140" Height="25" Background="#64ffda" Foreground="#0a192f" FontWeight="Bold"/>
                        <Button x:Name="ExportCsvButton" Content="Export CSV" Width="100" Height="25" Margin="10,0,0,0" Background="#233554" Foreground="#64ffda" FontWeight="Bold" IsEnabled="False"/>
                        <Button x:Name="ExportHtmlButton" Content="Export HTML" Width="100" Height="25" Margin="10,0,0,0" Background="#233554" Foreground="#64ffda" FontWeight="Bold" IsEnabled="False"/>
                    </StackPanel>
                    <DataGrid Grid.Row="1" x:Name="ResultsDataGrid" AutoGenerateColumns="False" IsReadOnly="True" Foreground="#ccd6f6" Background="#0a192f" BorderBrush="#233554">
                        <DataGrid.Columns>
                            <DataGridTextColumn Header="Status" Binding="{Binding Status}" FontWeight="Bold"/>
                            <DataGridTextColumn Header="Check ID" Binding="{Binding CheckID}"/>
                            <DataGridTextColumn Header="Description" Binding="{Binding Description}" Width="2*"/>
                            <DataGridTextColumn Header="Current Value" Binding="{Binding CurrentValue}" Width="*"/>
                            <DataGridTextColumn Header="Remediation" Binding="{Binding Remediation}" Width="2*"/>
                        </DataGrid.Columns>
                    </DataGrid>
                </Grid>
            </TabItem>

            <TabItem Header="File Activity Monitor">
                <Grid>
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                    </Grid.RowDefinitions>
                    <Border Background="#172a45" Padding="10" Margin="0,0,0,10" CornerRadius="5">
                        <WrapPanel Orientation="Horizontal">
                            <Label Content="Monitor Path:" Foreground="#ccd6f6" VerticalAlignment="Center"/>
                            <TextBox x:Name="MonitorPathBox" Width="200" Text="C:\" Margin="0,0,5,0" ToolTip="Folder to scan" VerticalAlignment="Center"/>
                            <Button x:Name="BrowseButton" Content="..." Width="30" Height="20" Margin="0,0,15,0" Background="#233554" Foreground="#ccd6f6"/>
                            <Label Content="Auth Groups:" Foreground="#ccd6f6" VerticalAlignment="Center"/>
                            <TextBox x:Name="AuthGroupsBox" Width="150" Text="Domain Admins" Margin="0,0,15,0" VerticalAlignment="Center"/>
                            <Label Content="Hours:" Foreground="#ccd6f6" VerticalAlignment="Center"/>
                            <TextBox x:Name="HoursBox" Width="30" Text="24" Margin="0,0,20,0" VerticalAlignment="Center"/>
                            <Button x:Name="ScanFilesButton" Content="Scan" Width="80" Height="25" Background="#64ffda" Foreground="#0a192f" FontWeight="Bold"/>
                            <Button x:Name="ExportFileCsvButton" Content="CSV" Width="60" Height="25" Margin="10,0,0,0" Background="#233554" Foreground="#64ffda" IsEnabled="False"/>
                            <Button x:Name="ExportFileHtmlButton" Content="HTML" Width="60" Height="25" Margin="5,0,0,0" Background="#233554" Foreground="#64ffda" IsEnabled="False"/>
                        </WrapPanel>
                    </Border>
                    <DataGrid Grid.Row="1" x:Name="FileActivityGrid" AutoGenerateColumns="False" IsReadOnly="True" Foreground="#ccd6f6" Background="#0a192f" BorderBrush="#233554">
                        <DataGrid.Columns>
                            <DataGridTextColumn Header="Status" Binding="{Binding Status}" FontWeight="Bold"/>
                            <DataGridTextColumn Header="Time" Binding="{Binding Timestamp}"/>
                            <DataGridTextColumn Header="User" Binding="{Binding UserName}" Width="*"/>
                            <DataGridTextColumn Header="File" Binding="{Binding FilePath}" Width="2*"/>
                            <DataGridTextColumn Header="Reason" Binding="{Binding Reason}" Width="*"/>
                        </DataGrid.Columns>
                    </DataGrid>
                </Grid>
            </TabItem>
            
            <TabItem Header="Raw Log">
                <DataGrid x:Name="LogDataGrid" AutoGenerateColumns="True" IsReadOnly="True" Foreground="#ccd6f6" Background="#0a192f"/>
            </TabItem>
        </TabControl>
        
        <StatusBar Grid.Row="2" Background="#112240" BorderBrush="#233554" BorderThickness="0,1,0,0">
            <StatusBarItem>
                <TextBlock x:Name="StatusTextBlock" Text="Ready" Foreground="#8892b0" Margin="5"/>
            </StatusBarItem>
        </StatusBar>
    </Grid>
</Window>
"@

# --- 5. INITIALIZE GUI ---
$reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($xaml.OuterXml))
$window = [System.Windows.Markup.XamlReader]::Load($reader)

# Connect Controls
$TargetBox = $window.FindName('TargetComputerTextBox')
$RoleBlock = $window.FindName('SystemRoleTextBlock')
$StatusBlock = $window.FindName('StatusTextBlock')
$RunButton = $window.FindName('RunAuditButton')
$ResultGrid = $window.FindName('ResultsDataGrid')
$LogGrid = $window.FindName('LogDataGrid')
$CsvButton = $window.FindName('ExportCsvButton')
$HtmlButton = $window.FindName('ExportHtmlButton')
$ScanButton = $window.FindName('ScanFilesButton')
$BrowseButton = $window.FindName('BrowseButton')
$MonitorPath = $window.FindName('MonitorPathBox')
$AuthGroups = $window.FindName('AuthGroupsBox')
$HoursBox = $window.FindName('HoursBox')
$FileGrid = $window.FindName('FileActivityGrid')
$FileCsvButton = $window.FindName('ExportFileCsvButton')
$FileHtmlButton = $window.FindName('ExportFileHtmlButton')

# --- 6. EVENT HANDLERS ---

# Auto Detect Role
$UpdateRole = {
    $comp = $TargetBox.Text
    $RoleBlock.Text = "Detecting..."
    $r = Get-SystemRole -ComputerName $comp
    $RoleBlock.Text = $r
    if($r -eq "Unreachable") { $RoleBlock.Foreground = "#ffc1c1" } else { $RoleBlock.Foreground = "#8892b0" }
}
$TargetBox.Add_LostFocus($UpdateRole)
$TargetBox.Text = $env:COMPUTERNAME
& $UpdateRole

# Config Audit
$RunButton.Add_Click({
    $RunButton.IsEnabled = $false; $window.Cursor = 'Wait'; $StatusBlock.Text = "Auditing..."
    [System.Windows.Forms.Application]::DoEvents()
    
    $mode = if($RoleBlock.Text -eq "Domain Controller"){"DomainController"}else{"StandaloneServer"}
    try {
        $res = Invoke-MultiFrameworkAudit -ComputerName $TargetBox.Text -Mode $mode
        $ResultGrid.ItemsSource = $res | ? { $_.Status -ne "SKIPPED" }
        $LogGrid.ItemsSource = $res
        $CsvButton.IsEnabled = $true; $HtmlButton.IsEnabled = $true
        $StatusBlock.Text = "Audit Complete."
    } catch {
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message)
    }
    $RunButton.IsEnabled = $true; $window.Cursor = 'Arrow'
})

# File Scan
$ScanButton.Add_Click({
    $ScanButton.IsEnabled = $false; $window.Cursor = 'Wait'; $StatusBlock.Text = "Scanning Logs..."
    [System.Windows.Forms.Application]::DoEvents()
    
    try {
        $res = @(Invoke-FileAccessAudit -Path $MonitorPath.Text -AuthorizedGroups $AuthGroups.Text -Hours $HoursBox.Text)
        $FileGrid.ItemsSource = $res
        $FileCsvButton.IsEnabled = $true; $FileHtmlButton.IsEnabled = $true
        $StatusBlock.Text = "Scan Complete: $($res.Count) events."
    } catch {
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message)
    }
    $ScanButton.IsEnabled = $true; $window.Cursor = 'Arrow'
})

# Browse
$BrowseButton.Add_Click({
    $d = New-Object System.Windows.Forms.FolderBrowserDialog
    if($d.ShowDialog() -eq 'OK') { $MonitorPath.Text = $d.SelectedPath }
})

# Exports
$CsvButton.Add_Click({
    $d = New-Object Microsoft.Win32.SaveFileDialog; $d.Filter="CSV|*.csv"; $d.FileName="Config.csv"
    if($d.ShowDialog() -eq $true) { $ResultGrid.ItemsSource | Export-Csv $d.FileName -NoTypeInformation }
})
$HtmlButton.Add_Click({
    $d = New-Object Microsoft.Win32.SaveFileDialog; $d.Filter="HTML|*.html"; $d.FileName="Config.html"
    if($d.ShowDialog() -eq $true) { 
        $h = $ResultGrid.ItemsSource | ConvertTo-Html -Head "<style>table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:8px}tr.PASS{background:#d4edda}tr.FAIL{background:#f8d7da}</style>" -Property Status,CheckID,Description,CurrentValue,Remediation,Requirement
        $f = ($h -join "`n") -replace "<tr><td>PASS", "<tr class='PASS'><td>PASS" -replace "<tr><td>FAIL", "<tr class='FAIL'><td>FAIL"
        $f | Out-File $d.FileName; Invoke-Item $d.FileName 
    }
})
$FileCsvButton.Add_Click({
    $d = New-Object Microsoft.Win32.SaveFileDialog; $d.Filter="CSV|*.csv"; $d.FileName="FileActivity.csv"
    if($d.ShowDialog() -eq $true) { $FileGrid.ItemsSource | Export-Csv $d.FileName -NoTypeInformation }
})
$FileHtmlButton.Add_Click({
    $d = New-Object Microsoft.Win32.SaveFileDialog; $d.Filter="HTML|*.html"; $d.FileName="FileActivity.html"
    if($d.ShowDialog() -eq $true) { 
        $h = $FileGrid.ItemsSource | ConvertTo-Html -Head "<style>table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:8px}tr.PASS{background:#d4edda}tr.WARNING{background:#fff3cd}</style>" -Property Status,Timestamp,UserName,FilePath,Reason
        $f = ($h -join "`n") -replace "<tr><td>PASS", "<tr class='PASS'><td>PASS" -replace "<tr><td>WARNING", "<tr class='WARNING'><td>WARNING"
        $f | Out-File $d.FileName; Invoke-Item $d.FileName 
    }
})

# --- 7. SHOW GUI ---
$window.ShowDialog() | Out-Null
