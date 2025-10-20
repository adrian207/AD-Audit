<#
.SYNOPSIS
    M&A Technical Discovery - Simple GUI Launcher

.DESCRIPTION
    User-friendly graphical interface for running M&A technical audits.
    No PowerShell knowledge required - just fill in the blanks and click Start.

.NOTES
    Author: Adrian Johnson <adrian207@gmail.com>
    Version: 2.0
    Requires: PowerShell 5.1+, Windows Forms
#>

#Requires -Version 5.1

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Create the main form
$form = New-Object System.Windows.Forms.Form
$form.Text = 'M&A Technical Discovery Audit'
$form.Size = New-Object System.Drawing.Size(750, 900)
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.MinimizeBox = $true
$form.Icon = [System.Drawing.SystemIcons]::Information
$form.AutoScroll = $true

# Title label
$titleLabel = New-Object System.Windows.Forms.Label
$titleLabel.Location = New-Object System.Drawing.Point(20, 20)
$titleLabel.Size = New-Object System.Drawing.Size(700, 40)
$titleLabel.Text = 'M&A Technical Discovery Audit Tool'
$titleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 18, [System.Drawing.FontStyle]::Bold)
$titleLabel.ForeColor = [System.Drawing.Color]::FromArgb(0, 102, 204)
$form.Controls.Add($titleLabel)

# Subtitle label
$subtitleLabel = New-Object System.Windows.Forms.Label
$subtitleLabel.Location = New-Object System.Drawing.Point(20, 60)
$subtitleLabel.Size = New-Object System.Drawing.Size(700, 25)
$subtitleLabel.Text = 'Comprehensive infrastructure audit for M&A due diligence'
$subtitleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$subtitleLabel.ForeColor = [System.Drawing.Color]::Gray
$form.Controls.Add($subtitleLabel)

# Separator line
$separator1 = New-Object System.Windows.Forms.Label
$separator1.Location = New-Object System.Drawing.Point(20, 90)
$separator1.Size = New-Object System.Drawing.Size(700, 2)
$separator1.BorderStyle = 'Fixed3D'
$form.Controls.Add($separator1)

#region Basic Settings

[int]$yPos = 110

# Company Name
$companyLabel = New-Object System.Windows.Forms.Label
$companyLabel.Location = New-Object System.Drawing.Point(20, $yPos)
$companyLabel.Size = New-Object System.Drawing.Size(200, 20)
$companyLabel.Text = 'Company Name: *'
$companyLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$form.Controls.Add($companyLabel)

$companyTextBox = New-Object System.Windows.Forms.TextBox
$companyTextBox.Location = New-Object System.Drawing.Point(220, $yPos)
$companyTextBox.Size = New-Object System.Drawing.Size(500, 25)
$companyTextBox.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$form.Controls.Add($companyTextBox)

$yPos += 40

# Output Folder
$outputLabel = New-Object System.Windows.Forms.Label
$outputLabel.Location = New-Object System.Drawing.Point(20, $yPos)
$outputLabel.Size = New-Object System.Drawing.Size(200, 20)
$outputLabel.Text = 'Save Results To: *'
$outputLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$form.Controls.Add($outputLabel)

$outputTextBox = New-Object System.Windows.Forms.TextBox
$outputTextBox.Location = New-Object System.Drawing.Point(220, $yPos)
$outputTextBox.Size = New-Object System.Drawing.Size(420, 25)
$outputTextBox.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$outputTextBox.Text = "C:\Audits"
$form.Controls.Add($outputTextBox)

$browseButton = New-Object System.Windows.Forms.Button
$browseButton.Location = New-Object System.Drawing.Point(645, ([int]$yPos - 2))
$browseButton.Size = New-Object System.Drawing.Size(75, 28)
$browseButton.Text = 'Browse...'
$browseButton.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$browseButton.Add_Click({
    $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderBrowser.Description = "Select folder to save audit results"
    $folderBrowser.SelectedPath = $outputTextBox.Text
    if ($folderBrowser.ShowDialog() -eq 'OK') {
        $outputTextBox.Text = $folderBrowser.SelectedPath
    }
})
$form.Controls.Add($browseButton)

$yPos += 40

# Report Title
$reportTitleLabel = New-Object System.Windows.Forms.Label
$reportTitleLabel.Location = New-Object System.Drawing.Point(20, $yPos)
$reportTitleLabel.Size = New-Object System.Drawing.Size(200, 20)
$reportTitleLabel.Text = 'Report Title:'
$reportTitleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$form.Controls.Add($reportTitleLabel)

$reportTitleTextBox = New-Object System.Windows.Forms.TextBox
$reportTitleTextBox.Location = New-Object System.Drawing.Point(220, $yPos)
$reportTitleTextBox.Size = New-Object System.Drawing.Size(500, 25)
$reportTitleTextBox.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$reportTitleTextBox.Text = "Q4 2025 M&A Technical Discovery"
$form.Controls.Add($reportTitleTextBox)

$yPos += 40

# Domain Name
$domainLabel = New-Object System.Windows.Forms.Label
$domainLabel.Location = New-Object System.Drawing.Point(20, $yPos)
$domainLabel.Size = New-Object System.Drawing.Size(200, 20)
$domainLabel.Text = 'Domain to Audit:'
$domainLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$form.Controls.Add($domainLabel)

$domainTextBox = New-Object System.Windows.Forms.TextBox
$domainTextBox.Location = New-Object System.Drawing.Point(220, $yPos)
$domainTextBox.Size = New-Object System.Drawing.Size(300, 25)
$domainTextBox.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$domainTextBox.Text = $env:USERDNSDOMAIN
$form.Controls.Add($domainTextBox)

$domainHelpLabel = New-Object System.Windows.Forms.Label
$domainHelpLabel.Location = New-Object System.Drawing.Point(525, ([int]$yPos + 2))
$domainHelpLabel.Size = New-Object System.Drawing.Size(195, 20)
$domainHelpLabel.Text = '(leave blank for current domain)'
$domainHelpLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Italic)
$domainHelpLabel.ForeColor = [System.Drawing.Color]::Gray
$form.Controls.Add($domainHelpLabel)

$yPos += 50

#endregion

#region What to Audit (GroupBox)

$auditGroupBox = New-Object System.Windows.Forms.GroupBox
$auditGroupBox.Location = New-Object System.Drawing.Point(20, $yPos)
$auditGroupBox.Size = New-Object System.Drawing.Size(700, 180)
$auditGroupBox.Text = ' What do you want to audit? '
$auditGroupBox.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$form.Controls.Add($auditGroupBox)

$cbYPos = 30

# Active Directory
$adCheckBox = New-Object System.Windows.Forms.CheckBox
$adCheckBox.Location = New-Object System.Drawing.Point(20, $cbYPos)
$adCheckBox.Size = New-Object System.Drawing.Size(650, 25)
$adCheckBox.Text = 'Active Directory (Users, Computers, Groups, Security)'
$adCheckBox.Checked = $true
$adCheckBox.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$auditGroupBox.Controls.Add($adCheckBox)

$cbYPos += 30

# Servers
$serverCheckBox = New-Object System.Windows.Forms.CheckBox
$serverCheckBox.Location = New-Object System.Drawing.Point(20, $cbYPos)
$serverCheckBox.Size = New-Object System.Drawing.Size(650, 25)
$serverCheckBox.Text = 'Servers (Hardware, Applications, Event Logs, Logon History)'
$serverCheckBox.Checked = $true
$serverCheckBox.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$auditGroupBox.Controls.Add($serverCheckBox)

$cbYPos += 30

# SQL Server
$sqlCheckBox = New-Object System.Windows.Forms.CheckBox
$sqlCheckBox.Location = New-Object System.Drawing.Point(20, $cbYPos)
$sqlCheckBox.Size = New-Object System.Drawing.Size(650, 25)
$sqlCheckBox.Text = 'SQL Server (Databases, Logins, Jobs, Backup Status)'
$sqlCheckBox.Checked = $true
$sqlCheckBox.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$auditGroupBox.Controls.Add($sqlCheckBox)

$cbYPos += 30

# Microsoft 365
$m365CheckBox = New-Object System.Windows.Forms.CheckBox
$m365CheckBox.Location = New-Object System.Drawing.Point(20, $cbYPos)
$m365CheckBox.Size = New-Object System.Drawing.Size(650, 25)
$m365CheckBox.Text = 'Microsoft 365 (Entra ID, Exchange, SharePoint, Teams)'
$m365CheckBox.Checked = $false
$m365CheckBox.Enabled = $false  # Not implemented yet
$m365CheckBox.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$auditGroupBox.Controls.Add($m365CheckBox)

# Coming soon label
$comingSoonLabel = New-Object System.Windows.Forms.Label
$comingSoonLabel.Location = New-Object System.Drawing.Point(40, ([int]$cbYPos + 25))
$comingSoonLabel.Size = New-Object System.Drawing.Size(200, 20)
$comingSoonLabel.Text = '(Coming soon)'
$comingSoonLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Italic)
$comingSoonLabel.ForeColor = [System.Drawing.Color]::Gray
$auditGroupBox.Controls.Add($comingSoonLabel)

$yPos += 190

#endregion

#region Audit Options (GroupBox)

$optionsGroupBox = New-Object System.Windows.Forms.GroupBox
$optionsGroupBox.Location = New-Object System.Drawing.Point(20, $yPos)
$optionsGroupBox.Size = New-Object System.Drawing.Size(700, 180)
$optionsGroupBox.Text = ' Audit Options '
$optionsGroupBox.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$form.Controls.Add($optionsGroupBox)

$optYPos = 30

# Event Log Days
$eventLogLabel = New-Object System.Windows.Forms.Label
$eventLogLabel.Location = New-Object System.Drawing.Point(20, $optYPos)
$eventLogLabel.Size = New-Object System.Drawing.Size(220, 20)
$eventLogLabel.Text = 'Event Logs (days back):'
$eventLogLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$optionsGroupBox.Controls.Add($eventLogLabel)

$eventLogComboBox = New-Object System.Windows.Forms.ComboBox
$eventLogComboBox.Location = New-Object System.Drawing.Point(240, ([int]$optYPos - 2))
$eventLogComboBox.Size = New-Object System.Drawing.Size(100, 25)
$eventLogComboBox.DropDownStyle = 'DropDownList'
$eventLogComboBox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
@('7 days', '30 days', '60 days', '90 days') | ForEach-Object { $eventLogComboBox.Items.Add($_) | Out-Null }
$eventLogComboBox.SelectedIndex = 1  # 30 days default
$optionsGroupBox.Controls.Add($eventLogComboBox)

# Logon History Days
$logonHistoryLabel = New-Object System.Windows.Forms.Label
$logonHistoryLabel.Location = New-Object System.Drawing.Point(360, $optYPos)
$logonHistoryLabel.Size = New-Object System.Drawing.Size(180, 20)
$logonHistoryLabel.Text = 'Logon History (days back):'
$logonHistoryLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$optionsGroupBox.Controls.Add($logonHistoryLabel)

$logonHistoryComboBox = New-Object System.Windows.Forms.ComboBox
$logonHistoryComboBox.Location = New-Object System.Drawing.Point(540, ([int]$optYPos - 2))
$logonHistoryComboBox.Size = New-Object System.Drawing.Size(100, 25)
$logonHistoryComboBox.DropDownStyle = 'DropDownList'
$logonHistoryComboBox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
@('30 days', '60 days', '90 days', '180 days', '365 days') | ForEach-Object { $logonHistoryComboBox.Items.Add($_) | Out-Null }
$logonHistoryComboBox.SelectedIndex = 2  # 90 days default
$optionsGroupBox.Controls.Add($logonHistoryComboBox)

$optYPos += 35

# Stale Account Threshold
$staleLabel = New-Object System.Windows.Forms.Label
$staleLabel.Location = New-Object System.Drawing.Point(20, $optYPos)
$staleLabel.Size = New-Object System.Drawing.Size(220, 20)
$staleLabel.Text = 'Consider accounts stale after:'
$staleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$optionsGroupBox.Controls.Add($staleLabel)

$staleComboBox = New-Object System.Windows.Forms.ComboBox
$staleComboBox.Location = New-Object System.Drawing.Point(240, ([int]$optYPos - 2))
$staleComboBox.Size = New-Object System.Drawing.Size(100, 25)
$staleComboBox.DropDownStyle = 'DropDownList'
$staleComboBox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
@('30 days', '60 days', '90 days', '180 days') | ForEach-Object { $staleComboBox.Items.Add($_) | Out-Null }
$staleComboBox.SelectedIndex = 2  # 90 days default
$optionsGroupBox.Controls.Add($staleComboBox)

# Parallel Servers
$parallelLabel = New-Object System.Windows.Forms.Label
$parallelLabel.Location = New-Object System.Drawing.Point(360, $optYPos)
$parallelLabel.Size = New-Object System.Drawing.Size(180, 20)
$parallelLabel.Text = 'Query servers in parallel:'
$parallelLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$optionsGroupBox.Controls.Add($parallelLabel)

$parallelNumeric = New-Object System.Windows.Forms.NumericUpDown
$parallelNumeric.Location = New-Object System.Drawing.Point(540, ([int]$optYPos - 2))
$parallelNumeric.Size = New-Object System.Drawing.Size(80, 25)
$parallelNumeric.Minimum = 1
$parallelNumeric.Maximum = 50
$parallelNumeric.Value = 10
$parallelNumeric.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$optionsGroupBox.Controls.Add($parallelNumeric)

$optYPos += 35

# Exclude Test/Lab OUs
$excludeTestCheckBox = New-Object System.Windows.Forms.CheckBox
$excludeTestCheckBox.Location = New-Object System.Drawing.Point(20, $optYPos)
$excludeTestCheckBox.Size = New-Object System.Drawing.Size(660, 20)
$excludeTestCheckBox.Text = 'Exclude test/lab/development environments (OUs with "test", "lab", "dev" in name)'
$excludeTestCheckBox.Checked = $true
$excludeTestCheckBox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$optionsGroupBox.Controls.Add($excludeTestCheckBox)

$optYPos += 30

# Specific OUs to Focus On
$focusOULabel = New-Object System.Windows.Forms.Label
$focusOULabel.Location = New-Object System.Drawing.Point(20, $optYPos)
$focusOULabel.Size = New-Object System.Drawing.Size(300, 20)
$focusOULabel.Text = 'Focus only on these OUs (optional, comma-separated):'
$focusOULabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$optionsGroupBox.Controls.Add($focusOULabel)

$optYPos += 22

$focusOUTextBox = New-Object System.Windows.Forms.TextBox
$focusOUTextBox.Location = New-Object System.Drawing.Point(20, $optYPos)
$focusOUTextBox.Size = New-Object System.Drawing.Size(660, 25)
$focusOUTextBox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$focusOUTextBox.Text = ""  # User will enter: OU=Production,DC=contoso,DC=com; OU=Corporate,DC=contoso,DC=com
$optionsGroupBox.Controls.Add($focusOUTextBox)

$yPos += 190

#endregion

#region Advanced Options (GroupBox)

$advancedGroupBox = New-Object System.Windows.Forms.GroupBox
$advancedGroupBox.Location = New-Object System.Drawing.Point(20, $yPos)
$advancedGroupBox.Size = New-Object System.Drawing.Size(700, 150)
$advancedGroupBox.Text = ' Advanced Options '
$advancedGroupBox.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$form.Controls.Add($advancedGroupBox)

$advYPos = 30

# Known SQL Instances
$sqlInstanceLabel = New-Object System.Windows.Forms.Label
$sqlInstanceLabel.Location = New-Object System.Drawing.Point(20, $advYPos)
$sqlInstanceLabel.Size = New-Object System.Drawing.Size(400, 20)
$sqlInstanceLabel.Text = 'Known SQL instances (if auto-discovery misses them):'
$sqlInstanceLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$advancedGroupBox.Controls.Add($sqlInstanceLabel)

$advYPos += 22

$sqlInstanceTextBox = New-Object System.Windows.Forms.TextBox
$sqlInstanceTextBox.Location = New-Object System.Drawing.Point(20, $advYPos)
$sqlInstanceTextBox.Size = New-Object System.Drawing.Size(660, 25)
$sqlInstanceTextBox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$sqlInstanceTextBox.Text = ""  # User will enter: SERVER1\SQL2019, SERVER2, SERVER3\INSTANCE1
$advancedGroupBox.Controls.Add($sqlInstanceTextBox)

$advYPos += 35

# Network Priority
$networkPriorityLabel = New-Object System.Windows.Forms.Label
$networkPriorityLabel.Location = New-Object System.Drawing.Point(20, $advYPos)
$networkPriorityLabel.Size = New-Object System.Drawing.Size(400, 20)
$networkPriorityLabel.Text = 'Prioritize these servers/locations (audited first):'
$networkPriorityLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$advancedGroupBox.Controls.Add($networkPriorityLabel)

$advYPos += 22

$networkPriorityTextBox = New-Object System.Windows.Forms.TextBox
$networkPriorityTextBox.Location = New-Object System.Drawing.Point(20, $advYPos)
$networkPriorityTextBox.Size = New-Object System.Drawing.Size(660, 25)
$networkPriorityTextBox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$networkPriorityTextBox.Text = ""  # User will enter: HQ-*, PROD-*, SQLSERVER* (wildcards supported)
$advancedGroupBox.Controls.Add($networkPriorityTextBox)

$yPos += 160

#endregion

#region Compliance & Notification

$complianceGroupBox = New-Object System.Windows.Forms.GroupBox
$complianceGroupBox.Location = New-Object System.Drawing.Point(20, $yPos)
$complianceGroupBox.Size = New-Object System.Drawing.Size(700, 130)
$complianceGroupBox.Text = ' Compliance & Notification '
$complianceGroupBox.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$form.Controls.Add($complianceGroupBox)

$compYPos = 30

# Compliance checkboxes
$complianceLabel = New-Object System.Windows.Forms.Label
$complianceLabel.Location = New-Object System.Drawing.Point(20, $compYPos)
$complianceLabel.Size = New-Object System.Drawing.Size(300, 20)
$complianceLabel.Text = 'Focus audit on these compliance requirements:'
$complianceLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$complianceGroupBox.Controls.Add($complianceLabel)

$compYPos += 25

# HIPAA
$hipaaCheckBox = New-Object System.Windows.Forms.CheckBox
$hipaaCheckBox.Location = New-Object System.Drawing.Point(40, $compYPos)
$hipaaCheckBox.Size = New-Object System.Drawing.Size(120, 20)
$hipaaCheckBox.Text = 'HIPAA'
$hipaaCheckBox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$complianceGroupBox.Controls.Add($hipaaCheckBox)

# PCI-DSS
$pciCheckBox = New-Object System.Windows.Forms.CheckBox
$pciCheckBox.Location = New-Object System.Drawing.Point(160, $compYPos)
$pciCheckBox.Size = New-Object System.Drawing.Size(120, 20)
$pciCheckBox.Text = 'PCI-DSS'
$pciCheckBox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$complianceGroupBox.Controls.Add($pciCheckBox)

# SOX
$soxCheckBox = New-Object System.Windows.Forms.CheckBox
$soxCheckBox.Location = New-Object System.Drawing.Point(280, $compYPos)
$soxCheckBox.Size = New-Object System.Drawing.Size(120, 20)
$soxCheckBox.Text = 'SOX'
$soxCheckBox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$complianceGroupBox.Controls.Add($soxCheckBox)

# ISO 27001
$isoCheckBox = New-Object System.Windows.Forms.CheckBox
$isoCheckBox.Location = New-Object System.Drawing.Point(400, $compYPos)
$isoCheckBox.Size = New-Object System.Drawing.Size(120, 20)
$isoCheckBox.Text = 'ISO 27001'
$isoCheckBox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$complianceGroupBox.Controls.Add($isoCheckBox)

# General
$generalCheckBox = New-Object System.Windows.Forms.CheckBox
$generalCheckBox.Location = New-Object System.Drawing.Point(520, $compYPos)
$generalCheckBox.Size = New-Object System.Drawing.Size(120, 20)
$generalCheckBox.Text = 'General'
$generalCheckBox.Checked = $true
$generalCheckBox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$complianceGroupBox.Controls.Add($generalCheckBox)

$compYPos += 30

# Email notification
$emailLabel = New-Object System.Windows.Forms.Label
$emailLabel.Location = New-Object System.Drawing.Point(20, $compYPos)
$emailLabel.Size = New-Object System.Drawing.Size(160, 20)
$emailLabel.Text = 'Email when complete:'
$emailLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$complianceGroupBox.Controls.Add($emailLabel)

$emailTextBox = New-Object System.Windows.Forms.TextBox
$emailTextBox.Location = New-Object System.Drawing.Point(180, ([int]$compYPos - 2))
$emailTextBox.Size = New-Object System.Drawing.Size(500, 25)
$emailTextBox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$emailTextBox.Text = ""  # Optional: your.email@company.com
$complianceGroupBox.Controls.Add($emailTextBox)

$yPos += 140

#endregion

#region Encryption Options

$encryptionCheckBox = New-Object System.Windows.Forms.CheckBox
$encryptionCheckBox.Location = New-Object System.Drawing.Point(20, $yPos)
$encryptionCheckBox.Size = New-Object System.Drawing.Size(400, 25)
$encryptionCheckBox.Text = 'Encrypt output files (recommended for security)'
$encryptionCheckBox.Checked = $true
$encryptionCheckBox.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$form.Controls.Add($encryptionCheckBox)

$yPos += 40

#endregion

#region Action Buttons

# Start Button
$startButton = New-Object System.Windows.Forms.Button
$startButton.Location = New-Object System.Drawing.Point(520, $yPos)
$startButton.Size = New-Object System.Drawing.Size(200, 45)
$startButton.Text = 'Start Audit'
$startButton.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
$startButton.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
$startButton.ForeColor = [System.Drawing.Color]::White
$startButton.FlatStyle = 'Flat'
$startButton.Cursor = [System.Windows.Forms.Cursors]::Hand
$startButton.Add_Click({
    # Validate inputs
    if ([string]::IsNullOrWhiteSpace($companyTextBox.Text)) {
        [System.Windows.Forms.MessageBox]::Show(
            "Please enter a company name.",
            "Missing Information",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        return
    }
    
    if ([string]::IsNullOrWhiteSpace($outputTextBox.Text)) {
        [System.Windows.Forms.MessageBox]::Show(
            "Please select an output folder.",
            "Missing Information",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        return
    }
    
    if (-not $adCheckBox.Checked -and -not $serverCheckBox.Checked -and -not $sqlCheckBox.Checked -and -not $m365CheckBox.Checked) {
        [System.Windows.Forms.MessageBox]::Show(
            "Please select at least one item to audit.",
            "Nothing Selected",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        return
    }
    
    # Build command parameters
    $script:AuditParams = @{
        CompanyName = $companyTextBox.Text.Trim()
        OutputFolder = $outputTextBox.Text.Trim()
        ServerInventory = $serverCheckBox.Checked
        ServerEventLogDays = [int]($eventLogComboBox.SelectedItem -replace ' days', '')
        ServerLogonHistoryDays = [int]($logonHistoryComboBox.SelectedItem -replace ' days', '')
        MaxParallelServers = [int]$parallelNumeric.Value
        SkipAD = -not $adCheckBox.Checked
        SkipSQL = -not $sqlCheckBox.Checked
        Verbose = $true
    }
    
    # Additional parameters
    $script:AuditParams['ReportTitle'] = $reportTitleTextBox.Text.Trim()
    $script:AuditParams['DomainName'] = $domainTextBox.Text.Trim()
    $script:AuditParams['StaleThresholdDays'] = [int]($staleComboBox.SelectedItem -replace ' days', '')
    $script:AuditParams['ExcludeTestOUs'] = $excludeTestCheckBox.Checked
    
    if (-not [string]::IsNullOrWhiteSpace($focusOUTextBox.Text)) {
        $script:AuditParams['FocusOUs'] = $focusOUTextBox.Text.Trim()
    }
    
    if (-not [string]::IsNullOrWhiteSpace($sqlInstanceTextBox.Text)) {
        $script:AuditParams['KnownSQLInstances'] = $sqlInstanceTextBox.Text.Trim()
    }
    
    if (-not [string]::IsNullOrWhiteSpace($networkPriorityTextBox.Text)) {
        $script:AuditParams['PriorityServers'] = $networkPriorityTextBox.Text.Trim()
    }
    
    # Compliance flags
    $complianceTypes = @()
    if ($hipaaCheckBox.Checked) { $complianceTypes += 'HIPAA' }
    if ($pciCheckBox.Checked) { $complianceTypes += 'PCI-DSS' }
    if ($soxCheckBox.Checked) { $complianceTypes += 'SOX' }
    if ($isoCheckBox.Checked) { $complianceTypes += 'ISO27001' }
    if ($generalCheckBox.Checked) { $complianceTypes += 'General' }
    
    if ($complianceTypes.Count -gt 0) {
        $script:AuditParams['ComplianceFocus'] = ($complianceTypes -join ',')
    }
    
    if (-not [string]::IsNullOrWhiteSpace($emailTextBox.Text)) {
        $script:AuditParams['NotificationEmail'] = $emailTextBox.Text.Trim()
    }
    
    if (-not $encryptionCheckBox.Checked) {
        $script:AuditParams['SkipEncryption'] = $true
    }
    
    # Confirm before starting
    $estimatedTime = if ($serverCheckBox.Checked) { "1-4 hours" } else { "30-60 minutes" }
    $confirmResult = [System.Windows.Forms.MessageBox]::Show(
        "Ready to start audit for: $($companyTextBox.Text)`n`nEstimated time: $estimatedTime`n`nDo you want to continue?",
        "Confirm Audit Start",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Question
    )
    
    if ($confirmResult -eq 'Yes') {
        $form.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $form.Close()
    }
})
$form.Controls.Add($startButton)

# Help Button
$helpButton = New-Object System.Windows.Forms.Button
$helpButton.Location = New-Object System.Drawing.Point(410, $yPos)
$helpButton.Size = New-Object System.Drawing.Size(100, 45)
$helpButton.Text = 'Help'
$helpButton.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$helpButton.FlatStyle = 'Flat'
$helpButton.Add_Click({
    $helpText = @"
M&A Technical Discovery Audit Tool - Quick Help

What this tool does:
• Audits your Microsoft infrastructure (Active Directory, servers, SQL, M365)
• Identifies migration blockers and security risks
• Estimates data volumes and migration timelines
• Generates executive reports and detailed CSV exports

How to use:
1. Enter the company name you're auditing
2. Choose where to save the results
3. Select what you want to audit
4. Configure options (use defaults if unsure)
5. Click "Start Audit"

The audit runs read-only - it won't make any changes.

Results will include:
• Executive dashboard (HTML)
• Security findings report
• Migration blocker analysis
• 60+ CSV files with detailed data

Tips:
• Higher parallel servers = faster audit (uses more resources)
• Exclude test OUs to speed up audit and improve data quality
• Use compliance focus to tailor reports to your requirements
• Email notification recommended for long audits (2-4 hours)

Need help? Contact: adrian207@gmail.com
Full documentation: docs\README.md
"@
    [System.Windows.Forms.MessageBox]::Show(
        $helpText,
        "Help - M&A Audit Tool",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
    )
})
$form.Controls.Add($helpButton)

# Cancel Button
$cancelButton = New-Object System.Windows.Forms.Button
$cancelButton.Location = New-Object System.Drawing.Point(20, $yPos)
$cancelButton.Size = New-Object System.Drawing.Size(100, 45)
$cancelButton.Text = 'Cancel'
$cancelButton.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$cancelButton.FlatStyle = 'Flat'
$cancelButton.Add_Click({
    $form.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.Close()
})
$form.Controls.Add($cancelButton)

$yPos += 60

#endregion

#region Footer

$footerLabel = New-Object System.Windows.Forms.Label
$footerLabel.Location = New-Object System.Drawing.Point(20, $yPos)
$footerLabel.Size = New-Object System.Drawing.Size(700, 20)
$footerLabel.Text = 'M&A Technical Discovery v2.0 | Author: Adrian Johnson | adrian207@gmail.com'
$footerLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
$footerLabel.ForeColor = [System.Drawing.Color]::Gray
$footerLabel.TextAlign = 'MiddleCenter'
$form.Controls.Add($footerLabel)

#endregion

# Show the form
$result = $form.ShowDialog()

if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
    # User clicked Start - launch the audit
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "   Launching M&A Audit..." -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Company: $($script:AuditParams.CompanyName)" -ForegroundColor White
    Write-Host "Output: $($script:AuditParams.OutputFolder)" -ForegroundColor White
    Write-Host ""
    Write-Host "A new PowerShell window will open to run the audit." -ForegroundColor Yellow
    Write-Host "DO NOT CLOSE this window - monitor progress there." -ForegroundColor Yellow
    Write-Host ""
    
    # Build the command string
    $scriptPath = Join-Path $PSScriptRoot "Run-M&A-Audit.ps1"
    
    # Convert hashtable to parameter string
    $paramString = ""
    foreach ($key in $script:AuditParams.Keys) {
        $value = $script:AuditParams[$key]
        if ($value -is [bool]) {
            if ($value) {
                $paramString += " -$key"
            }
        }
        elseif ($value -is [int]) {
            $paramString += " -$key $value"
        }
        else {
            $paramString += " -$key '$value'"
        }
    }
    
    # Launch in new PowerShell window
    $command = "& '$scriptPath' $paramString; Write-Host ''; Write-Host 'Press any key to close this window...' -ForegroundColor Yellow; `$null = `$Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')"
    
    Start-Process powershell.exe -ArgumentList "-NoExit", "-ExecutionPolicy Bypass", "-Command $command"
    
    Write-Host "Audit launched successfully!" -ForegroundColor Green
    Write-Host ""
}
else {
    Write-Host "Audit cancelled by user." -ForegroundColor Yellow
}
