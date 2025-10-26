<#
.SYNOPSIS
    M&A Audit Database - Visual Query Builder (PROOF OF CONCEPT)
    
.DESCRIPTION
    ServiceNow-style query builder for non-technical users to query the SQLite audit database.
    This is a PROOF OF CONCEPT showing the basic structure.
    
.NOTES
    Author: Adrian Johnson <adrian207@gmail.com>
    Status: POC - Not production ready (needs 16-20 hours to complete)
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Script variables
$script:DatabasePath = ""
$script:DatabaseConnection = $null
$script:SelectedTable = ""
$script:Conditions = @()

#region Helper Functions

function Get-DatabaseSchema {
    <#
    .SYNOPSIS
        Reads database schema and returns table and column information
    #>
    param(
        [Parameter(Mandatory = $true)]
        [System.Data.SQLite.SQLiteConnection]$Connection
    )
    
    $schema = @{}
    
    # Get list of tables
    $tablesQuery = "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    $command = $Connection.CreateCommand()
    $command.CommandText = $tablesQuery
    $reader = $command.ExecuteReader()
    
    while ($reader.Read()) {
        $tableName = $reader["name"]
        
        # Get columns for this table
        $columnsQuery = "PRAGMA table_info('$tableName')"
        $colCommand = $Connection.CreateCommand()
        $colCommand.CommandText = $columnsQuery
        $colReader = $colCommand.ExecuteReader()
        
        $columns = @()
        while ($colReader.Read()) {
            $columns += [PSCustomObject]@{
                Name = $colReader["name"]
                Type = $colReader["type"]
                NotNull = $colReader["notnull"]
                PrimaryKey = $colReader["pk"]
            }
        }
        $colReader.Close()
        
        $schema[$tableName] = $columns
    }
    $reader.Close()
    
    return $schema
}

function Build-SQLQuery {
    <#
    .SYNOPSIS
        Builds SQL query from UI selections
    #>
    param(
        [string]$TableName,
        [array]$Columns,
        [array]$Conditions
    )
    
    # Build SELECT clause
    $selectClause = if ($Columns.Count -eq 0) {
        "*"
    } else {
        ($Columns | ForEach-Object { "[$_]" }) -join ", "
    }
    
    $query = "SELECT $selectClause`nFROM [$TableName]"
    
    # Build WHERE clause
    if ($Conditions.Count -gt 0) {
        $whereConditions = @()
        foreach ($condition in $Conditions) {
            $field = $condition.Field
            $operator = $condition.Operator
            $value = $condition.Value
            $logic = $condition.Logic
            
            # Format value based on operator
            if ($operator -eq "IS NULL" -or $operator -eq "IS NOT NULL") {
                $whereConditions += "$logic [$field] $operator"
            }
            elseif ($operator -eq "LIKE") {
                $whereConditions += "$logic [$field] LIKE '%$value%'"
            }
            else {
                # Try to detect if value is numeric
                $numValue = 0
                if ([int]::TryParse($value, [ref]$numValue)) {
                    $whereConditions += "$logic [$field] $operator $value"
                }
                else {
                    $whereConditions += "$logic [$field] $operator '$value'"
                }
            }
        }
        
        # Remove first logic (AND/OR) from first condition
        if ($whereConditions.Count -gt 0) {
            $whereConditions[0] = $whereConditions[0] -replace "^(AND|OR) ", ""
        }
        
        $query += "`nWHERE " + ($whereConditions -join " ")
    }
    
    return $query
}

function Invoke-DatabaseQuery {
    <#
    .SYNOPSIS
        Executes SQL query and returns results as DataTable
    #>
    param(
        [Parameter(Mandatory = $true)]
        [System.Data.SQLite.SQLiteConnection]$Connection,
        
        [Parameter(Mandatory = $true)]
        [string]$Query
    )
    
    try {
        $command = $Connection.CreateCommand()
        $command.CommandText = $Query
        
        $adapter = New-Object System.Data.SQLite.SQLiteDataAdapter($command)
        $dataSet = New-Object System.Data.DataSet
        [void]$adapter.Fill($dataSet)
        
        return $dataSet.Tables[0]
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show(
            "Query execution failed:`n`n$($_.Exception.Message)",
            "Query Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
        return $null
    }
}

#endregion

#region GUI Creation

# Create main form
$form = New-Object System.Windows.Forms.Form
$form.Text = "M&A Audit Database - Query Builder (POC)"
$form.Size = New-Object System.Drawing.Size(900, 750)
$form.StartPosition = "CenterScreen"
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$form.BackColor = [System.Drawing.Color]::White

# Create title label
$titleLabel = New-Object System.Windows.Forms.Label
$titleLabel.Location = New-Object System.Drawing.Point(20, 20)
$titleLabel.Size = New-Object System.Drawing.Size(860, 30)
$titleLabel.Text = "Visual Query Builder - Proof of Concept"
$titleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
$titleLabel.ForeColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
$form.Controls.Add($titleLabel)

$yPos = 60

# Database path section
$dbLabel = New-Object System.Windows.Forms.Label
$dbLabel.Location = New-Object System.Drawing.Point(20, $yPos)
$dbLabel.Size = New-Object System.Drawing.Size(100, 20)
$dbLabel.Text = "Database:"
$form.Controls.Add($dbLabel)

$dbTextBox = New-Object System.Windows.Forms.TextBox
$dbTextBox.Location = New-Object System.Drawing.Point(120, $yPos - 2)
$dbTextBox.Size = New-Object System.Drawing.Size(600, 25)
$form.Controls.Add($dbTextBox)

$dbBrowseButton = New-Object System.Windows.Forms.Button
$dbBrowseButton.Location = New-Object System.Drawing.Point(730, $yPos - 2)
$dbBrowseButton.Size = New-Object System.Drawing.Size(80, 25)
$dbBrowseButton.Text = "Browse..."
$dbBrowseButton.Add_Click({
    $openDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openDialog.Filter = "SQLite Database (*.db)|*.db|All Files (*.*)|*.*"
    $openDialog.Title = "Select Audit Database"
    
    if ($openDialog.ShowDialog() -eq 'OK') {
        $dbTextBox.Text = $openDialog.FileName
        
        # Try to connect
        try {
            if ($script:DatabaseConnection) {
                $script:DatabaseConnection.Close()
            }
            
            # Load SQLite assembly
            $sqliteDll = Join-Path $PSScriptRoot "Libraries\System.Data.SQLite.dll"
            if (Test-Path $sqliteDll) {
                Add-Type -Path $sqliteDll
            } else {
                Add-Type -AssemblyName "System.Data.SQLite"
            }
            
            $script:DatabaseConnection = New-Object System.Data.SQLite.SQLiteConnection("Data Source=$($openDialog.FileName);Version=3;")
            $script:DatabaseConnection.Open()
            
            # Load schema
            $schema = Get-DatabaseSchema -Connection $script:DatabaseConnection
            
            # Populate table dropdown
            $tableComboBox.Items.Clear()
            foreach ($table in ($schema.Keys | Sort-Object)) {
                [void]$tableComboBox.Items.Add($table)
            }
            
            [System.Windows.Forms.MessageBox]::Show(
                "Connected successfully!`n`nFound $($schema.Keys.Count) tables.",
                "Database Connected",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to connect to database:`n`n$($_.Exception.Message)",
                "Connection Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        }
    }
})
$form.Controls.Add($dbBrowseButton)

$yPos += 40

# Table selection section
$tableGroupBox = New-Object System.Windows.Forms.GroupBox
$tableGroupBox.Location = New-Object System.Drawing.Point(20, $yPos)
$tableGroupBox.Size = New-Object System.Drawing.Size(420, 350)
$tableGroupBox.Text = "1. Select Table & Columns"
$form.Controls.Add($tableGroupBox)

$tableLabel = New-Object System.Windows.Forms.Label
$tableLabel.Location = New-Object System.Drawing.Point(10, 25)
$tableLabel.Size = New-Object System.Drawing.Size(100, 20)
$tableLabel.Text = "Table:"
$tableGroupBox.Controls.Add($tableLabel)

$tableComboBox = New-Object System.Windows.Forms.ComboBox
$tableComboBox.Location = New-Object System.Drawing.Point(110, 23)
$tableComboBox.Size = New-Object System.Drawing.Size(290, 25)
$tableComboBox.DropDownStyle = 'DropDownList'
$tableComboBox.Add_SelectedIndexChanged({
    # Load columns for selected table
    if ($script:DatabaseConnection -and $tableComboBox.SelectedItem) {
        $selectedTable = $tableComboBox.SelectedItem
        $columnsQuery = "PRAGMA table_info('$selectedTable')"
        
        $command = $script:DatabaseConnection.CreateCommand()
        $command.CommandText = $columnsQuery
        $reader = $command.ExecuteReader()
        
        $columnListBox.Items.Clear()
        while ($reader.Read()) {
            [void]$columnListBox.Items.Add($reader["name"], $true)  # All checked by default
        }
        $reader.Close()
    }
})
$tableGroupBox.Controls.Add($tableComboBox)

$columnsLabel = New-Object System.Windows.Forms.Label
$columnsLabel.Location = New-Object System.Drawing.Point(10, 60)
$columnsLabel.Size = New-Object System.Drawing.Size(100, 20)
$columnsLabel.Text = "Columns:"
$tableGroupBox.Controls.Add($columnsLabel)

$columnListBox = New-Object System.Windows.Forms.CheckedListBox
$columnListBox.Location = New-Object System.Drawing.Point(10, 85)
$columnListBox.Size = New-Object System.Drawing.Size(390, 250)
$columnListBox.CheckOnClick = $true
$tableGroupBox.Controls.Add($columnListBox)

# Filters section (simplified - POC only shows concept)
$filtersGroupBox = New-Object System.Windows.Forms.GroupBox
$filtersGroupBox.Location = New-Object System.Drawing.Point(460, $yPos)
$filtersGroupBox.Size = New-Object System.Drawing.Size(410, 350)
$filtersGroupBox.Text = "2. Add Filters (WHERE)"
$form.Controls.Add($filtersGroupBox)

$filtersLabel = New-Object System.Windows.Forms.Label
$filtersLabel.Location = New-Object System.Drawing.Point(10, 25)
$filtersLabel.Size = New-Object System.Drawing.Size(380, 40)
$filtersLabel.Text = "POC: Filters would be added here with dynamic controls`n(Field / Operator / Value dropdowns + textboxes)"
$filtersLabel.ForeColor = [System.Drawing.Color]::Gray
$filtersGroupBox.Controls.Add($filtersLabel)

$addFilterButton = New-Object System.Windows.Forms.Button
$addFilterButton.Location = New-Object System.Drawing.Point(10, 70)
$addFilterButton.Size = New-Object System.Drawing.Size(120, 30)
$addFilterButton.Text = "+ Add Condition"
$addFilterButton.Enabled = $false  # POC - not implemented
$filtersGroupBox.Controls.Add($addFilterButton)

$yPos += 360

# SQL Preview section
$sqlGroupBox = New-Object System.Windows.Forms.GroupBox
$sqlGroupBox.Location = New-Object System.Drawing.Point(20, $yPos)
$sqlGroupBox.Size = New-Object System.Drawing.Size(850, 120)
$sqlGroupBox.Text = "Generated SQL"
$form.Controls.Add($sqlGroupBox)

$sqlTextBox = New-Object System.Windows.Forms.TextBox
$sqlTextBox.Location = New-Object System.Drawing.Point(10, 20)
$sqlTextBox.Size = New-Object System.Drawing.Size(830, 90)
$sqlTextBox.Multiline = $true
$sqlTextBox.ScrollBars = 'Vertical'
$sqlTextBox.ReadOnly = $true
$sqlTextBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$sqlGroupBox.Controls.Add($sqlTextBox)

$yPos += 130

# Action buttons
$executeButton = New-Object System.Windows.Forms.Button
$executeButton.Location = New-Object System.Drawing.Point(520, $yPos)
$executeButton.Size = New-Object System.Drawing.Size(120, 35)
$executeButton.Text = "Execute Query"
$executeButton.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$executeButton.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
$executeButton.ForeColor = [System.Drawing.Color]::White
$executeButton.FlatStyle = 'Flat'
$executeButton.Add_Click({
    if (-not $script:DatabaseConnection) {
        [System.Windows.Forms.MessageBox]::Show(
            "Please connect to a database first.",
            "No Database",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        return
    }
    
    if (-not $tableComboBox.SelectedItem) {
        [System.Windows.Forms.MessageBox]::Show(
            "Please select a table first.",
            "No Table Selected",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        return
    }
    
    # Get selected columns
    $selectedColumns = @()
    foreach ($item in $columnListBox.CheckedItems) {
        $selectedColumns += $item
    }
    
    # Build and execute query
    $query = Build-SQLQuery -TableName $tableComboBox.SelectedItem -Columns $selectedColumns -Conditions @()
    $sqlTextBox.Text = $query
    
    # Execute and display results (POC - would show in DataGridView)
    $results = Invoke-DatabaseQuery -Connection $script:DatabaseConnection -Query $query
    
    if ($results) {
        $rowCount = $results.Rows.Count
        [System.Windows.Forms.MessageBox]::Show(
            "Query executed successfully!`n`nRows returned: $rowCount`n`n(POC: Results would display in DataGridView below)",
            "Query Successful",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
    }
})
$form.Controls.Add($executeButton)

$copyButton = New-Object System.Windows.Forms.Button
$copyButton.Location = New-Object System.Drawing.Point(650, $yPos)
$copyButton.Size = New-Object System.Drawing.Size(100, 35)
$copyButton.Text = "Copy SQL"
$copyButton.Add_Click({
    if ($sqlTextBox.Text) {
        [System.Windows.Forms.Clipboard]::SetText($sqlTextBox.Text)
        [System.Windows.Forms.MessageBox]::Show(
            "SQL copied to clipboard!",
            "Copied",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
    }
})
$form.Controls.Add($copyButton)

$clearButton = New-Object System.Windows.Forms.Button
$clearButton.Location = New-Object System.Drawing.Point(760, $yPos)
$clearButton.Size = New-Object System.Drawing.Size(100, 35)
$clearButton.Text = "Clear"
$clearButton.Add_Click({
    $tableComboBox.SelectedIndex = -1
    $columnListBox.Items.Clear()
    $sqlTextBox.Text = ""
})
$form.Controls.Add($clearButton)

# Footer
$footerLabel = New-Object System.Windows.Forms.Label
$footerLabel.Location = New-Object System.Drawing.Point(20, 690)
$footerLabel.Size = New-Object System.Drawing.Size(850, 20)
$footerLabel.Text = "POC STATUS: Basic structure only • Full implementation: 16-20 hours • Author: Adrian Johnson"
$footerLabel.ForeColor = [System.Drawing.Color]::Gray
$footerLabel.TextAlign = 'MiddleCenter'
$form.Controls.Add($footerLabel)

#endregion

# Show the form
[void]$form.ShowDialog()

# Cleanup
if ($script:DatabaseConnection) {
    $script:DatabaseConnection.Close()
}

