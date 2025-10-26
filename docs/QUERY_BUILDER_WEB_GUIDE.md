# Web-Based Query Builder - User Guide

> Executive summary: Use the web query builder to explore the audit database visually—connect, select tables/columns, add filters, and export results.
>
> Key recommendations:
> - Let the server auto-detect the latest database; specify a path if needed
> - Use filters and column selection to keep queries fast
> - Leverage templates for common questions; copy SQL when you need it
>
> Supporting points:
> - Multi-user, remote access; CSV export built-in
> - Safe SELECT-only execution with preview
> - Works with mobile devices and modern browsers

**Author**: Adrian Johnson <adrian207@gmail.com>

---

## Quick Start (5 minutes)

### Step 1: Install Pode
```powershell
Install-Module Pode -Scope CurrentUser -Force
```

### Step 2: Start the Server
```powershell
cd C:\Users\adria\OneDrive\Documents\GitHub\Ad-Audit\AD-Audit
.\Start-M&A-QueryBuilder-Web.ps1
```

### Step 3: Open Browser
Navigate to: **`http://localhost:5000`**

**That's it!** The query builder is now running.

---

## Features

### ✅ What You Can Do

1. **Browse Database Schema** - See all tables and columns
2. **Visual Query Builder** - Point-and-click query construction
3. **Add Filters (WHERE)** - Multiple conditions with AND/OR logic
4. **Execute Queries** - Run SELECT queries safely
5. **View Results** - Modern, sortable table view
6. **Export to CSV** - Download results with one click
7. **Pre-built Templates** - 8 common queries ready to use
8. **SQL Preview** - See generated SQL before execution
9. **Multi-User** - Multiple people can use simultaneously
10. **Remote Access** - Access from any device with browser

---

## Usage Guide

### Connecting to Database

#### Auto-Detection (Recommended)
- When you start the server, it automatically searches for the most recent `AuditData.db`
- Click "Connect" with empty path field
- Server will use auto-detected database

#### Manual Path
1. Enter full path to database: `C:\Audits\Contoso\AuditData.db`
2. Click "Connect"
3. UI will update with available tables

### Building a Query

#### Step 1: Select Table
1. Choose table from dropdown
2. All columns will be checked by default
3. Uncheck columns you don't need

**Quick Actions:**
- **Select All** - Check all columns
- **Deselect All** - Uncheck all columns
- **View Sample** - See first 10 rows of table

#### Step 2: Add Filters (Optional)
1. Click "+ Add Filter"
2. Select field from dropdown
3. Choose operator:
   - `=` - Equals
   - `!=` - Not equals
   - `<`, `>`, `<=`, `>=` - Comparisons
   - `LIKE` - Text search (auto-adds wildcards)
   - `IS NULL`, `IS NOT NULL` - Null checks
4. Enter value
5. Choose AND/OR logic for multiple filters

**Example Filter:**
```
AND Department = IT
AND Enabled = 1
AND DaysSinceLastLogon > 90
```

#### Step 3: Review SQL
- Generated SQL appears in "Generated SQL" section
- Click "Copy SQL" to copy to clipboard
- Verify query looks correct

#### Step 4: Execute
1. Click "Execute Query" button
2. Wait for results (usually < 1 second)
3. Results appear below

#### Step 5: Export (Optional)
- Click "Export CSV" to download results
- File name includes timestamp
- Opens directly in Excel or similar

---

## Using Query Templates

### Available Templates

#### Security Category
1. **Stale Privileged Accounts**
   - Admin accounts inactive 90+ days
   - Critical security finding

2. **Service Account Inventory**
   - All detected service accounts
   - SPN details included

#### SQL Category
3. **SQL Backup Risk Servers**
   - Databases without recent backups
   - Sorted by size (largest first)

4. **SQL Server Inventory Summary**
   - All SQL instances
   - Version and edition details

#### Servers Category
5. **Top 20 Applications by Server Count**
   - Most deployed applications
   - Useful for licensing

6. **Virtual vs Physical Servers**
   - Virtualization breakdown
   - Resource totals

#### Active Directory Category
7. **Stale Computer Accounts**
   - Computers inactive 90+ days

8. **Users by Department**
   - User counts and status

### Using a Template
1. Find template in right panel
2. Click template name
3. SQL loads in preview
4. Click "Execute Query"
5. Modify if needed

---

## Advanced Features

### Multi-User Access

#### Local Access (Default)
```powershell
.\Start-M&A-QueryBuilder-Web.ps1
```
Access: `http://localhost:5000`

#### Network Access
```powershell
.\Start-M&A-QueryBuilder-Web.ps1 -Address "0.0.0.0" -Port 5000
```
Access from other computers: `http://YOUR-SERVER-NAME:5000`

**Firewall Rule Needed:**
```powershell
# Run as Administrator
New-NetFirewallRule -DisplayName "M&A Query Builder" `
    -Direction Inbound -LocalPort 5000 -Protocol TCP -Action Allow
```

#### Custom Port
```powershell
.\Start-M&A-QueryBuilder-Web.ps1 -Port 8080
```
Access: `http://localhost:8080`

### Connecting to Specific Database
```powershell
.\Start-M&A-QueryBuilder-Web.ps1 -DatabasePath "C:\Audits\Contoso\AuditData.db"
```

### Running in Background
```powershell
# Start as background job
Start-Job -ScriptBlock {
    Set-Location "C:\AD-Audit"
    .\Start-M&A-QueryBuilder-Web.ps1 -Address "0.0.0.0"
}

# Check status
Get-Job

# Stop server
Stop-Job -Name Job1
```

---

## Example Queries

### Example 1: Find Admins in Specific Department
**Goal**: Find all IT department users in privileged groups

**Steps**:
1. Select table: `PrivilegedAccounts`
2. Join would be needed (use template or raw SQL)
3. Or use template "Stale Privileged Accounts" and modify

**Template SQL**:
```sql
SELECT 
    u.SamAccountName,
    u.DisplayName,
    u.Department,
    pa.GroupName
FROM Users u
INNER JOIN PrivilegedAccounts pa 
    ON u.SamAccountName = pa.MemberSamAccountName
WHERE u.Department = 'IT'
ORDER BY pa.GroupName
```

### Example 2: Large Databases Without Backups
**Goal**: Find SQL databases >50GB with no recent backup

**Steps**:
1. Select table: `SQLDatabases`
2. Add filter: `SizeGB > 50`
3. Add filter: `BackupIssue IS NOT NULL`
4. Execute

**Or use template**: "SQL Backup Risk Servers"

### Example 3: Application Inventory
**Goal**: List all servers running specific application

**Steps**:
1. Select table: `ServerApplications`
2. Columns: `ServerName`, `ApplicationName`, `Version`
3. Add filter: `ApplicationName LIKE Microsoft`
4. Execute

---

## Troubleshooting

### "Pode module not found"
**Solution**: Install Pode
```powershell
Install-Module Pode -Scope CurrentUser -Force
```

### "Database file not found"
**Solution 1**: Let server auto-detect
- Leave path blank
- Click "Connect"

**Solution 2**: Specify full path
- Enter complete path: `C:\Audits\...\AuditData.db`
- Click "Connect"

### "Connection failed"
**Possible causes**:
1. Database file doesn't exist
2. File is locked by another process
3. Insufficient permissions

**Solution**: Check file exists and is accessible
```powershell
Test-Path "C:\Audits\Contoso\AuditData.db"
```

### "Query execution failed"
**Common causes**:
1. Invalid SQL syntax
2. Non-existent column name
3. Query timeout

**Solution**: 
- Check SQL preview
- Verify column names match schema
- Simplify query

### Can't Access from Other Computer
**Solution**: Allow firewall
```powershell
# Run as Administrator
New-NetFirewallRule -DisplayName "M&A Query Builder" `
    -Direction Inbound -LocalPort 5000 -Protocol TCP -Action Allow
```

### Page Won't Load
**Check**:
1. Is server still running? (Look at PowerShell window)
2. Is port correct? (Default: 5000)
3. Is URL correct? (`http://localhost:5000`)

**Restart server**:
- Press Ctrl+C in PowerShell window
- Re-run: `.\Start-M&A-QueryBuilder-Web.ps1`

---

## Security Considerations

### What's Protected

1. ✅ **Read-Only**: Only SELECT queries allowed
2. ✅ **No Modifications**: Cannot UPDATE, DELETE, DROP
3. ✅ **SQL Injection Prevention**: Parameterized queries
4. ✅ **Row Limit**: Max 1000 rows per query
5. ✅ **Timeout**: 30-second query timeout

### Network Security

#### Local Only (Most Secure)
```powershell
.\Start-M&A-QueryBuilder-Web.ps1
# Only accessible from same computer
```

#### Network Access (Team Use)
```powershell
.\Start-M&A-QueryBuilder-Web.ps1 -Address "0.0.0.0"
# Accessible from network - ensure firewall rules
```

### Recommendations

1. ✅ **Run on secure network** (behind firewall)
2. ✅ **Use Windows Authentication** if hosting on server
3. ✅ **Monitor access logs** (check PowerShell output)
4. ✅ **Stop server when not in use** (Ctrl+C)
5. ✅ **Don't expose to internet** (internal use only)

---

## Performance Tips

### Query Performance

1. ✅ **Use filters** - WHERE clauses reduce result set
2. ✅ **Select specific columns** - Don't use SELECT *
3. ✅ **Limit results** - Automatic 1000 row limit
4. ✅ **Use indexed columns** - Primary keys are fastest

### Server Performance

1. ✅ **Close unused browsers** - Frees memory
2. ✅ **Restart server periodically** - Clears connections
3. ✅ **Use local database** - Don't query over network share

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+Enter` | Execute query (when in SQL preview) |
| `Ctrl+C` | Copy SQL to clipboard |
| `Ctrl+R` | Reset query builder |

---

## Browser Compatibility

| Browser | Status |
|---------|--------|
| Chrome | ✅ Fully supported |
| Edge | ✅ Fully supported |
| Firefox | ✅ Fully supported |
| Safari | ✅ Supported (Mac) |
| Mobile Browsers | ⚠️ Works, but desktop recommended |

---

## FAQ

### Q: Can multiple people use this at once?
**A**: Yes! That's the main benefit of web-based. 10+ users can query simultaneously.

### Q: Do other users need PowerShell installed?
**A**: No! They just need a web browser. Server runs PowerShell.

### Q: Can I save my queries?
**A**: Currently, copy SQL and save to text file. Future versions will add save feature.

### Q: Is my data encrypted?
**A**: Data is already encrypted in the database file (if you enabled encryption during audit). Browser-to-server traffic is unencrypted by default (local network only). For production, consider HTTPS.

### Q: Can I run this 24/7?
**A**: Yes, but recommended to run during business hours and stop when not needed. Consider Windows Service for 24/7 hosting.

### Q: What if database is updated?
**A**: Disconnect and reconnect to refresh schema. Server will see new data immediately.

---

## Next Steps

### Phase 2 Features (Future)

1. **Saved Queries** - Store favorite queries
2. **Query History** - See what you've run
3. **JOIN Builder** - Visual multi-table queries
4. **Chart Visualization** - Graphs from results
5. **Authentication** - Windows Auth integration
6. **Scheduled Queries** - Run queries automatically
7. **Email Results** - Send CSV to stakeholders

### Want These Features?

Contact: adrian207@gmail.com

---

**Document Version**: 1.0  
**Last Updated**: 2025-10-21  
**Author**: Adrian Johnson <adrian207@gmail.com>

