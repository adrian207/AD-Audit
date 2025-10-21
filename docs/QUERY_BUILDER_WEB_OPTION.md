# Web-Based Query Builder - Kestrel/HTTP.sys Analysis

**Author**: Adrian Johnson <adrian207@gmail.com>

---

## Executive Summary

**Answer**: ✅ **YES - Both Kestrel and HTTP.sys are viable options**

**Recommendation**: **Kestrel with PowerShell Universal** or **Pode PowerShell Web Framework**

**Effort**: 32-48 hours (vs. 24-40 for Windows Forms)

**Benefits**: Better UX, cross-platform, modern UI, easier to maintain

---

## Option 1: Kestrel + ASP.NET Core (Recommended)

### What is Kestrel?
- Cross-platform web server included in ASP.NET Core
- High-performance, lightweight
- Can be hosted in PowerShell via .NET Core

### Implementation Approaches

#### Approach 1A: PowerShell Universal (Commercial) ⭐ **BEST OPTION**
**Product**: Ironman Software's PowerShell Universal  
**License**: $600/year (Pro) or $1,500/year (Enterprise)  
**Website**: https://ironmansoftware.com/powershell-universal

**Pros**:
- Built-in Kestrel hosting
- React-based UI components
- PowerShell backend
- Built-in authentication
- Dashboard designer
- REST API generation
- Active Directory integration
- **Perfect fit for your use case**

**Cons**:
- Commercial license required
- Learning curve for Universal Dashboard syntax

**Effort**: 24-32 hours (faster than Windows Forms!)

**Code Example**:
```powershell
# Install-Module UniversalDashboard

Import-Module UniversalDashboard

$Dashboard = New-UDDashboard -Title "M&A Audit Query Builder" -Content {
    New-UDCard -Title "Query Builder" -Content {
        # Table selector
        New-UDSelect -Label "Table" -Option {
            New-UDSelectOption -Name "Users" -Value "Users"
            New-UDSelectOption -Name "Servers" -Value "Servers"
            New-UDSelectOption -Name "SQLDatabases" -Value "SQLDatabases"
        } -OnChange {
            # Load columns dynamically
            Set-UDElement -Id "columns" -Content {
                # Get columns from SQLite
            }
        }
        
        # Column selector
        New-UDCheckbox -Label "SamAccountName" -Id "col_sam"
        New-UDCheckbox -Label "DisplayName" -Id "col_display"
        # ... more columns
        
        # WHERE clause builder
        New-UDDynamic -Id "filters" -Content {
            New-UDButton -Text "+ Add Filter" -OnClick {
                # Add filter row
            }
        }
        
        # SQL Preview
        New-UDCodeEditor -Language "sql" -Code $SQLQuery -ReadOnly
        
        # Execute button
        New-UDButton -Text "Execute Query" -OnClick {
            $results = Invoke-Query -Query $SQLQuery
            Set-UDElement -Id "results" -Content {
                New-UDTable -Data $results -Export
            }
        }
        
        # Results table
        New-UDDynamic -Id "results"
    }
}

Start-UDDashboard -Dashboard $Dashboard -Port 5000
```

**Result**: Navigate to `http://localhost:5000` - modern, responsive UI

---

#### Approach 1B: Pode PowerShell Web Framework (Free, Open-Source) ⭐
**Product**: Pode (PowerShell web framework)  
**License**: MIT (Free)  
**GitHub**: https://github.com/Badgerati/Pode  
**Website**: https://badgerati.github.io/Pode/

**Pros**:
- **Free and open-source**
- Built-in Kestrel server
- PowerShell-native
- REST API support
- WebSockets support
- Static file serving
- Template engines (Pode, EPS)
- Authentication built-in
- **No additional licensing costs**

**Cons**:
- More manual UI work (HTML/CSS/JS)
- Less pre-built components than Universal Dashboard
- Community support (not commercial)

**Effort**: 32-40 hours

**Code Example**:
```powershell
# Install-Module Pode

Import-Module Pode

Start-PodeServer {
    Add-PodeEndpoint -Address localhost -Port 5000 -Protocol Http
    
    # Enable static file serving
    Add-PodeStaticRoute -Path '/assets' -Source './wwwroot/assets'
    
    # Homepage - Query Builder UI
    Add-PodeRoute -Method Get -Path '/' -ScriptBlock {
        Write-PodeHtmlResponse -Value @"
<!DOCTYPE html>
<html>
<head>
    <title>M&A Audit Query Builder</title>
    <link rel="stylesheet" href="/assets/css/bootstrap.min.css">
    <link rel="stylesheet" href="/assets/css/query-builder.css">
</head>
<body>
    <div class="container mt-5">
        <h1>M&A Audit Query Builder</h1>
        
        <!-- Table Selection -->
        <div class="form-group">
            <label>Table</label>
            <select id="tableSelect" class="form-control">
                <option value="">Select a table...</option>
            </select>
        </div>
        
        <!-- Column Selection -->
        <div class="form-group">
            <label>Columns</label>
            <div id="columnChecks"></div>
        </div>
        
        <!-- Filters -->
        <div id="filters">
            <button class="btn btn-primary" onclick="addFilter()">+ Add Filter</button>
        </div>
        
        <!-- SQL Preview -->
        <div class="form-group">
            <label>Generated SQL</label>
            <pre id="sqlPreview" class="bg-light p-3"></pre>
        </div>
        
        <!-- Execute Button -->
        <button class="btn btn-success btn-lg" onclick="executeQuery()">Execute Query</button>
        
        <!-- Results -->
        <div id="results" class="mt-4"></div>
    </div>
    
    <script src="/assets/js/jquery.min.js"></script>
    <script src="/assets/js/query-builder.js"></script>
</body>
</html>
"@
    }
    
    # API: Get database schema
    Add-PodeRoute -Method Get -Path '/api/schema' -ScriptBlock {
        $dbPath = "C:\Audits\AuditData.db"
        $connection = New-Object System.Data.SQLite.SQLiteConnection("Data Source=$dbPath")
        $connection.Open()
        
        # Get tables
        $tables = @()
        $query = "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        $cmd = $connection.CreateCommand()
        $cmd.CommandText = $query
        $reader = $cmd.ExecuteReader()
        
        while ($reader.Read()) {
            $tables += $reader["name"]
        }
        $reader.Close()
        $connection.Close()
        
        Write-PodeJsonResponse -Value @{ tables = $tables }
    }
    
    # API: Get table columns
    Add-PodeRoute -Method Get -Path '/api/columns/:table' -ScriptBlock {
        $table = $WebEvent.Parameters['table']
        $dbPath = "C:\Audits\AuditData.db"
        $connection = New-Object System.Data.SQLite.SQLiteConnection("Data Source=$dbPath")
        $connection.Open()
        
        $columns = @()
        $query = "PRAGMA table_info('$table')"
        $cmd = $connection.CreateCommand()
        $cmd.CommandText = $query
        $reader = $cmd.ExecuteReader()
        
        while ($reader.Read()) {
            $columns += @{
                name = $reader["name"]
                type = $reader["type"]
            }
        }
        $reader.Close()
        $connection.Close()
        
        Write-PodeJsonResponse -Value @{ columns = $columns }
    }
    
    # API: Execute query
    Add-PodeRoute -Method Post -Path '/api/query' -ScriptBlock {
        $body = $WebEvent.Data
        $query = $body.query
        
        try {
            $dbPath = "C:\Audits\AuditData.db"
            $connection = New-Object System.Data.SQLite.SQLiteConnection("Data Source=$dbPath")
            $connection.Open()
            
            $cmd = $connection.CreateCommand()
            $cmd.CommandText = $query
            
            $adapter = New-Object System.Data.SQLite.SQLiteDataAdapter($cmd)
            $dataSet = New-Object System.Data.DataSet
            [void]$adapter.Fill($dataSet)
            
            $results = @()
            foreach ($row in $dataSet.Tables[0].Rows) {
                $obj = @{}
                foreach ($col in $dataSet.Tables[0].Columns) {
                    $obj[$col.ColumnName] = $row[$col]
                }
                $results += $obj
            }
            
            $connection.Close()
            
            Write-PodeJsonResponse -Value @{ 
                success = $true
                data = $results
                rowCount = $results.Count
            }
        }
        catch {
            Write-PodeJsonResponse -Value @{ 
                success = $false
                error = $_.Exception.Message
            } -StatusCode 500
        }
    }
    
    # API: Export to CSV
    Add-PodeRoute -Method Post -Path '/api/export' -ScriptBlock {
        $body = $WebEvent.Data
        $data = $body.data
        
        # Convert to CSV
        $csv = $data | ConvertTo-Csv -NoTypeInformation
        
        Write-PodeTextResponse -Value $csv -ContentType 'text/csv' `
            -Headers @{ 'Content-Disposition' = 'attachment; filename=query_results.csv' }
    }
}
```

**Frontend (wwwroot/assets/js/query-builder.js)**:
```javascript
// Load tables on page load
$(document).ready(function() {
    loadTables();
});

function loadTables() {
    $.get('/api/schema', function(data) {
        data.tables.forEach(function(table) {
            $('#tableSelect').append(`<option value="${table}">${table}</option>`);
        });
    });
}

$('#tableSelect').change(function() {
    const table = $(this).val();
    if (table) {
        loadColumns(table);
    }
});

function loadColumns(table) {
    $.get(`/api/columns/${table}`, function(data) {
        $('#columnChecks').empty();
        data.columns.forEach(function(col) {
            $('#columnChecks').append(`
                <div class="form-check">
                    <input class="form-check-input column-check" type="checkbox" 
                           value="${col.name}" id="col_${col.name}" checked>
                    <label class="form-check-label" for="col_${col.name}">
                        ${col.name} <span class="text-muted">(${col.type})</span>
                    </label>
                </div>
            `);
        });
        updateSQL();
    });
}

function addFilter() {
    const filterHtml = `
        <div class="filter-row row mb-2">
            <div class="col-md-3">
                <select class="form-control filter-field">
                    <option>Field...</option>
                </select>
            </div>
            <div class="col-md-2">
                <select class="form-control filter-operator">
                    <option value="=">=</option>
                    <option value="!=">!=</option>
                    <option value="<"><</option>
                    <option value=">">></option>
                    <option value="LIKE">LIKE</option>
                    <option value="IS NULL">IS NULL</option>
                </select>
            </div>
            <div class="col-md-4">
                <input type="text" class="form-control filter-value" placeholder="Value">
            </div>
            <div class="col-md-2">
                <select class="form-control filter-logic">
                    <option>AND</option>
                    <option>OR</option>
                </select>
            </div>
            <div class="col-md-1">
                <button class="btn btn-danger btn-sm" onclick="$(this).closest('.filter-row').remove(); updateSQL();">×</button>
            </div>
        </div>
    `;
    $('#filters').append(filterHtml);
}

function updateSQL() {
    const table = $('#tableSelect').val();
    if (!table) return;
    
    // Build SELECT
    const columns = $('.column-check:checked').map(function() {
        return $(this).val();
    }).get();
    
    const selectClause = columns.length > 0 ? columns.join(', ') : '*';
    
    let sql = `SELECT ${selectClause}\nFROM ${table}`;
    
    // Build WHERE (simplified)
    const filters = [];
    $('.filter-row').each(function() {
        const field = $(this).find('.filter-field').val();
        const operator = $(this).find('.filter-operator').val();
        const value = $(this).find('.filter-value').val();
        const logic = $(this).find('.filter-logic').val();
        
        if (field && value) {
            filters.push(`${logic} ${field} ${operator} '${value}'`);
        }
    });
    
    if (filters.length > 0) {
        filters[0] = filters[0].replace(/^(AND|OR) /, '');
        sql += '\nWHERE ' + filters.join('\n  ');
    }
    
    $('#sqlPreview').text(sql);
    return sql;
}

function executeQuery() {
    const sql = updateSQL();
    
    $.ajax({
        url: '/api/query',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ query: sql }),
        success: function(response) {
            if (response.success) {
                displayResults(response.data);
            } else {
                alert('Query failed: ' + response.error);
            }
        },
        error: function(xhr) {
            alert('Error: ' + xhr.responseJSON.error);
        }
    });
}

function displayResults(data) {
    if (data.length === 0) {
        $('#results').html('<div class="alert alert-info">No results found</div>');
        return;
    }
    
    // Build table
    const columns = Object.keys(data[0]);
    let html = `<h3>Results (${data.length} rows)</h3>`;
    html += '<button class="btn btn-primary mb-2" onclick="exportResults()">Export to CSV</button>';
    html += '<table class="table table-striped table-bordered">';
    html += '<thead><tr>';
    columns.forEach(col => html += `<th>${col}</th>`);
    html += '</tr></thead><tbody>';
    
    data.forEach(row => {
        html += '<tr>';
        columns.forEach(col => html += `<td>${row[col] || ''}</td>`);
        html += '</tr>';
    });
    
    html += '</tbody></table>';
    $('#results').html(html);
}
```

**Result**: Modern, responsive web UI accessible from any browser

---

#### Approach 1C: Pure .NET Core + Kestrel (Advanced)
**Description**: Build ASP.NET Core web app, call from PowerShell

**Pros**:
- Full control
- Excellent performance
- Modern web framework

**Cons**:
- Requires C# development
- More complex deployment
- Not PowerShell-native

**Effort**: 48-64 hours

**Recommendation**: Only if you have C# developers available

---

## Option 2: HTTP.sys (Windows-Only)

### What is HTTP.sys?
- Windows kernel-mode HTTP driver
- High-performance
- Used by IIS
- PowerShell can interact via `System.Net.HttpListener`

### Implementation Approach

**Code Example**:
```powershell
# Simple HTTP.sys server in PowerShell

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://localhost:8080/")
$listener.Start()

Write-Host "Query Builder running at http://localhost:8080"
Write-Host "Press Ctrl+C to stop..."

try {
    while ($listener.IsListening) {
        $context = $listener.GetContext()
        $request = $context.Request
        $response = $context.Response
        
        # Route handling
        switch ($request.Url.LocalPath) {
            "/" {
                # Serve HTML
                $html = Get-Content ".\wwwroot\index.html" -Raw
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($html)
                $response.ContentLength64 = $buffer.Length
                $response.OutputStream.Write($buffer, 0, $buffer.Length)
            }
            "/api/query" {
                # Handle query API
                $reader = New-Object System.IO.StreamReader($request.InputStream)
                $body = $reader.ReadToEnd() | ConvertFrom-Json
                
                # Execute query (similar to Pode example)
                $results = Execute-SQLiteQuery -Query $body.query
                
                $json = $results | ConvertTo-Json
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($json)
                $response.ContentType = "application/json"
                $response.ContentLength64 = $buffer.Length
                $response.OutputStream.Write($buffer, 0, $buffer.Length)
            }
        }
        
        $response.Close()
    }
}
finally {
    $listener.Stop()
}
```

**Pros**:
- Windows-native
- No external dependencies
- Good performance
- Can use URL ACLs for port binding

**Cons**:
- Windows-only (not cross-platform)
- More manual HTTP handling
- Less feature-rich than Kestrel
- More code to write

**Effort**: 40-56 hours

**Recommendation**: Use Pode instead (similar effort, better features)

---

## Comparison Matrix

| Feature | Windows Forms | Pode (Kestrel) | PowerShell Universal | HTTP.sys |
|---------|---------------|----------------|---------------------|----------|
| **Effort** | 24-40 hrs | 32-40 hrs | 24-32 hrs | 40-56 hrs |
| **Cost** | Free | Free | $600-1500/yr | Free |
| **Cross-Platform** | ❌ Windows only | ✅ Yes | ✅ Yes | ❌ Windows only |
| **Modern UI** | ⚠️ Basic | ✅ Excellent | ✅ Excellent | ✅ Excellent |
| **Remote Access** | ❌ No | ✅ Yes | ✅ Yes | ✅ Yes |
| **Mobile-Friendly** | ❌ No | ✅ Yes | ✅ Yes | ✅ Yes |
| **Authentication** | ⚠️ Manual | ✅ Built-in | ✅ Built-in | ⚠️ Manual |
| **Maintenance** | ⚠️ More code | ✅ Easier | ✅ Easiest | ⚠️ More code |
| **Learning Curve** | Low | Medium | Medium | Medium-High |
| **Pre-built Components** | ❌ No | ⚠️ Some | ✅ Many | ❌ No |
| **PowerShell Native** | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
| **Multi-User** | ❌ Single | ✅ Yes | ✅ Yes | ✅ Yes |

---

## Recommendation

### 🏆 **Option 1: Pode (Free) or PowerShell Universal (Paid)**

#### If Budget Allows: **PowerShell Universal** ✅
**Reasons**:
1. **Fastest development**: 24-32 hours (similar to Windows Forms)
2. **Best UX**: Modern React components out-of-the-box
3. **Built-in features**: Authentication, dashboards, REST APIs
4. **Professional support**: Commercial product with good support
5. **Perfect fit**: Designed exactly for this use case
6. **Active Directory integration**: Built-in Windows Auth
7. **$600/year is cheap** compared to 20+ hours of dev time savings

**ROI**: License cost ($600) < 15 hours of dev time @ $40/hr

#### If Budget-Constrained: **Pode** ✅
**Reasons**:
1. **Free and open-source**
2. **Modern Kestrel server**
3. **PowerShell-native**
4. **Good documentation**
5. **Active community**
6. **Only 8-12 hours more effort than Universal**

---

## Web-Based Advantages (vs. Windows Forms)

### User Experience
1. ✅ **Modern UI**: Bootstrap, DataTables, modern JavaScript libraries
2. ✅ **Responsive**: Works on tablets and mobile
3. ✅ **Remote access**: Use from any computer
4. ✅ **No installation**: Just navigate to URL
5. ✅ **Familiar**: Everyone knows how to use web apps

### Technical
1. ✅ **Easier UI development**: HTML/CSS/JS vs. Windows Forms layout code
2. ✅ **Better libraries**: jQuery QueryBuilder, DataTables, Chart.js
3. ✅ **Easier testing**: Use browser dev tools
4. ✅ **Easier updates**: Update server, all clients see changes
5. ✅ **Multi-user**: Multiple users can query simultaneously

### Deployment
1. ✅ **Single server**: Deploy once, serve many
2. ✅ **Cross-platform**: Run on Linux if needed
3. ✅ **Container-ready**: Easy Docker deployment
4. ✅ **Cloud-ready**: Can host in Azure/AWS

---

## Architecture Diagram (Pode/Kestrel)

```
┌─────────────────────────────────────────────────────────────────┐
│                        User's Browser                           │
│                    (Chrome, Edge, Firefox)                      │
└────────────────────────────┬────────────────────────────────────┘
                             │ HTTP (localhost:5000 or remote)
                             ↓
┌─────────────────────────────────────────────────────────────────┐
│                      Pode Web Server                            │
│                    (Kestrel/PowerShell)                         │
│                                                                 │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐   │
│  │  Static Files  │  │   REST APIs    │  │  WebSockets    │   │
│  │  (HTML/CSS/JS) │  │  /api/schema   │  │  (real-time)   │   │
│  │                │  │  /api/query    │  │                │   │
│  └────────────────┘  └────────────────┘  └────────────────┘   │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ↓
┌─────────────────────────────────────────────────────────────────┐
│                   SQLite-AuditDB.ps1                            │
│                   (Your existing library)                       │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ↓
┌─────────────────────────────────────────────────────────────────┐
│                      AuditData.db                               │
│                    (SQLite Database)                            │
└─────────────────────────────────────────────────────────────────┘
```

---

## Sample UI (Web-Based)

### Using jQuery QueryBuilder Plugin
https://querybuilder.js.org/

```html
<div id="builder"></div>

<script>
$('#builder').queryBuilder({
  filters: [
    {
      id: 'SamAccountName',
      label: 'Username',
      type: 'string'
    },
    {
      id: 'Department',
      label: 'Department',
      type: 'string',
      input: 'select',
      values: ['IT', 'Finance', 'HR', 'Sales']
    },
    {
      id: 'Enabled',
      label: 'Enabled',
      type: 'boolean'
    },
    {
      id: 'DaysSinceLastLogon',
      label: 'Days Since Last Logon',
      type: 'integer'
    }
  ]
});

// Get SQL from query builder
$('#btn-get').on('click', function() {
  var sql = $('#builder').queryBuilder('getSQL', 'SQLite');
  $('#sql-preview').text(sql);
});
</script>
```

**Result**: Professional query builder with drag-and-drop, complex conditions, and automatic SQL generation!

---

## Deployment Options

### Option A: Local Host (Simplest)
```powershell
# Run on localhost:5000
# Access via http://localhost:5000
# Single user at a time
```

### Option B: Network Share
```powershell
# Run on server
# Bind to network interface
# Multiple users can access via http://server:5000
# Requires firewall rule
```

### Option C: IIS Reverse Proxy (Enterprise)
```powershell
# Pode/Kestrel runs on localhost:5000
# IIS proxies to it via URL Rewrite
# Benefits: SSL, authentication, logging
```

### Option D: Azure App Service (Cloud)
```powershell
# Deploy as Azure Web App
# Access from anywhere
# Built-in SSL, authentication, scaling
```

---

## Security Considerations

### Web-Based Security
1. **Authentication**: Windows Auth, Forms Auth, JWT
2. **Authorization**: Role-based access control
3. **HTTPS**: SSL/TLS encryption
4. **CORS**: Cross-origin protection
5. **SQL Injection**: Parameterized queries (same as Windows Forms)
6. **Rate Limiting**: Prevent abuse
7. **Audit Logging**: Track who queried what

**[Inference] Web-based requires more security planning than Windows Forms**

---

## Final Recommendation

### 🎯 **Build with Pode (Free) or PowerShell Universal (Best)**

**Decision Matrix**:
- **Budget < $1000**: Choose **Pode** (32-40 hours, free)
- **Budget > $1000**: Choose **PowerShell Universal** (24-32 hours, $600/year)
- **Need offline/single-user**: Choose **Windows Forms** (24-40 hours, free)

**My Strong Recommendation**: **Pode** (best balance of cost/features/effort)

---

## Next Steps

1. ✅ **Install Pode**: `Install-Module Pode -Scope CurrentUser`
2. ✅ **Test POC**: Run basic Pode server with query builder
3. ✅ **Prototype**: 4-8 hours for working prototype
4. ✅ **User feedback**: Show to 2-3 target users
5. ✅ **Full build**: 24-32 hours for production version

---

**Ready to proceed with Pode implementation?**


