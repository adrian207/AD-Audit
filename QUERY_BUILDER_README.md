# 🌐 Web-Based Query Builder - Quick Start

**Modern, user-friendly query builder for your M&A audit database**

---

## 🚀 Get Started in 2 Minutes

### 1. Install Pode (One-Time Setup)
```powershell
Install-Module Pode -Scope CurrentUser -Force
```

### 2. Start the Server
```powershell
.\Start-M&A-QueryBuilder-Web.ps1
```

### 3. Open Your Browser
Navigate to: **http://localhost:5000**

**Done!** You now have a modern query builder running.

---

## ✨ What You Get

### Visual Query Builder
- 📊 **Point-and-click** query construction
- 🎯 **No SQL knowledge required**
- 🔍 **Real-time SQL preview**
- 📝 **8 pre-built templates**

### Modern Features
- 🌐 **Multi-user** - Whole team can use at once
- 📱 **Mobile-friendly** - Works on tablets/phones
- 💾 **CSV export** - One-click download
- 🔒 **Secure** - Read-only, no data modification

### Pre-Built Templates
1. Stale Privileged Accounts
2. SQL Backup Risk Servers
3. Top 20 Applications
4. Virtual vs Physical Servers
5. Service Account Inventory
6. Stale Computer Accounts
7. SQL Server Inventory
8. Users by Department

---

## 🖥️ How to Use

### Basic Query (30 seconds)
1. Click "Connect" (auto-detects database)
2. Select a table from dropdown
3. Choose columns to display
4. Click "Execute Query"
5. View results!

### With Filters
1. Follow steps above
2. Click "+ Add Filter"
3. Select field, operator, value
4. Click "Execute Query"

### Use Template
1. Find template in right panel
2. Click template name
3. Click "Execute Query"
4. Download CSV if needed

---

## 🌍 Multi-User Access

### Share with Your Team

**On same computer:**
```powershell
.\Start-M&A-QueryBuilder-Web.ps1
```
URL: `http://localhost:5000`

**On network (for team access):**
```powershell
.\Start-M&A-QueryBuilder-Web.ps1 -Address "0.0.0.0" -Port 5000
```
URL: `http://YOUR-COMPUTER-NAME:5000`

**Firewall rule needed:**
```powershell
# Run PowerShell as Administrator
New-NetFirewallRule -DisplayName "M&A Query Builder" `
    -Direction Inbound -LocalPort 5000 -Protocol TCP -Action Allow
```

Now anyone on your network can access the query builder!

---

## 📚 Documentation

- **Quick Start**: This file
- **Complete Guide**: `docs\QUERY_BUILDER_WEB_GUIDE.md`
- **Design Details**: `docs\QUERY_BUILDER_WEB_OPTION.md`
- **Windows Forms POC**: `Start-M&A-QueryBuilder-GUI-POC.ps1`

---

## 🔧 Command-Line Options

### Custom Port
```powershell
.\Start-M&A-QueryBuilder-Web.ps1 -Port 8080
```

### Specific Database
```powershell
.\Start-M&A-QueryBuilder-Web.ps1 -DatabasePath "C:\Audits\Contoso\AuditData.db"
```

### Network Access
```powershell
.\Start-M&A-QueryBuilder-Web.ps1 -Address "0.0.0.0"
```

---

## 🛠️ Troubleshooting

### "Pode module not found"
```powershell
Install-Module Pode -Scope CurrentUser -Force
```

### "Database not found"
- Let server auto-detect (leave path blank)
- Or specify full path in UI

### Can't access from other computer
- Check firewall rule
- Verify started with `-Address "0.0.0.0"`
- Use computer name, not "localhost"

### Page won't load
- Check server is still running (PowerShell window)
- Verify URL: `http://localhost:5000`
- Try restarting server (Ctrl+C, then rerun)

---

## 💡 Tips & Best Practices

### Performance
- ✅ Use filters to reduce result size
- ✅ Select specific columns (not all)
- ✅ Results limited to 1000 rows automatically

### Security
- ✅ Read-only (no UPDATE/DELETE)
- ✅ SQL injection protected
- ✅ 30-second query timeout
- ✅ Run on trusted network only

### Teamwork
- ✅ Share the URL with team
- ✅ Use templates for common queries
- ✅ Copy SQL for documentation
- ✅ Export results to share findings

---

## 🎯 Example Queries

### Find Stale Admin Accounts
1. Click template: "Stale Privileged Accounts"
2. Click "Execute Query"
3. Review results
4. Export CSV for remediation

### List SQL Databases Without Backups
1. Click template: "SQL Backup Risk Servers"
2. Click "Execute Query"
3. Sort by size
4. Export for action items

### Application Inventory
1. Select table: "ServerApplications"
2. Add filter: `ApplicationName LIKE Microsoft`
3. Execute
4. See all Microsoft apps

---

## 🔒 Security Features

| Feature | Description |
|---------|-------------|
| Read-Only | Only SELECT queries allowed |
| No Modifications | Cannot UPDATE, DELETE, DROP tables |
| SQL Injection Prevention | Parameterized queries |
| Row Limit | Max 1000 rows per query |
| Timeout | 30-second query timeout |

---

## 🆚 Why Web vs Windows Forms?

| Feature | Windows Forms | Web (Pode) |
|---------|---------------|------------|
| Installation | Required on each PC | Just open browser |
| Multi-User | ❌ Single user | ✅ Unlimited users |
| Remote Access | ❌ Must RDP | ✅ URL from anywhere |
| Mobile | ❌ No | ✅ Yes |
| Updates | Update each PC | Update server once |
| Modern UI | ⚠️ Basic | ✅ Bootstrap 5 |

---

## 📞 Support

**Questions?** See full guide: `docs\QUERY_BUILDER_WEB_GUIDE.md`

**Issues?** Contact: adrian207@gmail.com

**Want Features?**
- Saved queries
- Query history
- Chart visualization
- Scheduled queries

Let us know!

---

## 📊 Project Stats

- **PowerShell Server**: 370 lines
- **HTML/CSS/JS Frontend**: 650+ lines
- **Pre-built Templates**: 8 queries
- **REST API Endpoints**: 8
- **Documentation**: 450+ lines
- **Development Time**: ~6 hours
- **Status**: ✅ Production Ready

---

## 🎉 You're Ready!

**Start querying your audit database with a modern, team-friendly interface!**

```powershell
# Run this now:
.\Start-M&A-QueryBuilder-Web.ps1
```

Then open: **http://localhost:5000**

---

**Author**: Adrian Johnson <adrian207@gmail.com>  
**Version**: 1.0  
**Technology**: Pode + Kestrel + Bootstrap 5  
**License**: Part of M&A Technical Discovery Audit Tool

