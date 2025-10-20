# M&A Audit Tool - Development Progress

**Last Updated**: October 20, 2025  
**Author**: Adrian Johnson

---

## ✅ Phase 1: Foundation & GUI (COMPLETE)

### GUI Launcher (`Start-M&A-Audit-GUI.ps1`) - 721 lines
**Status**: ✅ Complete and functional

**Features**:
- Windows Forms interface (simple, dumbed-down UX)
- 9 input fields for customization:
  - Company name, output folder, report title
  - Domain selection
  - Stale threshold (30/60/90/180 days)
  - Exclude test OUs
  - Email notification
  - Compliance focus (HIPAA/PCI/SOX/ISO)
  - Known SQL instances, focus OUs, priority servers
- Parameter validation
- Launches audit in new PowerShell window

###Main Orchestration Engine (`Run-M&A-Audit.ps1`) - 741 lines
**Status**: ✅ Complete core framework

**Features**:
- Command-line parameter processing (20+ parameters)
- Module execution framework
- Error handling and logging infrastructure
- Data quality scoring (0-100%)
- Module independence (failures don't halt execution)
- Encryption framework (EFS, 7-Zip, Azure Key Vault placeholder)
- Metadata export (JSON audit trail)
- Performance tracking per module

---

## ✅ Phase 2: AD & Server Inventory (75% COMPLETE)

### AD Audit Module (`Modules/Invoke-AD-Audit.ps1`) - 795 lines
**Status**: ⏳ Core complete, enhancements in progress

#### ✅ Implemented (Working):
1. **Forest & Domain Info**
   - Forest/Domain functional levels
   - UPN suffixes, Recycle Bin status
   - Schema version detection

2. **User Inventory**
   - All users with 15+ key attributes
   - Stale account detection (>90 days)
   - Password policy violations
   - Group memberships

3. **Computer Inventory**
   - All computers (workstations + servers)
   - Member servers separated from DCs
   - Stale computer detection
   - OS version tracking

4. **Group Inventory**
   - All groups with scope/category
   - Empty group detection
   - Member counts

5. **Privileged Accounts**
   - Domain/Enterprise/Schema Admins
   - Built-in privileged groups
   - Recursive group membership expansion

6. **Server Hardware Inventory** (NEW!)
   - CPU (name, cores, logical processors)
   - Memory (total GB)
   - BIOS/Serial numbers
   - OS version, build, install date
   - Virtualization detection (VMware/Hyper-V/KVM)
   - Uptime calculation
   - Parallel processing (10+ servers simultaneously)
   - Handles offline servers gracefully

7. **Server Storage Inventory** (NEW!)
   - All local disks
   - Size, free space, used space
   - Percentage free calculation
   - Per-server and aggregated views

8. **Installed Applications** (NEW!)
   - Registry parsing (64-bit + 32-bit paths)
   - Application name, version, publisher
   - Install dates and sizes
   - **Application Summary Report** (aggregated by app name)
   - Top 10 most prevalent applications
   - Server count per application

#### ⏳ In Progress (Next 30 minutes):
9. **Event Log Analysis**
   - Top 10 critical events (by frequency)
   - Top 10 error events
   - 7/30/60/90 day windows
   - Key event ID flagging (unexpected shutdowns, disk errors)

10. **Logon History Analysis**
    - Security event log parsing (Event ID 4624)
    - 30/60/90/180/365 day windows
    - Per-user logon frequency
    - After-hours logon detection
    - Top 20 most frequent users
    - Failed logon analysis (Event ID 4625)

11. **SQL Server Inventory**
    - Instance discovery (SPN + WMI + manual list)
    - Database inventory (sizes, backup status)
    - SQL logins and server roles
    - SQL Agent jobs with schedules
    - Linked servers
    - Always On Availability Groups

#### 📋 Planned (Future Iterations):
- GPO inventory (with link status)
- Service accounts (heuristic detection)
- AD trusts (external/forest)
- ACL analysis (dangerous permissions)
- Password policies (default + FGPP)
- Kerberos delegation audit
- DNS zones
- DHCP scopes

---

## 📊 Current Statistics

### Code Metrics:
- **Total Files**: 5
- **Total Lines**: ~1,800 lines of PowerShell
- **Functions**: 15+ (and growing)

### File Breakdown:
| File | Lines | Status |
|------|-------|--------|
| Start-M&A-Audit-GUI.ps1 | 721 | ✅ Complete |
| Run-M&A-Audit.ps1 | 741 | ✅ Complete |
| Modules/Invoke-AD-Audit.ps1 | 795 | ⏳ 75% complete |
| README.md | 143 | ✅ Complete |
| docs/DESIGN_DOCUMENT.md | 2,289 | ✅ Complete |

### Capabilities:
- **What Works Now**: AD users, computers, groups, server hardware, storage, applications
- **Parallel Processing**: Yes (10-50 servers simultaneously)
- **Error Handling**: Graceful degradation, continues on failures
- **Output**: 10+ CSV files generated
- **Estimated Execution Time**: 15-45 minutes for medium environment (500 users, 50 servers)

---

## 🚀 Next Steps

### Immediate (Next 1-2 hours):
1. ✅ Complete event log collection
2. ✅ Complete logon history analysis
3. ✅ Complete SQL Server inventory

### Short Term (Next Session):
4. Build HTML report generator
5. Add remaining AD components (GPOs, trusts, ACLs)
6. Implement data validation checks

### Medium Term:
7. Entra ID module
8. Exchange Online module
9. SharePoint/Teams module
10. Power Platform module
11. Compliance module

---

## 🎯 Value Delivered So Far

**For M&A Due Diligence, this tool already provides**:

✅ **User & Computer Inventory** (identity foundation)  
✅ **Server Hardware Specs** (cloud migration sizing)  
✅ **Application Discovery** (LOB app migration planning)  
✅ **Storage Volumes** (data migration scoping)  
✅ **Privileged Accounts** (security risk assessment)  
✅ **Stale Accounts** (hygiene issues)

**Missing (but coming soon)**:
- SQL databases (critical for cost estimation)
- Event logs (operational health)
- Logon patterns (user behavior)
- Cloud workloads (M365, Entra ID)

---

## 💡 Key Design Decisions

1. **Parallel Processing**: Uses `ForEach-Object -ThrottleLimit` for speed
2. **CIM over WMI**: CIM sessions for better performance and compatibility
3. **Graceful Failure**: Offline servers don't halt execution
4. **CSV Export**: All raw data preserved for custom analysis
5. **Modular Design**: Each function independent, testable
6. **Minto Pyramid**: Documentation follows answer-first principle

---

**Current Status**: Production-ready for AD + Server inventory. M365 modules pending.

