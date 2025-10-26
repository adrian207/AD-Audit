# Visual Query Builder - Effort Analysis

> Executive summary: Deliver a ServiceNow-style visual query builder for the audit database to enable non-technical analysis with manageable effort.
>
> Key recommendations:
> - Phase delivery: basic builder → saved queries → advanced filters
> - Generate SQL safely; validate inputs to prevent injection
> - Keep UX responsive with async queries and pagination
>
> Supporting points:
> - Clear effort breakdown and ROI
> - Schema-driven UI and reusable components
> - Works with SQLite-backed datasets

**Author**: Adrian Johnson <adrian207@gmail.com>

---

## Executive Summary

**Goal**: Build a ServiceNow-style visual query builder for the SQLite audit database

**Effort Estimate**: 24-40 hours (3-5 days)

**Complexity**: Medium-High

**ROI**: High - Makes database accessible to non-technical users

---

## Features Breakdown

### Phase 1: Basic Query Builder (16-20 hours)

#### 1.1 Table & Column Selection (4 hours)
- **UI Components**:
  - ComboBox for table selection (14 tables)
  - CheckedListBox for column selection (multi-select)
  - DataGridView for results preview
  
- **Backend Logic**:
  - Read database schema dynamically (`PRAGMA table_info(table_name)`)
  - Populate UI from schema metadata
  - Build SELECT clause from selections

**Complexity**: Low-Medium

#### 1.2 WHERE Clause Builder (6-8 hours)
- **UI Components**:
  - Add/Remove condition buttons
  - For each condition:
    - ComboBox: Field selection
    - ComboBox: Operator (=, !=, <, >, LIKE, IN, IS NULL, etc.)
    - TextBox/DatePicker/NumericUpDown: Value input
    - ComboBox: AND/OR logic
  
- **Backend Logic**:
  - Dynamic control creation
  - Type detection (string, number, date, boolean)
  - Input validation
  - SQL injection prevention (parameterized queries)
  - Build WHERE clause from conditions

**Complexity**: Medium

#### 1.3 Results Display & Export (3-4 hours)
- **UI Components**:
  - DataGridView with sorting/filtering
  - Export button (CSV/Excel)
  - Row count display
  - Execution time display
  
- **Backend Logic**:
  - Execute query safely
  - Bind results to DataGridView
  - Export to CSV/Excel (ClosedXML or EPPlus)
  - Error handling and user-friendly messages

**Complexity**: Low-Medium

#### 1.4 Query Preview & Save (3-4 hours)
- **UI Components**:
  - TextBox showing generated SQL (read-only)
  - "Copy SQL" button
  - "Save Query" button
  - "Load Query" dropdown
  
- **Backend Logic**:
  - Real-time SQL generation
  - Save query definitions to JSON
  - Load saved queries
  - Query history

**Complexity**: Low

---

### Phase 2: Advanced Features (8-12 hours)

#### 2.1 JOIN Builder (4-6 hours)
- **UI Components**:
  - "Add Join" button
  - For each join:
    - ComboBox: Join type (INNER, LEFT, RIGHT, FULL)
    - ComboBox: Target table
    - ComboBox: Left table field
    - ComboBox: Right table field
  - Visual relationship diagram (optional)
  
- **Backend Logic**:
  - Detect foreign key relationships automatically
  - Suggest join conditions
  - Build JOIN clause
  - Handle multi-table queries

**Complexity**: Medium-High

#### 2.2 Aggregation & Grouping (2-3 hours)
- **UI Components**:
  - Checkbox: "Enable Aggregation"
  - For selected columns:
    - ComboBox: Aggregate function (SUM, COUNT, AVG, MIN, MAX)
  - CheckedListBox: GROUP BY fields
  - WHERE-like builder for HAVING clause
  
- **Backend Logic**:
  - Build GROUP BY clause
  - Build aggregate SELECT clause
  - HAVING clause support

**Complexity**: Medium

#### 2.3 Sorting & Limiting (1-2 hours)
- **UI Components**:
  - DataGridView for ORDER BY (field, ASC/DESC)
  - NumericUpDown for LIMIT
  
- **Backend Logic**:
  - Build ORDER BY clause
  - Build LIMIT clause

**Complexity**: Low

#### 2.4 Templates & Pre-built Queries (1 hour)
- **UI Components**:
  - "Template" dropdown
  - Templates for common scenarios
  
- **Backend Logic**:
  - Load template definitions
  - Populate UI from template

**Complexity**: Low

---

### Phase 3: Polish & UX (4-8 hours)

#### 3.1 Validation & Help (2-3 hours)
- Input validation with helpful error messages
- Tooltips explaining each field
- "Help" button with examples
- Sample data preview for each table

**Complexity**: Low

#### 3.2 Performance & Optimization (2-3 hours)
- Query timeout handling
- Progress indicator for long queries
- Result pagination (1000 rows at a time)
- Memory-efficient result handling

**Complexity**: Medium

#### 3.3 Visual Design (2-2 hours)
- Professional styling
- Modern UI theme
- Consistent with main GUI
- Responsive layout

**Complexity**: Low

---

## Technical Architecture

### GUI Technology Options

#### Option 1: Windows Forms (Current Tech Stack) ✅
**Pros**:
- Already used in `Start-M&A-Audit-GUI.ps1`
- No new dependencies
- Native performance
- Works offline

**Cons**:
- More code for complex layouts
- Limited modern UI components

**Effort**: 24-32 hours

#### Option 2: WPF (Windows Presentation Foundation)
**Pros**:
- Better UI flexibility (XAML)
- Data binding
- Modern controls
- Better for complex layouts

**Cons**:
- Learning curve if team is unfamiliar
- More complex setup

**Effort**: 32-40 hours

#### Option 3: Web-Based (HTML/JavaScript + PowerShell backend)
**Pros**:
- Cross-platform potential
- Rich UI libraries (DataTables, Select2)
- Easier to build query builder (jQuery QueryBuilder)
- Can host in local IIS/Kestrel

**Cons**:
- More complex architecture
- Requires web server
- Additional dependencies

**Effort**: 40-56 hours

**Recommendation**: **Option 1 (Windows Forms)** - Fastest to implement, consistent with existing codebase

---

## File Structure

```
AD-Audit/
├── Start-M&A-QueryBuilder-GUI.ps1    (Main query builder GUI - 800-1200 lines)
├── Libraries/
│   ├── SQLite-AuditDB.ps1            (Existing - enhanced with schema helpers)
│   └── QueryBuilder-Helpers.ps1      (New - 400-600 lines)
│       ├── Get-DatabaseSchema()
│       ├── Build-SQLQuery()
│       ├── Validate-QueryConditions()
│       ├── Export-QueryResults()
│       └── Save-QueryTemplate()
├── Templates/
│   └── QueryTemplates.json           (Pre-built query definitions)
└── docs/
    └── QUERY_BUILDER_GUIDE.md        (User documentation - 200-300 lines)
```

---

## Development Phases

### Phase 1 (Week 1): MVP - Basic Query Builder
**Time**: 16-20 hours

**Deliverables**:
1. ✅ Launch GUI from main menu or standalone
2. ✅ Select table
3. ✅ Select columns (multi-select)
4. ✅ Add WHERE conditions (field/operator/value)
5. ✅ Execute query and display results
6. ✅ Export to CSV
7. ✅ Show generated SQL

**User Story**: "As a business analyst, I can query the Users table and filter by Department without writing SQL."

### Phase 2 (Week 2): Advanced Features
**Time**: 8-12 hours

**Deliverables**:
1. ✅ JOIN multiple tables
2. ✅ Aggregation (COUNT, SUM, AVG)
3. ✅ GROUP BY and HAVING
4. ✅ ORDER BY and LIMIT
5. ✅ Save/load queries
6. ✅ Pre-built templates

**User Story**: "As a technical lead, I can build complex queries joining Servers and SQLDatabases to analyze backup compliance."

### Phase 3 (Week 3): Polish
**Time**: 4-8 hours

**Deliverables**:
1. ✅ Comprehensive validation
2. ✅ Help system with examples
3. ✅ Professional styling
4. ✅ Performance optimization
5. ✅ User documentation

**User Story**: "As a consultant, I can confidently use the query builder without technical support."

---

## Sample Implementation Preview

### GUI Layout (Windows Forms)

```
┌─────────────────────────────────────────────────────────────────┐
│  M&A Audit Database - Visual Query Builder                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  📂 Database: AuditData.db     [Browse...]                     │
│                                                                 │
│  ┌─ Table & Columns ──────────────────────────────────────┐    │
│  │  Table:    [Users                 ▼]                   │    │
│  │  Columns:  ☑ SamAccountName                            │    │
│  │            ☑ DisplayName                               │    │
│  │            ☑ Department                                │    │
│  │            ☐ Email                                     │    │
│  │            ☐ LastLogonDate                             │    │
│  │            ... (scrollable)                            │    │
│  └────────────────────────────────────────────────────────┘    │
│                                                                 │
│  ┌─ Filters (WHERE) ──────────────────────────────────────┐    │
│  │  [+] Department      [equals ▼]  [IT         ]  [AND▼] │    │
│  │  [+] Enabled         [equals ▼]  [True       ]  [AND▼] │    │
│  │  [-] (click + to add condition)                        │    │
│  └────────────────────────────────────────────────────────┘    │
│                                                                 │
│  ┌─ Joins (Advanced) ────────────────────────────────────┐     │
│  │  [Add Join...]                                         │     │
│  └────────────────────────────────────────────────────────┘    │
│                                                                 │
│  ┌─ Generated SQL ───────────────────────────────────────┐     │
│  │  SELECT SamAccountName, DisplayName, Department        │     │
│  │  FROM Users                                            │     │
│  │  WHERE Department = 'IT' AND Enabled = 1               │     │
│  │                                   [Copy SQL] [Save]    │     │
│  └────────────────────────────────────────────────────────┘    │
│                                                                 │
│  [Execute Query]  [Export to CSV]  [Clear]  [Load Template ▼] │
│                                                                 │
│  ┌─ Results (125 rows) ──────────────────────────────────┐     │
│  │ SamAccountName │ DisplayName      │ Department        │     │
│  ├────────────────┼──────────────────┼───────────────────┤     │
│  │ jsmith         │ John Smith       │ IT                │     │
│  │ mjones         │ Mary Jones       │ IT                │     │
│  │ bwilliams      │ Bob Williams     │ IT                │     │
│  │ ...                                                    │     │
│  └────────────────────────────────────────────────────────┘    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Pre-built Templates (Examples)

### Template 1: Stale Privileged Accounts
```json
{
  "name": "Stale Privileged Accounts",
  "description": "Find admin accounts that haven't logged in for 90+ days",
  "query": {
    "tables": ["Users", "PrivilegedAccounts"],
    "columns": ["Users.SamAccountName", "Users.DisplayName", "Users.DaysSinceLastLogon", "PrivilegedAccounts.GroupName"],
    "joins": [
      {"type": "INNER", "table": "PrivilegedAccounts", "on": "Users.SamAccountName = PrivilegedAccounts.MemberSamAccountName"}
    ],
    "where": [
      {"field": "Users.IsStale", "operator": "=", "value": "1"},
      {"field": "Users.Enabled", "operator": "=", "value": "1", "logic": "AND"}
    ],
    "orderBy": [{"field": "Users.DaysSinceLastLogon", "direction": "DESC"}]
  }
}
```

### Template 2: SQL Backup Risk by Server
```json
{
  "name": "SQL Backup Risk by Server",
  "description": "Servers with SQL databases that have no recent backups",
  "query": {
    "tables": ["Servers", "SQLDatabases"],
    "columns": ["Servers.ServerName", "Servers.MemoryGB", "SQLDatabases.DatabaseName", "SQLDatabases.SizeGB", "SQLDatabases.DaysSinceLastBackup"],
    "joins": [
      {"type": "INNER", "table": "SQLDatabases", "on": "Servers.ServerName = SQLDatabases.ServerName"}
    ],
    "where": [
      {"field": "SQLDatabases.BackupIssue", "operator": "IS NOT NULL", "value": ""}
    ],
    "orderBy": [{"field": "SQLDatabases.SizeGB", "direction": "DESC"}]
  }
}
```

### Template 3: Application Distribution
```json
{
  "name": "Application Distribution",
  "description": "Count of servers per application",
  "query": {
    "tables": ["ServerApplications"],
    "columns": ["ServerApplications.ApplicationName", "COUNT(DISTINCT ServerApplications.ServerName) AS ServerCount"],
    "groupBy": ["ServerApplications.ApplicationName"],
    "orderBy": [{"field": "ServerCount", "direction": "DESC"}],
    "limit": 20
  }
}
```

---

## Cost-Benefit Analysis

### Benefits
1. **Accessibility**: Non-technical users can query database (BA, PM, consultants)
2. **Time Savings**: 10-20 minutes per query → 30 seconds
3. **Reduced Errors**: No SQL syntax errors
4. **Knowledge Transfer**: Less dependency on technical team
5. **Reusability**: Save and share queries across team
6. **Compliance**: Audit trail of who ran what queries

### Costs
1. **Development Time**: 24-40 hours
2. **Testing**: 8-12 hours
3. **Documentation**: 4-6 hours
4. **Maintenance**: 2-4 hours/quarter

### ROI Calculation
- **Team Size**: 5 consultants
- **Queries per Week**: 10 queries/consultant = 50 total
- **Time Saved per Query**: 15 minutes
- **Weekly Savings**: 50 × 15 min = 12.5 hours = 1.5 FTE days
- **Monthly Savings**: 6 FTE days
- **Payback Period**: ~1 month

**[Inference] ROI: Very Positive - Tool pays for itself in 1 month**

---

## Risk Assessment

### Technical Risks
| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| SQL injection | High | Low | Use parameterized queries only |
| Performance issues with large result sets | Medium | Medium | Implement pagination (1000 rows) |
| Complex JOIN queries fail | Medium | Medium | Validate relationships, provide templates |
| Database schema changes break UI | Low | Low | Dynamic schema reading |

### User Risks
| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| User creates incorrect queries | Medium | Medium | Validation, preview results before export |
| User overwhelmed by complexity | Medium | Low | Start with templates, progressive disclosure |
| User expectations too high | Low | Medium | Clear documentation on capabilities |

---

## Recommendation

### ✅ **Proceed with Phase 1 MVP**

**Reasoning**:
1. **High ROI**: Payback in 1 month with 5-user team
2. **Manageable Effort**: 16-20 hours for usable MVP
3. **Low Risk**: Building on existing technology (Windows Forms)
4. **High Demand**: Non-technical users need database access
5. **Competitive Advantage**: Most audit tools don't offer this

### **Phased Rollout**
- **Week 1**: MVP (table select, WHERE, results)
- **Week 2**: Get user feedback, iterate
- **Week 3**: Add JOINs and aggregation if needed
- **Week 4**: Polish and templates

### **Alternative: Third-Party Tools**
If development time is constrained, consider:
1. **DB Browser for SQLite** (Free, open-source)
2. **SQLiteStudio** (Free, visual query builder)
3. **Linqpad** (Commercial, powerful)

**Trade-off**: Less integrated, but zero development time

---

## Next Steps

1. ✅ Review this design document
2. ✅ Decide: Build custom vs. recommend third-party tool
3. ✅ If building: Approve Phase 1 budget (16-20 hours)
4. ✅ Assign developer (ideally same as main GUI)
5. ✅ Schedule user testing with 2-3 business analysts

---

**Document Version**: 1.0  
**Author**: Adrian Johnson <adrian207@gmail.com>  
**Last Updated**: 2025-10-21

