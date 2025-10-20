# M&A Technical Discovery Script - Documentation

**Author**: Adrian Johnson <adrian207@gmail.com>  
**Version**: 1.0  
**Last Updated**: October 20, 2025

---

## Documentation Structure

This directory contains comprehensive documentation for the M&A Technical Discovery Script. Start here to find what you need.

### 📚 Core Documentation

| Document | Description | Audience |
|----------|-------------|----------|
| [Quick Start Guide](QUICK_START.md) | Get up and running in 5 minutes | All Users |
| [Installation Guide](INSTALLATION.md) | Detailed setup and prerequisites | IT Administrators |
| [User Guide](USER_GUIDE.md) | Complete usage instructions | Consultants, Auditors |
| [Troubleshooting Guide](TROUBLESHOOTING.md) | Common issues and solutions | Support Teams |
| [Module Reference](MODULE_REFERENCE.md) | Technical API documentation | Developers |

### 🔧 Technical Documentation

| Document | Description | Audience |
|----------|-------------|----------|
| [Design Document](DESIGN_DOCUMENT.md) | Architecture and technical design | Architects, Developers |
| [Development Progress](DEVELOPMENT_PROGRESS.md) | Build history and features | Project Stakeholders |

---

## Quick Links by Role

### **I'm an M&A Consultant**
👉 Start with [Quick Start Guide](QUICK_START.md)  
📖 Then read [User Guide](USER_GUIDE.md)

### **I'm an IT Administrator**
👉 Start with [Installation Guide](INSTALLATION.md)  
🔧 Keep [Troubleshooting Guide](TROUBLESHOOTING.md) handy

### **I'm a Developer/Engineer**
👉 Review [Design Document](DESIGN_DOCUMENT.md)  
📚 Reference [Module Reference](MODULE_REFERENCE.md)

### **I'm a Project Manager/Executive**
👉 Read [Development Progress](DEVELOPMENT_PROGRESS.md)  
📊 Focus on value metrics and deliverables

---

## Common Questions

**Q: How long does the audit take?**  
A: 30-90 minutes for a medium environment (500 users, 50 servers, 10 SQL instances). See [User Guide](USER_GUIDE.md) for details.

**Q: What permissions do I need?**  
A: Domain Admin (on-prem) + Global Reader (M365). See [Installation Guide](INSTALLATION.md) for full requirements.

**Q: Is the data encrypted?**  
A: Yes! Three encryption methods available (EFS, Archive, Azure Key Vault). See [User Guide - Security](USER_GUIDE.md#security) section.

**Q: The GUI isn't launching - help!**  
A: Check [Troubleshooting Guide](TROUBLESHOOTING.md) for common issues and solutions.

**Q: Can I customize the reports?**  
A: Yes! See [Module Reference](MODULE_REFERENCE.md) for customization options.

---

## Support & Contribution

**Questions?** Check the [Troubleshooting Guide](TROUBLESHOOTING.md) first.

**Found a bug?** See [CONTRIBUTING.md](../CONTRIBUTING.md) for how to report issues.

**Want to contribute?** Review [Design Document](DESIGN_DOCUMENT.md) to understand the architecture.

---

## Document Conventions

Throughout this documentation:

- ✅ **Green checkmarks** indicate completed features
- ⚠️ **Yellow warnings** highlight important notes
- 🚨 **Red alerts** mark critical security considerations
- 💡 **Light bulbs** provide helpful tips
- 📝 **Notes** offer additional context
- 🔐 **Locks** indicate security-related content

**Code blocks** use PowerShell syntax highlighting:
```powershell
.\Run-M&A-Audit.ps1 -CompanyName "Contoso" -OutputFolder "C:\Audits\Contoso"
```

**File paths** use backticks: `C:\Audits\Output\`

**Parameters** are shown in bold: `-CompanyName`

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | Oct 2025 | Initial release - All 18 modules complete |

---

**Next Steps**: Choose a document from the table above based on your role and needs.
