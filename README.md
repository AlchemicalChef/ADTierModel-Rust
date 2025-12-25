# AD Tier Model Manager

A desktop application for managing Microsoft Active Directory tiered administrative models, built with Tauri, Rust, and React.

## Overview

AD Tier Model Manager implements a tiered administrative model for Active Directory environments, following Microsoft's Enhanced Security Administrative Environment (ESAE) best practices. The application enforces separation of duties and reduces the risk of privilege escalation by logically separating administrative access into three tiers.

## Features

- **Tier Management**: View and manage objects across Tier 0, Tier 1, Tier 2, and Unassigned
- **Virtualized UI**: Handle thousands of AD objects with smooth scrolling (tested with 6,000+ objects)
- **GPO Configuration**: Automatically configure Group Policy Objects for tier isolation
- **Compliance Monitoring**: Detect cross-tier access violations, unassigned objects, stale accounts, and more
- **User Rights Assignments**: Enforce logon restrictions between tiers
- **Bulk Operations**: Select and move multiple objects between tiers
- **Health Checks**: Monitor AD infrastructure health
- **Audit Logging**: Track administrative actions with exportable reports
- **Dark Mode**: Full dark mode support

## Tier Structure

| Tier | Description | Examples |
|------|-------------|----------|
| **Tier 0** | Identity Infrastructure | Domain Controllers, ADFS, Entra Connect, Certificate Authorities, PAWs |
| **Tier 1** | Server Management | Application servers, database servers, file servers |
| **Tier 2** | Workstation Management | User workstations, endpoints |

## Security Model

The application enforces tier isolation through GPO-based user rights assignments:

- **Deny log on locally** - Prevents interactive logon from other tiers
- **Deny log on through Remote Desktop** - Prevents RDP access from other tiers
- **Deny access from the network** - Prevents network logon from other tiers
- **Deny log on as a batch job** - Prevents scheduled task execution from other tiers
- **Deny log on as a service** - Prevents service account abuse from other tiers

### Tier Isolation Matrix

| Account | Tier 0 Resources | Tier 1 Resources | Tier 2 Resources |
|---------|------------------|------------------|------------------|
| Tier 0 Admins | ✓ Allowed | ✗ Denied | ✗ Denied |
| Tier 1 Admins | ✗ Denied | ✓ Allowed | ✗ Denied |
| Tier 2 Admins | ✗ Denied | ✗ Denied | ✓ Allowed |

## Requirements

- Windows 10/11 or Windows Server 2016+
- Active Directory domain membership
- Domain Admin or equivalent privileges for GPO configuration
- .NET Framework 4.7.2+ (for PowerShell cmdlets)

## Installation

### From Release

1. Download the latest installer from [Releases](../../releases)
2. Run `AD Tier Model_x.x.x_x64-setup.exe` or install via MSI
3. Launch "AD Tier Model" from the Start Menu

### Build from Source

#### Prerequisites

- **Node.js 18+** - [Download](https://nodejs.org/)
- **Rust 1.70+** - [Download](https://rustup.rs/)
- **Visual Studio Build Tools 2022** - Required for Windows MSVC toolchain
  - Install with "Desktop development with C++" workload
  - Or run: `winget install Microsoft.VisualStudio.2022.BuildTools`

#### Build Steps

```powershell
# Clone the repository
git clone https://github.com/yourusername/ADTierModel-Rust.git
cd ADTierModel-Rust

# Install dependencies
npm install

# Development mode (with hot reload)
npm run tauri dev

# Production build
npm run tauri build
```

#### Build Outputs

After a successful build, installers are located at:
- **MSI**: `src-tauri/target/release/bundle/msi/AD Tier Model_1.0.0_x64_en-US.msi`
- **NSIS**: `src-tauri/target/release/bundle/nsis/AD Tier Model_1.0.0_x64-setup.exe`
- **Standalone**: `src-tauri/target/release/ad-tier-model.exe`

## Usage

### Initial Setup

1. Launch the application on a domain-joined machine
2. The initialization wizard will guide you through:
   - Creating the tier OU structure
   - Creating tier security groups
   - Configuring GPOs for tier isolation

### GPO Management

Navigate to **Settings > GPO Management** to:
- View GPO status for each tier
- Configure or reconfigure tier GPOs
- Verify user rights assignments are applied

### Compliance Monitoring

The **Compliance** tab displays a compliance score (0-100) and detects:
- **Cross-tier access violations** - Users with group membership in multiple tiers (Critical)
- **Unassigned objects** - Computers, users, and groups not assigned to any tier (High)
- **Stale accounts** - Accounts that haven't logged in for 90+ days (Medium)
- **Service account vulnerabilities** - Service accounts not marked as sensitive (High)
- **Wrong tier placement** - Objects with group membership conflicting with their OU location

Bulk remediation actions are available for stale accounts and service account hardening.

## Project Structure

```
ADTierModel-Rust/
├── src/                    # React frontend
│   ├── components/         # UI components
│   ├── hooks/              # React hooks
│   ├── services/           # Tauri API bindings
│   ├── store/              # Zustand state management
│   └── types/              # TypeScript types
├── src-tauri/              # Rust backend
│   ├── src/
│   │   ├── commands/       # Tauri commands
│   │   ├── domain/         # Domain models
│   │   └── infrastructure/ # AD/LDAP integration
│   └── Cargo.toml
├── package.json
└── tauri.conf.json
```

## Technology Stack

- **Frontend**: React 18, TypeScript, Tailwind CSS, Headless UI
- **State Management**: Zustand, TanStack Query
- **Virtualization**: TanStack Virtual (for large dataset rendering)
- **Backend**: Rust, Tauri 2.x
- **AD Integration**: Windows ADSI (via windows-rs crate)
- **GPO Management**: Native Windows API via windows-rs

## License

MIT License - See [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please read the contributing guidelines before submitting pull requests.

## Acknowledgments

- Microsoft's [Securing Privileged Access](https://docs.microsoft.com/en-us/security/compass/privileged-access-access-model) documentation
- [Tauri](https://tauri.app/) framework
- [windows-rs](https://github.com/microsoft/windows-rs) crate
