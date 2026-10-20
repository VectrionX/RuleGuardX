# RuleGuardX

RuleGuardX is a privacy-bounded, local-first firewall rules audit and risk analysis application. Ingest exported policy configurations, service objects, and network objects to inspect structural risk without network exposure or cloud dependencies.

[![RuleGuardX Portal Screenshot](https://raw.githubusercontent.com/VectrionX/RuleGuardX/main/screenshot/Homeepage.png)](https://github.com/VectrionX/RuleGuardX/blob/main/screenshot/Homeepage.png)

## What it reports

- High-risk and plaintext protocol exposure (RDP 3389, SSH 22, Telnet 23, FTP 21, SMB 445, etc.)
- Permissive wildcard access (`ANY` source, destination, or port combinations)
- Subnet blast radius and CIDR scope evaluations (`/8`, `/16`, or large network blocks)
- Policy hygiene anomalies: shadowed rules (dead configurations), conflicting allow/deny logic, and latent risk in disabled rules
- Dynamic object resolution for mapped service definitions and network CIDR definitions
- Defensible risk scores (0–100) aligned with NIST SP 800-41, MITRE ATT&CK, CIS Controls, and Zero-Trust baselines

The application has no external network analysis path, cloud synchronization, or remote database. It does not communicate with firewall management planes or modify production configurations. All parsing, correlation, and scoring execute strictly inside the client browser.

## Run locally

Requires Node.js 18+ and npm.

```sh
npm install
npm run dev
```

Open the local Vite URL shown in the terminal. No API key or environment configuration is needed. All policy analysis runs client-side from the imported CSV files.

## Quality checks

```sh
npm run build
npm run preview
```

The application compiles via Vite and TypeScript with strict typing. Deterministic correlation and CIDR parsing logic run in browser memory without persisting rule content.

## Safety and privacy

Use sanitized policy exports where possible. The application intentionally does not upload, transmit, or synchronize firewall rules to any remote service. Configuration settings and custom port definitions are kept in browser `localStorage`. Treat generated scores and findings as analyst triage evidence. Never upload live credentials or unredacted confidential keys.

## Repository hygiene

Sensitive files are excluded via `.gitignore`. Policy samples used for evaluation should be sanitized of internal hostnames and confidential IP blocks. No malware or proprietary firewall keys are stored in this repository. See [SECURITY.md](./SECURITY.md) for reporting security issues.

## Disclaimer

This project is provided "as is" without warranty. The authors are not responsible for misuse or damages. It is intended for defensive cybersecurity auditing and verification purposes only.

## Security and vulnerabilities

Refer to [SECURITY.md](./SECURITY.md) for security reporting and vulnerability information.

## Project status

Active client-side firewall policy auditor. Designed to run completely offline in zero-trust environments, isolated bastion workstations, or air-gapped security operations centers.

## Support

- Issues: [GitHub Issues](https://github.com/VectrionX/ruleguardx/issues)
- Maintainer: [VectrionX](https://github.com/VectrionX/)
- Website: [vectrionx.com](https://vectrionx.com/)
- LinkedIn: [mag99](https://www.linkedin.com/in/mag99/)

## License summary

This project is licensed under a Non-Commercial Attribution License. It is free for personal, educational, and research use; modifications and derivatives must credit the author; commercial use requires prior written permission; and it is provided without warranty. See [LICENSE](./LICENSE) for full details.
