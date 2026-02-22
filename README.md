<div align="center">

# 🐺 HoundBot
**AI-Powered BloodHound Analyzer**

<p align="center">
  <img src="https://img.shields.io/badge/Tool-Offensive_Security-red.svg?style=for-the-badge" alt="Offensive Security">
  <img src="https://img.shields.io/badge/Target-Active_Directory-darkred.svg?style=for-the-badge" alt="Active Directory">
  <img src="https://img.shields.io/badge/AI_Engine-Ollama-red.svg?style=for-the-badge" alt="Ollama">
</p>

An offensive security tool that parses BloodHound/SharpHound ZIP dumps, performs static analysis for Active Directory vulnerabilities, and uses AI (Ollama) to generate actionable exploitation commands.

<img width="732" height="141" alt="image" src="https://github.com/user-attachments/assets/e175f973-2547-4855-a2e7-aa65081c06ee" />

</div>

> [!CAUTION]
> **RED TEAM & VAPT USE ONLY:** This tool is intended strictly for authorized penetration testing, red teaming, and security research. Unauthorized use against systems you do not own or have explicit permission to test is illegal.

---

## 🚀 Features

* **📦 BloodHound ZIP Parser** — Automatically extracts and parses SharpHound JSON files (users, groups, computers, GPOs, OUs, domains, containers).
* **🔍 12+ Static Analysis Checks**:
  * Domain Admins & high-value group enumeration
  * Kerberoastable accounts (SPNs)
  * AS-REP Roastable accounts
  * Password Never Expires detection
  * Unconstrained & Constrained Delegation
  * Dangerous ACL abuse (GenericAll, WriteDacl, WriteOwner, ForceChangePassword, etc.)
  * DCSync rights detection
  * GPO abuse opportunities
  * Stale/disabled privileged accounts
  * **BFS privilege escalation path finding** from owned user to Domain Admin
* **🧠 AI-Powered Exploitation Guidance** — Sends findings to Ollama (`qwen3.5:397b`) for exact, copy-paste-ready commands using `netexec`, `impacket`, `bloodyAD`, `Certipy`, and more.
* **🎨 Beautiful Terminal Output** — Rich-powered color-coded panels, tables, and trees.
* **📑 Multi-Format Report Export**:
  * **Markdown** — Full report with executive summary, all findings, and AI commands.
  * **HTML** — Dark-themed, self-contained report with copy-to-clipboard buttons, TOC sidebar, and responsive design.
  * **JSON** — Structured data for programmatic consumption and pipeline integration.
* **🎯 Risk Scoring** — Weighted 0–100 risk score with letter grade (A–F) based on finding severity.

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/Ravi-lk/HoundBot.git
cd HoundBot

# Install dependencies
pip install -r requirements.txt

# Configure API key
cp .env.example .env
# Edit .env and set your OLLAMA_API_KEY
```

## ⚙️ Configuration

Edit the `.env` file to configure your AI engine:

```env
OLLAMA_API_KEY=your_api_key_here
OLLAMA_MODEL=qwen3.5:397b
OLLAMA_BASE_URL=https://ollama.com
```

## 💻 Usage

### Full Analysis (Static + AI)
```bash
python houndbot.py --zip bloodhound.zip --owned-user "Ravindu.Lakmina" --dc-ip 172.16.101.200
```

### Static Analysis Only (No AI)
```bash
python houndbot.py --zip bloodhound.zip --owned-user "Ravindu.Lakmina" --dc-ip 172.16.101.200 --no-ai
```

### Export Report
```bash
# Default: generates both Markdown + HTML reports
python houndbot.py --zip bloodhound.zip --owned-user "Ravindu.Lakmina" --dc-ip 172.16.101.200 --output report

# HTML report only
python houndbot.py --zip bloodhound.zip --no-ai --format html

# JSON report only  
python houndbot.py --zip bloodhound.zip --no-ai --format json

# All formats (MD + HTML + JSON)
python houndbot.py --zip bloodhound.zip --no-ai --format all
```

### All Options

```text
usage: houndbot.py [-h] --zip ZIP [--owned-user OWNED_USER] [--dc-ip DC_IP]
                   [--no-ai] [--output OUTPUT] [--api-key API_KEY]
                   [--model MODEL] [--verbose] [--version]

Options:
  --zip, -z         Path to BloodHound SharpHound ZIP file (required)
  --owned-user, -u  Currently owned username (e.g., "Ravindu.Lakmina")
  --dc-ip, -d       Domain Controller IP address
  --no-ai           Skip AI analysis, run static checks only
  --output, -o      Output report base path (without extension)
  --format, -f      Report format: md, html, json, or all (default: all)
  --api-key         Ollama API key (overrides .env)
  --model           Ollama model name (default: qwen3.5:397b)
  --verbose, -v     Enable verbose output
```

## 🏗️ Architecture

```text
houndbot.py      — CLI entry point (4-phase execution)
parser.py        — BloodHound ZIP/JSON parser with SID resolution
analyzer.py      — Static analysis engine (12+ vulnerability checks + BFS pathfinder)
ai_engine.py     — Ollama cloud API integration (streaming)
prompts.py       — Expert system prompts for exploitation commands
reporter.py      — Rich terminal output + markdown report generator
```

## 📊 Supported Findings

| Finding | Severity | Description |
|---------|----------|-------------|
| **Kerberoastable** | `CRITICAL` | Users with SPNs — crack TGS tickets offline |
| **AS-REP Roastable** | `CRITICAL` | No preauth — get AS-REP hashes without creds |
| **DCSync Rights** | `CRITICAL` | Replicate domain creds — full compromise |
| **Dangerous ACLs** | `CRITICAL` | GenericAll, WriteDacl, WriteOwner abuse |
| **Unconstrained Delegation** | `CRITICAL` | Capture TGTs from authenticating principals |
| **Privesc Paths** | `CRITICAL` | BFS attack paths from owned user to DA |
| **Constrained Delegation** | `HIGH` | S4U2Proxy abuse |
| **GPO Abuse** | `HIGH` | Write access to GPOs |
| **Password Never Expires** | `MEDIUM` | Stale passwords, spray targets |
| **Stale Accounts** | `INFO` | Disabled accounts in privileged groups |

## 🤖 AI-Generated Commands

When AI is enabled, HoundBot generates exploitation commands utilizing industry-standard tools:
* **`netexec` (nxc)** — SMB/LDAP/WinRM enumeration and exploitation
* **`impacket`** — secretsdump, getST, getTGT, psexec, wmiexec, GetNPUsers, GetUserSPNs
* **`bloodyAD`** — LDAP-based AD object manipulation
* **`Certipy`** — AD CS certificate abuse
* **`Rubeus`** — Kerberos attacks
* **`Evil-WinRM`** — WinRM shell access

---

## ⚠️ Disclaimer

This tool is intended for authorized penetration testing and security research only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before using this tool.

## 📜 Credits

Built by **Ravindu Lakmina**

## ⚖️ License

MIT License
