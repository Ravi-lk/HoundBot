"""
prompts.py — Expert System Prompts for AI-Powered AD Exploitation Guidance

Contains carefully crafted system prompts and finding-specific templates
that instruct the AI model to generate actionable exploitation commands.
"""

SYSTEM_PROMPT = """You are an expert Active Directory penetration tester and red team operator with deep knowledge of:
- **netexec (nxc)** — for SMB, LDAP, WinRM, MSSQL enumeration and exploitation
- **impacket** — secretsdump.py, getST.py, getTGT.py, wmiexec.py, psexec.py, dcomexec.py, smbexec.py, GetNPUsers.py, GetUserSPNs.py, addcomputer.py, rbcd.py
- **bloodyAD** — for LDAP-based AD object manipulation (ACL abuse, RBCD, Shadow Credentials, password changes)
- **Certipy** — for AD CS abuse (ESC1-ESC8, certificate template enumeration)
- **Rubeus** — for Kerberos attacks (AS-REP roasting, Kerberoasting, delegation abuse, S4U)
- **PowerView / SharpHound** — for AD enumeration
- **ldapsearch / ldapmodify** — for direct LDAP queries
- **Evil-WinRM** — for WinRM shell access
- **CrackMapExec legacy** — as fallback reference

Your role is to analyze BloodHound findings and provide EXACT, COPY-PASTE-READY exploitation commands for each vulnerability found. 

Rules:
1. Always provide the FULL command with proper syntax — no placeholders like <value>, use the actual values provided in the findings
2. Use `$TARGET_IP` for the DC/target IP (user will substitute), `$USERNAME` for owned username, `$PASSWORD` for owned password, `$DOMAIN` for domain name
3. Provide MULTIPLE tool alternatives where possible (e.g., both netexec and impacket)
4. Explain each step briefly — what the command does and why
5. Order commands by attack chain logic (enumerate → exploit → post-exploit)
6. Include verification commands to confirm exploitation success
7. Flag any prerequisites or dependencies (e.g., "requires valid creds", "requires network access to port 445")
8. For privilege escalation paths, show the FULL chain of commands from owned user to target
9. Use Linux command syntax (attacker machine runs Kali/Parrot)
10. Always consider OPSEC — mention if a command is noisy or generates logs"""


def build_analysis_prompt(findings_summary: str, domain_info: str, owned_user: str, dc_ip: str) -> str:
    """Build the main analysis prompt with all findings context."""
    return f"""Analyze the following Active Directory BloodHound findings and provide detailed exploitation commands for each finding.

## Environment Context
- **Domain**: {domain_info}
- **Domain Controller IP**: {dc_ip}
- **Currently Owned User**: {owned_user}

## BloodHound Analysis Findings

{findings_summary}

## Instructions

For EACH finding above, provide:
1. **Risk Assessment** — Why this is dangerous (1-2 sentences)
2. **Exploitation Commands** — Exact commands using netexec, impacket, bloodyAD, or other relevant tools
3. **Verification** — How to confirm the exploit worked
4. **OPSEC Notes** — Detection risk level (Low/Medium/High)

For privilege escalation paths, provide the COMPLETE chain of commands from the owned user to Domain Admin.

Format your response clearly with markdown headers for each finding. Use code blocks for all commands."""


def build_finding_prompt(finding_type: str, finding_data: dict, domain: str, owned_user: str, dc_ip: str) -> str:
    """Build a prompt for a specific finding type."""
    templates = {
        "kerberoastable": _kerberoast_prompt,
        "asreproastable": _asreproast_prompt,
        "dcsync": _dcsync_prompt,
        "dangerous_acl": _dangerous_acl_prompt,
        "unconstrained_delegation": _unconstrained_deleg_prompt,
        "constrained_delegation": _constrained_deleg_prompt,
        "gpo_abuse": _gpo_abuse_prompt,
        "privesc_path": _privesc_path_prompt,
        "password_never_expires": _pwd_never_expires_prompt,
        "admin_to": _admin_to_prompt,
    }

    builder = templates.get(finding_type)
    if builder:
        return builder(finding_data, domain, owned_user, dc_ip)
    return _generic_finding_prompt(finding_type, finding_data, domain, owned_user, dc_ip)


def _kerberoast_prompt(data: dict, domain: str, owned_user: str, dc_ip: str) -> str:
    users = ", ".join(data.get("users", []))
    return f"""The following users have Service Principal Names (SPNs) set and are Kerberoastable:
**Users**: {users}
**Domain**: {domain} | **DC**: {dc_ip} | **Owned User**: {owned_user}

Provide exact commands to:
1. Request TGS tickets for these SPNs using impacket's GetUserSPNs.py
2. Request using netexec
3. Crack the tickets with hashcat (include the correct hash mode)
4. Alternative: Use Rubeus if we have a Windows foothold"""


def _asreproast_prompt(data: dict, domain: str, owned_user: str, dc_ip: str) -> str:
    users = ", ".join(data.get("users", []))
    return f"""The following users have "Do not require Kerberos preauthentication" enabled (AS-REP Roastable):
**Users**: {users}
**Domain**: {domain} | **DC**: {dc_ip}

Provide exact commands to:
1. Request AS-REP hashes using impacket's GetNPUsers.py
2. Request using netexec
3. Crack with hashcat (include correct hash mode)
4. Alternative: Use Rubeus if Windows foothold available"""


def _dcsync_prompt(data: dict, domain: str, owned_user: str, dc_ip: str) -> str:
    principals = ", ".join(data.get("principals", []))
    return f"""The following principals have DCSync rights (GetChanges + GetChangesAll) on the domain:
**Principals**: {principals}
**Domain**: {domain} | **DC**: {dc_ip} | **Owned User**: {owned_user}

Provide exact commands to:
1. Perform DCSync attack using impacket's secretsdump.py
2. Extract specific user hashes (Administrator, krbtgt)
3. Use netexec for DCSync
4. Create a Golden Ticket with the krbtgt hash
5. Pass-the-Hash to gain Domain Admin access"""


def _dangerous_acl_prompt(data: dict, domain: str, owned_user: str, dc_ip: str) -> str:
    acls_desc = "\n".join(
        f"- {a['principal']} has **{a['right']}** over {a['target']} ({a['target_type']})"
        for a in data.get("acls", [])
    )
    return f"""The following dangerous ACL permissions were found:
{acls_desc}
**Domain**: {domain} | **DC**: {dc_ip} | **Owned User**: {owned_user}

For EACH ACL finding, provide exploitation commands:
- **GenericAll**: Full control — change password, add to group, set SPN, RBCD, Shadow Credentials
- **GenericWrite**: Write properties — targeted Kerberoast (set SPN), RBCD, Shadow Credentials
- **WriteDacl**: Modify DACL — grant yourself GenericAll then exploit
- **WriteOwner**: Change owner — take ownership then modify DACL
- **ForceChangePassword**: Reset password without knowing current
- **AddMember**: Add yourself to a group
- **AllExtendedRights**: Force password change, read LAPS

Use bloodyAD, netexec, and impacket as appropriate for each."""


def _unconstrained_deleg_prompt(data: dict, domain: str, owned_user: str, dc_ip: str) -> str:
    targets = ", ".join(data.get("targets", []))
    return f"""The following objects have Unconstrained Delegation enabled:
**Targets**: {targets}
**Domain**: {domain} | **DC**: {dc_ip}

Provide commands for:
1. Printer Bug / PetitPotam to coerce DC authentication
2. Capture TGT using Rubeus monitor
3. Pass the captured TGT
4. Alternative: krbrelayx for relay attacks"""


def _constrained_deleg_prompt(data: dict, domain: str, owned_user: str, dc_ip: str) -> str:
    entries = "\n".join(
        f"- {e['source']} can delegate to: {', '.join(e['targets'])}"
        for e in data.get("entries", [])
    )
    return f"""The following constrained delegation configurations were found:
{entries}
**Domain**: {domain} | **DC**: {dc_ip} | **Owned User**: {owned_user}

Provide commands for:
1. S4U2Self + S4U2Proxy attack using impacket's getST.py
2. Use the resulting ticket to access the target service
3. Alternative: Rubeus s4u command"""


def _gpo_abuse_prompt(data: dict, domain: str, owned_user: str, dc_ip: str) -> str:
    gpos_desc = "\n".join(
        f"- {g['principal']} has {g['right']} on GPO: {g['gpo_name']}"
        for g in data.get("gpos", [])
    )
    return f"""The following GPO abuse opportunities were found:
{gpos_desc}
**Domain**: {domain} | **DC**: {dc_ip} | **Owned User**: {owned_user}

Provide commands for:
1. Modify GPO to add a scheduled task or startup script
2. Use SharpGPOAbuse for targeted exploitation
3. Add a local admin via GPO
4. Deploy a reverse shell via GPO"""


def _privesc_path_prompt(data: dict, domain: str, owned_user: str, dc_ip: str) -> str:
    paths_desc = ""
    for i, path in enumerate(data.get("paths", []), 1):
        chain = " → ".join(
            f"{step['from']} --[{step['via']}]--> {step['to']}"
            for step in path
        )
        paths_desc += f"\n**Path {i}**: {chain}\n"

    return f"""The following privilege escalation paths were found from the owned user to high-value targets:
{paths_desc}
**Domain**: {domain} | **DC**: {dc_ip} | **Owned User**: {owned_user}

For EACH path, provide the COMPLETE chain of exploitation commands:
1. Step-by-step commands for each link in the chain
2. Verification at each step
3. Final proof of Domain Admin access"""


def _pwd_never_expires_prompt(data: dict, domain: str, owned_user: str, dc_ip: str) -> str:
    users = ", ".join(data.get("users", []))
    return f"""The following enabled accounts have "Password Never Expires" set:
**Users**: {users}
**Domain**: {domain} | **DC**: {dc_ip}

Provide recommendations for:
1. Password spraying these accounts (they may have old/weak passwords)
2. netexec smb password spraying command
3. Considerations for lockout policies"""


def _admin_to_prompt(data: dict, domain: str, owned_user: str, dc_ip: str) -> str:
    entries = "\n".join(
        f"- {e['user']} is local admin on {e['computer']}"
        for e in data.get("entries", [])
    )
    return f"""The following users have local admin access on computers:
{entries}
**Domain**: {domain} | **DC**: {dc_ip} | **Owned User**: {owned_user}

Provide commands for:
1. Remote command execution via netexec (SMB, WinRM)
2. impacket psexec.py / wmiexec.py / smbexec.py
3. Credential dumping with secretsdump.py
4. SAM/SYSTEM/SECURITY hive extraction
5. LSASS dump for cleartext creds or tickets"""


def _generic_finding_prompt(finding_type: str, data: dict, domain: str, owned_user: str, dc_ip: str) -> str:
    import json as _json
    details = _json.dumps(data, indent=2, default=str)
    return f"""The following Active Directory misconfiguration was identified:
**Finding Type**: {finding_type}
**Details**:
```json
{details}
```
**Domain**: {domain} | **DC**: {dc_ip} | **Owned User**: {owned_user}

Provide detailed exploitation commands using netexec, impacket, bloodyAD, or any other relevant tool.
Include step-by-step instructions and verification commands."""
