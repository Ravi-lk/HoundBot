"""
reporter.py — Rich Terminal Output & Report Generator

Produces beautiful, color-coded terminal output using Rich library
and generates exportable reports in Markdown, HTML, and JSON formats.
"""

import os
import sys
import json
import time
from datetime import datetime

import markdown as md_lib
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich.columns import Columns
from rich.text import Text
from rich.markdown import Markdown
from rich import box

# Force UTF-8 output on Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

console = Console(force_terminal=True)

# Severity color mapping
SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "INFO": "cyan",
}


def print_banner():
    """Print the HoundBot banner."""
    banner = """
[bold red]  _   _                       _ ____        _
 | | | | ___  _   _ _ __   __| | __ )  ___ | |_
 | |_| |/ _ \\| | | | '_ \\ / _` |  _ \\ / _ \\| __|
 |  _  | (_) | |_| | | | | (_| | |_) | (_) | |_
 |_| |_|\\___/ \\__,_|_| |_|\\__,_|____/ \\___/ \\__|[/bold red]
[dim]    AI-Powered BloodHound Analyzer - Offensive Security Suite[/dim]
[dim]    v1.0.0 | github.com/Ravi-lk/HoundBot[/dim]
[dim italic]    Built by Ravindu[/dim italic]
"""
    console.print(banner)


def print_domain_overview(overview: dict):
    """Print domain overview in a styled panel."""
    table = Table(
        show_header=False,
        box=box.SIMPLE,
        padding=(0, 2),
        expand=True,
    )
    table.add_column("Property", style="bold cyan", width=22)
    table.add_column("Value", style="white")

    table.add_row("🌐 Domain", overview.get("domain_name", "N/A"))
    table.add_row("🔑 Domain SID", overview.get("domain_sid", "N/A"))
    table.add_row("📊 Functional Level", overview.get("functional_level", "N/A"))
    table.add_row(
        "👤 Users",
        f"{overview.get('total_users', 0)} total "
        f"({overview.get('enabled_users', 0)} enabled, "
        f"{overview.get('disabled_users', 0)} disabled)"
    )
    table.add_row("👥 Groups", str(overview.get("total_groups", 0)))
    table.add_row("💻 Computers", str(overview.get("total_computers", 0)))
    table.add_row("📋 GPOs", str(overview.get("total_gpos", 0)))
    table.add_row("📁 OUs", str(overview.get("total_ous", 0)))

    console.print(Panel(
        table,
        title="[bold white]🏰 Domain Overview[/]",
        border_style="cyan",
        padding=(1, 2),
    ))


def print_domain_admins(da: dict, data: dict):
    """Print Domain Admins information."""
    if not da.get("direct_members") and not da.get("nested_members"):
        return

    table = Table(
        title="👑 Domain Admins",
        box=box.ROUNDED,
        border_style="red",
        header_style="bold red",
        show_lines=True,
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("Name", style="bold white")
    table.add_column("Type", style="cyan")
    table.add_column("Membership", style="yellow")

    idx = 1
    for m in da.get("direct_members", []):
        table.add_row(str(idx), m["name"], m["type"], "Direct")
        idx += 1

    for m in da.get("nested_members", []):
        table.add_row(str(idx), m["name"], m["type"], f"Nested via {m.get('via_group', '?')}")
        idx += 1

    console.print(table)
    console.print()


def print_high_value_groups(groups: list):
    """Print high-value groups as a tree."""
    if not groups:
        return

    tree = Tree("[bold red]🎯 High-Value Groups[/bold red]")

    for g in sorted(groups, key=lambda x: x["member_count"], reverse=True):
        branch = tree.add(
            f"[bold yellow]{g['name']}[/] [dim]({g['member_count']} members)[/dim]"
        )
        for m in g["members"]:
            branch.add(f"[white]{m['name']}[/] [dim]({m['type']})[/dim]")

    console.print(Panel(tree, border_style="red", padding=(1, 2)))


def print_finding_table(title: str, severity: str, items: list, columns: list):
    """Print a generic finding table."""
    if not items:
        return

    color = SEVERITY_COLORS.get(severity, "white")

    table = Table(
        title=f"{title}",
        box=box.ROUNDED,
        border_style=color.replace("bold ", ""),
        header_style=f"bold {color.replace('bold ', '')}",
        show_lines=True,
    )

    for col_name, col_style, col_width in columns:
        table.add_column(col_name, style=col_style, width=col_width)

    for item in items:
        row = [str(item.get(col_name.lower().replace(" ", "_").replace("#", "idx"), ""))
               for col_name, _, _ in columns]
        table.add_row(*row)

    # Add severity badge
    console.print()
    severity_badge = Text(f" {severity} ", style=f"bold white on {color.replace('bold ', '')}")
    console.print(severity_badge, end=" ")
    console.print(table)


def print_kerberoastable(finding: dict):
    """Print Kerberoastable accounts."""
    if not finding.get("users"):
        return

    table = Table(
        box=box.ROUNDED,
        border_style="red",
        header_style="bold red",
        show_lines=True,
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("Username", style="bold white")
    table.add_column("Admin Count", style="yellow", justify="center")
    table.add_column("SPNs", style="cyan")

    for i, u in enumerate(finding["users"], 1):
        spns = ", ".join(u.get("spns", [])) or "N/A"
        admin = "✓" if u.get("admincount") else "✗"
        table.add_row(str(i), u["name"], admin, spns)

    console.print()
    console.print(Panel(
        table,
        title=f"[bold red]🔥 Kerberoastable Accounts ({finding['count']})[/]",
        border_style="red",
        subtitle="[dim]Accounts with SPNs set — request TGS tickets and crack offline[/dim]",
    ))


def print_asreproastable(finding: dict):
    """Print AS-REP Roastable accounts."""
    if not finding.get("users"):
        return

    table = Table(
        box=box.ROUNDED,
        border_style="red",
        header_style="bold red",
        show_lines=True,
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("Username", style="bold white")
    table.add_column("Enabled", style="green", justify="center")
    table.add_column("Admin Count", style="yellow", justify="center")

    for i, u in enumerate(finding["users"], 1):
        enabled = "✓" if u.get("enabled") else "✗"
        admin = "✓" if u.get("admincount") else "✗"
        table.add_row(str(i), u["name"], enabled, admin)

    console.print()
    console.print(Panel(
        table,
        title=f"[bold red]🔥 AS-REP Roastable Accounts ({finding['count']})[/]",
        border_style="red",
        subtitle="[dim]Pre-auth disabled — request AS-REP hashes without creds[/dim]",
    ))


def print_dangerous_acls(finding: dict):
    """Print dangerous ACL permissions."""
    if not finding.get("acls"):
        return

    table = Table(
        box=box.ROUNDED,
        border_style="red",
        header_style="bold red",
        show_lines=True,
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("Principal", style="bold white", max_width=30)
    table.add_column("Right", style="bold red", justify="center")
    table.add_column("Target", style="cyan", max_width=30)
    table.add_column("Type", style="yellow")
    table.add_column("Inh.", style="dim", justify="center")

    for i, a in enumerate(finding["acls"][:40], 1):
        inherited = "✓" if a.get("is_inherited") else "✗"
        table.add_row(
            str(i),
            a["principal_name"],
            a["right"],
            a["target_name"],
            a["target_type"],
            inherited,
        )

    console.print()
    console.print(Panel(
        table,
        title=f"[bold red]🔥 Dangerous ACL Permissions ({finding['count']})[/]",
        border_style="red",
        subtitle="[dim]Non-default principals with exploitable AD permissions[/dim]",
    ))


def print_dcsync(finding: dict):
    """Print DCSync rights."""
    if not finding.get("principals"):
        return

    table = Table(
        box=box.ROUNDED,
        border_style="red",
        header_style="bold red",
        show_lines=True,
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("Principal", style="bold white")
    table.add_column("Type", style="cyan")

    for i, p in enumerate(finding["principals"], 1):
        table.add_row(str(i), p["name"], p["type"])

    console.print()
    console.print(Panel(
        table,
        title=f"[bold red]🔥 DCSync Rights ({finding['count']})[/]",
        border_style="red",
        subtitle="[dim]Can replicate domain credentials — full domain compromise[/dim]",
    ))


def print_delegation(ud_finding: dict, cd_finding: dict):
    """Print delegation findings."""
    if ud_finding.get("targets"):
        table = Table(
            box=box.ROUNDED,
            border_style="red",
            header_style="bold red",
            show_lines=True,
        )
        table.add_column("#", style="dim", width=4)
        table.add_column("Object", style="bold white")
        table.add_column("Type", style="cyan")
        table.add_column("OS", style="dim")

        for i, t in enumerate(ud_finding["targets"], 1):
            table.add_row(str(i), t["name"], t["type"], t.get("os", ""))

        console.print()
        console.print(Panel(
            table,
            title=f"[bold red]🔥 Unconstrained Delegation ({ud_finding['count']})[/]",
            border_style="red",
            subtitle="[dim]Can capture TGTs from authenticating principals[/dim]",
        ))

    if cd_finding.get("entries"):
        table = Table(
            box=box.ROUNDED,
            border_style="yellow",
            header_style="bold yellow",
            show_lines=True,
        )
        table.add_column("#", style="dim", width=4)
        table.add_column("Source", style="bold white")
        table.add_column("Type", style="cyan")
        table.add_column("Delegation Targets", style="yellow")

        for i, e in enumerate(cd_finding["entries"], 1):
            targets = ", ".join(
                t if isinstance(t, str) else t.get("ObjectIdentifier", t.get("Service", str(t)))
                for t in e["targets"]
            )
            table.add_row(str(i), e["name"], e["type"], targets)

        console.print()
        console.print(Panel(
            table,
            title=f"[bold yellow]⚠️ Constrained Delegation ({cd_finding['count']})[/]",
            border_style="yellow",
            subtitle="[dim]S4U2Proxy abuse potential[/dim]",
        ))


def print_gpo_abuse(finding: dict):
    """Print GPO abuse opportunities."""
    if not finding.get("gpos"):
        return

    table = Table(
        box=box.ROUNDED,
        border_style="yellow",
        header_style="bold yellow",
        show_lines=True,
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("Principal", style="bold white")
    table.add_column("Right", style="red")
    table.add_column("GPO Name", style="cyan")

    for i, g in enumerate(finding["gpos"], 1):
        table.add_row(str(i), g["principal_name"], g["right"], g["gpo_name"])

    console.print()
    console.print(Panel(
        table,
        title=f"[bold yellow]⚠️ GPO Abuse Opportunities ({finding['count']})[/]",
        border_style="yellow",
    ))


def print_pwd_never_expires(finding: dict):
    """Print password never expires accounts."""
    if not finding.get("users"):
        return

    table = Table(
        box=box.ROUNDED,
        border_style="yellow",
        header_style="bold yellow",
        show_lines=True,
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("Username", style="bold white")
    table.add_column("Admin Count", style="yellow", justify="center")

    for i, u in enumerate(finding["users"], 1):
        admin = "✓" if u.get("admincount") else "✗"
        table.add_row(str(i), u["name"], admin)

    console.print()
    console.print(Panel(
        table,
        title=f"[bold yellow]⚠️ Password Never Expires ({finding['count']})[/]",
        border_style="yellow",
        subtitle="[dim]Potential targets for password spraying[/dim]",
    ))


def print_privesc_paths(finding: dict):
    """Print privilege escalation paths as trees."""
    if not finding.get("paths"):
        console.print()
        console.print(Panel(
            "[yellow]No privilege escalation paths found from owned user.[/yellow]",
            title="[bold]🛤️ Privilege Escalation Paths[/]",
            border_style="dim",
        ))
        return

    console.print()
    tree = Tree(f"[bold red]🛤️ Privilege Escalation Paths ({finding['count']} found)[/bold red]")

    for i, path in enumerate(finding["paths"][:10], 1):
        path_branch = tree.add(
            f"[bold yellow]Path {i}[/] → [bold red]{path['target']}[/] "
            f"[dim]({path['hops']} hops)[/dim]"
        )
        for step in path["chain"]:
            step_text = (
                f"[white]{step['from']}[/] "
                f"[dim]──[[/][bold red]{step['via']}[/][dim]]──▶[/] "
                f"[cyan]{step['to']}[/]"
            )
            path_branch.add(step_text)

    console.print(Panel(tree, border_style="red", padding=(1, 2)))


def print_stale_accounts(finding: dict):
    """Print stale/disabled accounts."""
    if not finding.get("accounts"):
        return

    table = Table(
        box=box.ROUNDED,
        border_style="blue",
        header_style="bold blue",
        show_lines=True,
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("Account", style="bold white")
    table.add_column("Issue", style="yellow")
    table.add_column("Groups", style="cyan")

    for i, a in enumerate(finding["accounts"], 1):
        groups = ", ".join(a.get("groups", []))
        table.add_row(str(i), a["name"], a["issue"], groups)

    console.print()
    console.print(Panel(
        table,
        title=f"[bold blue]ℹ️ Stale/Disabled Accounts ({finding['count']})[/]",
        border_style="blue",
    ))


def print_all_findings(findings: dict, data: dict):
    """Print all findings to the console."""
    # Domain Overview
    print_domain_overview(findings.get("domain_overview", {}))

    # Domain Admins
    print_domain_admins(findings.get("domain_admins", {}), data)

    # High Value Groups
    print_high_value_groups(findings.get("high_value_groups", []))

    # Critical findings
    print_kerberoastable(findings.get("kerberoastable", {}))
    print_asreproastable(findings.get("asreproastable", {}))
    print_dcsync(findings.get("dcsync_rights", {}))
    print_delegation(
        findings.get("unconstrained_delegation", {}),
        findings.get("constrained_delegation", {}),
    )
    print_dangerous_acls(findings.get("dangerous_acls", {}))

    # Medium findings
    print_gpo_abuse(findings.get("gpo_abuse", {}))
    print_pwd_never_expires(findings.get("password_never_expires", {}))

    # Low/Info findings
    print_stale_accounts(findings.get("stale_accounts", {}))

    # Privesc paths (if available)
    if "privesc_paths" in findings:
        print_privesc_paths(findings["privesc_paths"])


def generate_markdown_report(
    findings: dict,
    ai_response: str = None,
    owned_user: str = None,
    dc_ip: str = None,
    output_path: str = "report.md",
):
    """Generate a comprehensive markdown report."""
    domain = findings.get("domain_overview", {})
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = []
    lines.append("# 🐕 HoundBot — BloodHound Analysis Report")
    lines.append(f"\n**Generated**: {now}")
    lines.append(f"**Domain**: {domain.get('domain_name', 'N/A')}")
    if owned_user:
        lines.append(f"**Owned User**: {owned_user}")
    if dc_ip:
        lines.append(f"**DC IP**: {dc_ip}")
    lines.append("")

    # Executive Summary
    lines.append("## 📊 Executive Summary\n")
    summary_items = []

    kerb = findings.get("kerberoastable", {})
    if kerb.get("count", 0):
        summary_items.append(f"- 🔥 **{kerb['count']}** Kerberoastable accounts found")

    asrep = findings.get("asreproastable", {})
    if asrep.get("count", 0):
        summary_items.append(f"- 🔥 **{asrep['count']}** AS-REP Roastable accounts found")

    dcs = findings.get("dcsync_rights", {})
    if dcs.get("count", 0):
        summary_items.append(f"- 🔥 **{dcs['count']}** principals with DCSync rights")

    dacl = findings.get("dangerous_acls", {})
    if dacl.get("count", 0):
        summary_items.append(f"- 🔥 **{dacl['count']}** dangerous ACL permissions")

    ud = findings.get("unconstrained_delegation", {})
    if ud.get("count", 0):
        summary_items.append(f"- 🔥 **{ud['count']}** unconstrained delegation targets")

    pe = findings.get("privesc_paths", {})
    if pe.get("count", 0):
        summary_items.append(f"- 🛤️ **{pe['count']}** privilege escalation paths found")

    gpo = findings.get("gpo_abuse", {})
    if gpo.get("count", 0):
        summary_items.append(f"- ⚠️ **{gpo['count']}** GPO abuse opportunities")

    pne = findings.get("password_never_expires", {})
    if pne.get("count", 0):
        summary_items.append(f"- ⚠️ **{pne['count']}** accounts with password never expires")

    if summary_items:
        lines.extend(summary_items)
    else:
        lines.append("No critical findings detected.")
    lines.append("")

    # Domain Overview
    lines.append("## 🏰 Domain Overview\n")
    lines.append(f"| Property | Value |")
    lines.append(f"|----------|-------|")
    lines.append(f"| Domain | {domain.get('domain_name', 'N/A')} |")
    lines.append(f"| Domain SID | {domain.get('domain_sid', 'N/A')} |")
    lines.append(f"| Functional Level | {domain.get('functional_level', 'N/A')} |")
    lines.append(f"| Total Users | {domain.get('total_users', 0)} ({domain.get('enabled_users', 0)} enabled) |")
    lines.append(f"| Total Groups | {domain.get('total_groups', 0)} |")
    lines.append(f"| Total Computers | {domain.get('total_computers', 0)} |")
    lines.append(f"| Total GPOs | {domain.get('total_gpos', 0)} |")
    lines.append("")

    # Domain Admins
    da = findings.get("domain_admins", {})
    if da.get("direct_members") or da.get("nested_members"):
        lines.append("## 👑 Domain Admins\n")
        lines.append("| Name | Type | Membership |")
        lines.append("|------|------|------------|")
        for m in da.get("direct_members", []):
            lines.append(f"| {m['name']} | {m['type']} | Direct |")
        for m in da.get("nested_members", []):
            lines.append(f"| {m['name']} | {m['type']} | Nested via {m.get('via_group', '?')} |")
        lines.append("")

    # Kerberoastable
    if kerb.get("users"):
        lines.append(f"## 🔥 Kerberoastable Accounts ({kerb['count']})\n")
        lines.append("| Username | Admin Count | SPNs |")
        lines.append("|----------|-------------|------|")
        for u in kerb["users"]:
            spns = ", ".join(u.get("spns", [])) or "N/A"
            lines.append(f"| {u['name']} | {'Yes' if u.get('admincount') else 'No'} | {spns} |")
        lines.append("")

    # AS-REP Roastable
    if asrep.get("users"):
        lines.append(f"## 🔥 AS-REP Roastable ({asrep['count']})\n")
        lines.append("| Username | Enabled | Admin Count |")
        lines.append("|----------|---------|-------------|")
        for u in asrep["users"]:
            lines.append(f"| {u['name']} | {'Yes' if u.get('enabled') else 'No'} | {'Yes' if u.get('admincount') else 'No'} |")
        lines.append("")

    # DCSync
    if dcs.get("principals"):
        lines.append(f"## 🔥 DCSync Rights ({dcs['count']})\n")
        lines.append("| Principal | Type |")
        lines.append("|-----------|------|")
        for p in dcs["principals"]:
            lines.append(f"| {p['name']} | {p['type']} |")
        lines.append("")

    # Dangerous ACLs
    if dacl.get("acls"):
        lines.append(f"## 🔥 Dangerous ACL Permissions ({dacl['count']})\n")
        lines.append("| Principal | Right | Target | Target Type | Inherited |")
        lines.append("|-----------|-------|--------|-------------|-----------|")
        for a in dacl["acls"][:50]:
            lines.append(
                f"| {a['principal_name']} | {a['right']} | "
                f"{a['target_name']} | {a['target_type']} | "
                f"{'Yes' if a.get('is_inherited') else 'No'} |"
            )
        lines.append("")

    # Delegation
    if ud.get("targets"):
        lines.append(f"## 🔥 Unconstrained Delegation ({ud['count']})\n")
        lines.append("| Object | Type |")
        lines.append("|--------|------|")
        for t in ud["targets"]:
            lines.append(f"| {t['name']} | {t['type']} |")
        lines.append("")

    cd = findings.get("constrained_delegation", {})
    if cd.get("entries"):
        lines.append(f"## ⚠️ Constrained Delegation ({cd['count']})\n")
        lines.append("| Source | Type | Delegation Targets |")
        lines.append("|--------|------|--------------------|")
        for e in cd["entries"]:
            targets = ", ".join(
                t if isinstance(t, str) else t.get("ObjectIdentifier", t.get("Service", str(t)))
                for t in e["targets"]
            )
            lines.append(f"| {e['name']} | {e['type']} | {targets} |")
        lines.append("")

    # GPO Abuse
    if gpo.get("gpos"):
        lines.append(f"## ⚠️ GPO Abuse ({gpo['count']})\n")
        lines.append("| Principal | Right | GPO |")
        lines.append("|-----------|-------|-----|")
        for g in gpo["gpos"]:
            lines.append(f"| {g['principal_name']} | {g['right']} | {g['gpo_name']} |")
        lines.append("")

    # Password Never Expires
    if pne.get("users"):
        lines.append(f"## ⚠️ Password Never Expires ({pne['count']})\n")
        lines.append("| Username | Admin Count |")
        lines.append("|----------|-------------|")
        for u in pne["users"]:
            lines.append(f"| {u['name']} | {'Yes' if u.get('admincount') else 'No'} |")
        lines.append("")

    # Stale Accounts
    stale = findings.get("stale_accounts", {})
    if stale.get("accounts"):
        lines.append(f"## ℹ️ Stale Accounts ({stale['count']})\n")
        lines.append("| Account | Issue | Groups |")
        lines.append("|---------|-------|--------|")
        for a in stale["accounts"]:
            groups = ", ".join(a.get("groups", []))
            lines.append(f"| {a['name']} | {a['issue']} | {groups} |")
        lines.append("")

    # Privesc Paths
    if pe.get("paths"):
        lines.append(f"## 🛤️ Privilege Escalation Paths ({pe['count']})\n")
        for i, path in enumerate(pe["paths"][:10], 1):
            chain = " → ".join(
                f"`{step['from']}` --[**{step['via']}**]--> `{step['to']}`"
                for step in path["chain"]
            )
            lines.append(f"### Path {i} → {path['target']} ({path['hops']} hops)\n")
            lines.append(chain)
            lines.append("")

    # AI Analysis
    if ai_response:
        lines.append("---\n")
        lines.append("## 🤖 AI-Generated Exploitation Commands\n")
        lines.append(ai_response)
        lines.append("")

    # Footer
    lines.append("---\n")
    lines.append("*Generated by HoundBot — AI-Powered BloodHound Analyzer | Built by Ravindu*")

    report_content = "\n".join(lines)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_content)

    return output_path


def calculate_risk_score(findings: dict) -> dict:
    """
    Calculate a 0-100 risk score based on weighted findings.

    Returns dict with score, grade, label, and color.
    """
    weights = {
        "kerberoastable": 15,
        "asreproastable": 15,
        "dcsync_rights": 20,
        "dangerous_acls": 12,
        "unconstrained_delegation": 14,
        "constrained_delegation": 6,
        "gpo_abuse": 8,
        "password_never_expires": 4,
        "stale_accounts": 2,
        "privesc_paths": 18,
    }

    score = 0
    for key, weight in weights.items():
        finding = findings.get(key, {})
        count = finding.get("count", 0)
        if count > 0:
            # Diminishing returns: first finding adds most weight
            score += min(weight, weight * (1 - 1 / (1 + count * 0.5)))

    # Clamp to 0-100
    score = min(100, max(0, round(score)))

    # Grade & label
    if score >= 80:
        grade, label, color = "F", "Critical Risk", "#ff4444"
    elif score >= 60:
        grade, label, color = "D", "High Risk", "#ff8c00"
    elif score >= 40:
        grade, label, color = "C", "Medium Risk", "#ffcc00"
    elif score >= 20:
        grade, label, color = "B", "Low Risk", "#44bb44"
    else:
        grade, label, color = "A", "Minimal Risk", "#00cc88"

    return {
        "score": score,
        "grade": grade,
        "label": label,
        "color": color,
    }


def generate_html_report(
    markdown_content: str,
    output_path: str = "report.html",
    risk: dict = None,
):
    """Generate a self-contained HTML report from markdown content."""

    # Convert markdown to HTML
    html_body = md_lib.markdown(
        markdown_content,
        extensions=["tables", "fenced_code", "codehilite", "toc"],
        extension_configs={
            "toc": {"title": "Table of Contents"},
        },
    )

    risk = risk or {"score": 0, "grade": "?", "label": "Unknown", "color": "#888"}

    html_template = f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HoundBot \u2014 BloodHound Analysis Report</title>
<style>
  :root {{
    --bg-primary: #0d1117;
    --bg-secondary: #161b22;
    --bg-tertiary: #21262d;
    --bg-card: #1c2128;
    --border: #30363d;
    --text-primary: #e6edf3;
    --text-secondary: #8b949e;
    --text-muted: #6e7681;
    --accent: #58a6ff;
    --accent-hover: #79c0ff;
    --critical: #ff4444;
    --high: #ff8c00;
    --medium: #ffcc00;
    --low: #44bb44;
    --info: #58a6ff;
    --success: #3fb950;
    --code-bg: #0d1117;
    --shadow: 0 1px 3px rgba(0,0,0,0.4), 0 4px 12px rgba(0,0,0,0.3);
    --radius: 8px;
  }}

  * {{ margin: 0; padding: 0; box-sizing: border-box; }}

  body {{
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, 'Helvetica Neue', Arial, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.7;
    font-size: 15px;
  }}

  /* ── Layout ───────────────────────────────────── */
  .wrapper {{
    display: flex;
    min-height: 100vh;
  }}

  .sidebar {{
    position: sticky;
    top: 0;
    height: 100vh;
    width: 280px;
    min-width: 280px;
    background: var(--bg-secondary);
    border-right: 1px solid var(--border);
    overflow-y: auto;
    padding: 24px 16px;
    scrollbar-width: thin;
    scrollbar-color: var(--border) transparent;
  }}

  .sidebar-brand {{
    display: flex;
    align-items: center;
    gap: 10px;
    padding-bottom: 20px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 20px;
  }}

  .sidebar-brand .logo {{
    font-size: 28px;
  }}

  .sidebar-brand .name {{
    font-weight: 700;
    font-size: 18px;
    color: var(--text-primary);
  }}

  .sidebar-brand .sub {{
    font-size: 11px;
    color: var(--text-muted);
    display: block;
  }}

  .toc-title {{
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    color: var(--text-muted);
    margin-bottom: 12px;
    font-weight: 600;
  }}

  .sidebar nav a {{
    display: block;
    padding: 6px 12px;
    color: var(--text-secondary);
    text-decoration: none;
    font-size: 13px;
    border-radius: 6px;
    transition: all 0.15s ease;
    margin-bottom: 2px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }}

  .sidebar nav a:hover {{
    background: var(--bg-tertiary);
    color: var(--accent);
  }}

  .main-content {{
    flex: 1;
    max-width: 960px;
    margin: 0 auto;
    padding: 40px 48px 80px;
  }}

  /* ── Risk Score Badge ─────────────────────────── */
  .risk-banner {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 24px 32px;
    display: flex;
    align-items: center;
    gap: 28px;
    margin-bottom: 36px;
    box-shadow: var(--shadow);
  }}

  .risk-circle {{
    width: 90px;
    height: 90px;
    border-radius: 50%;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    font-weight: 800;
    font-size: 32px;
    color: #fff;
    flex-shrink: 0;
    box-shadow: 0 0 20px rgba(0,0,0,0.3);
  }}

  .risk-circle .grade {{
    font-size: 14px;
    font-weight: 600;
    opacity: 0.85;
  }}

  .risk-info h3 {{
    font-size: 20px;
    margin-bottom: 4px;
  }}

  .risk-info p {{
    color: var(--text-secondary);
    font-size: 14px;
  }}

  /* ── Typography ───────────────────────────────── */
  h1 {{
    font-size: 28px;
    font-weight: 700;
    margin: 40px 0 16px;
    padding-bottom: 10px;
    border-bottom: 2px solid var(--border);
    color: var(--text-primary);
  }}

  h1:first-child {{ margin-top: 0; }}

  h2 {{
    font-size: 22px;
    font-weight: 600;
    margin: 36px 0 14px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--border);
    color: var(--accent);
  }}

  h3 {{
    font-size: 17px;
    font-weight: 600;
    margin: 24px 0 10px;
    color: var(--text-primary);
  }}

  p {{ margin: 8px 0; }}
  strong {{ color: var(--text-primary); }}
  hr {{
    border: none;
    border-top: 1px solid var(--border);
    margin: 32px 0;
  }}

  a {{ color: var(--accent); text-decoration: none; }}
  a:hover {{ color: var(--accent-hover); text-decoration: underline; }}

  ul, ol {{
    padding-left: 24px;
    margin: 10px 0;
  }}

  li {{
    margin: 4px 0;
  }}

  /* ── Tables ───────────────────────────────────── */
  table {{
    width: 100%;
    border-collapse: separate;
    border-spacing: 0;
    margin: 16px 0 24px;
    font-size: 14px;
    border-radius: var(--radius);
    overflow: hidden;
    box-shadow: var(--shadow);
  }}

  thead th {{
    background: var(--bg-tertiary);
    color: var(--text-primary);
    font-weight: 600;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    padding: 12px 16px;
    text-align: left;
    border-bottom: 2px solid var(--border);
  }}

  tbody td {{
    padding: 10px 16px;
    border-bottom: 1px solid var(--border);
    color: var(--text-secondary);
  }}

  tbody tr {{
    background: var(--bg-card);
    transition: background 0.12s ease;
  }}

  tbody tr:hover {{
    background: var(--bg-tertiary);
  }}

  tbody tr:last-child td {{
    border-bottom: none;
  }}

  /* ── Code Blocks ──────────────────────────────── */
  pre {{
    position: relative;
    background: var(--code-bg);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 16px 20px;
    margin: 14px 0;
    overflow-x: auto;
    font-size: 13px;
    line-height: 1.6;
  }}

  pre code {{
    font-family: 'Cascadia Code', 'Fira Code', 'JetBrains Mono', 'Consolas', monospace;
    color: #e6edf3;
    background: none;
    padding: 0;
    border: none;
    font-size: 13px;
  }}

  code {{
    font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
    background: var(--bg-tertiary);
    color: var(--accent);
    padding: 2px 7px;
    border-radius: 4px;
    font-size: 0.88em;
    border: 1px solid var(--border);
  }}

  /* ── Copy Button ──────────────────────────────── */
  .code-wrapper {{
    position: relative;
  }}

  .copy-btn {{
    position: absolute;
    top: 8px;
    right: 8px;
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    color: var(--text-secondary);
    padding: 4px 10px;
    border-radius: 5px;
    cursor: pointer;
    font-size: 12px;
    font-family: inherit;
    transition: all 0.15s ease;
    opacity: 0;
    z-index: 2;
  }}

  .code-wrapper:hover .copy-btn {{
    opacity: 1;
  }}

  .copy-btn:hover {{
    background: var(--accent);
    color: #fff;
    border-color: var(--accent);
  }}

  .copy-btn.copied {{
    background: var(--success);
    color: #fff;
    border-color: var(--success);
  }}

  /* ── Emoji severity badges ────────────────────── */
  /* ── Footer ───────────────────────────────────── */
  .footer {{
    text-align: center;
    padding: 36px 0 24px;
    color: var(--text-muted);
    font-size: 13px;
    border-top: 1px solid var(--border);
    margin-top: 48px;
  }}

  .footer a {{
    color: var(--accent);
  }}

  /* ── Print ────────────────────────────────────── */
  @media print {{
    .sidebar {{ display: none; }}
    .copy-btn {{ display: none; }}
    body {{ background: #fff; color: #000; font-size: 12px; }}
    .main-content {{ max-width: 100%; padding: 20px; }}
    .risk-banner {{ border: 2px solid #333; box-shadow: none; }}
    table {{ box-shadow: none; font-size: 11px; }}
    thead th {{ background: #eee; color: #000; }}
    tbody td {{ color: #333; }}
    pre {{ background: #f6f6f6; border: 1px solid #ccc; color: #000; }}
    pre code {{ color: #000; }}
    h1, h2, h3 {{ color: #000; }}
    .risk-circle {{ print-color-adjust: exact; -webkit-print-color-adjust: exact; }}
  }}

  /* ── Responsive ───────────────────────────────── */
  @media (max-width: 900px) {{
    .sidebar {{ display: none; }}
    .main-content {{ padding: 24px 20px 60px; }}
  }}
</style>
</head>
<body>
<div class="wrapper">
  <!-- Sidebar TOC -->
  <aside class="sidebar">
    <div class="sidebar-brand">
      <span class="logo">\U0001F415</span>
      <div>
        <span class="name">HoundBot</span>
        <span class="sub">BloodHound Analyzer</span>
      </div>
    </div>
    <div class="toc-title">Navigation</div>
    <nav id="toc-nav"></nav>
  </aside>

  <!-- Main Content -->
  <main class="main-content">
    <!-- Risk Score Banner -->
    <div class="risk-banner">
      <div class="risk-circle" style="background: {risk['color']};">
        {risk['score']}
        <span class="grade">Grade {risk['grade']}</span>
      </div>
      <div class="risk-info">
        <h3 style="color: {risk['color']};">{risk['label']}</h3>
        <p>Overall security risk score based on {risk['score'] > 0 and 'detected vulnerabilities and misconfigurations' or 'analysis results'}.</p>
      </div>
    </div>

    <!-- Report Body -->
    {html_body}

    <!-- Footer -->
    <div class="footer">
      Generated by <strong>HoundBot</strong> \u2014 AI-Powered BloodHound Analyzer | Built by <a href="#">Ravindu</a>
    </div>
  </main>
</div>

<script>
// ── Build TOC from headings ──────────────────────
(function() {{
  const nav = document.getElementById('toc-nav');
  const headings = document.querySelectorAll('.main-content h1, .main-content h2');
  headings.forEach(function(h, i) {{
    if (!h.id) h.id = 'section-' + i;
    const a = document.createElement('a');
    a.href = '#' + h.id;
    a.textContent = h.textContent;
    a.style.paddingLeft = h.tagName === 'H2' ? '20px' : '12px';
    a.style.fontWeight = h.tagName === 'H1' ? '600' : '400';
    nav.appendChild(a);
  }});
}})();

// ── Copy-to-clipboard on code blocks ─────────────
(function() {{
  document.querySelectorAll('pre').forEach(function(pre) {{
    const wrapper = document.createElement('div');
    wrapper.className = 'code-wrapper';
    pre.parentNode.insertBefore(wrapper, pre);
    wrapper.appendChild(pre);

    const btn = document.createElement('button');
    btn.className = 'copy-btn';
    btn.textContent = '\U0001F4CB Copy';
    btn.addEventListener('click', function() {{
      const code = pre.querySelector('code') || pre;
      navigator.clipboard.writeText(code.textContent).then(function() {{
        btn.textContent = '\u2705 Copied!';
        btn.classList.add('copied');
        setTimeout(function() {{
          btn.textContent = '\U0001F4CB Copy';
          btn.classList.remove('copied');
        }}, 2000);
      }});
    }});
    wrapper.appendChild(btn);
  }});
}})();
</script>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_template)

    return output_path


def generate_json_report(
    findings: dict,
    ai_response: str = None,
    owned_user: str = None,
    dc_ip: str = None,
    risk: dict = None,
    output_path: str = "report.json",
):
    """Generate a structured JSON report for programmatic consumption."""
    domain = findings.get("domain_overview", {})
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report = {
        "meta": {
            "tool": "HoundBot",
            "version": "1.0.0",
            "generated": now,
            "domain": domain.get("domain_name", "N/A"),
            "owned_user": owned_user,
            "dc_ip": dc_ip,
            "built_by": "Ravindu",
        },
        "risk_score": risk or {"score": 0, "grade": "?", "label": "Unknown"},
        "domain_overview": domain,
        "findings": {
            "domain_admins": findings.get("domain_admins", {}),
            "kerberoastable": findings.get("kerberoastable", {}),
            "asreproastable": findings.get("asreproastable", {}),
            "dcsync_rights": findings.get("dcsync_rights", {}),
            "dangerous_acls": findings.get("dangerous_acls", {}),
            "unconstrained_delegation": findings.get("unconstrained_delegation", {}),
            "constrained_delegation": findings.get("constrained_delegation", {}),
            "gpo_abuse": findings.get("gpo_abuse", {}),
            "password_never_expires": findings.get("password_never_expires", {}),
            "stale_accounts": findings.get("stale_accounts", {}),
            "privesc_paths": findings.get("privesc_paths", {}),
        },
        "ai_analysis": ai_response,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=str)

    return output_path


def print_summary_stats(findings: dict):
    """Print a compact summary of all finding counts."""
    stats = []

    checks = [
        ("🔥 Kerberoastable", findings.get("kerberoastable", {}).get("count", 0), "red"),
        ("🔥 AS-REP Roast", findings.get("asreproastable", {}).get("count", 0), "red"),
        ("🔥 DCSync", findings.get("dcsync_rights", {}).get("count", 0), "red"),
        ("🔥 Dangerous ACLs", findings.get("dangerous_acls", {}).get("count", 0), "red"),
        ("🔥 Uncons. Deleg.", findings.get("unconstrained_delegation", {}).get("count", 0), "red"),
        ("⚠️ Cons. Deleg.", findings.get("constrained_delegation", {}).get("count", 0), "yellow"),
        ("⚠️ GPO Abuse", findings.get("gpo_abuse", {}).get("count", 0), "yellow"),
        ("⚠️ Pwd No Expire", findings.get("password_never_expires", {}).get("count", 0), "yellow"),
        ("ℹ️ Stale Accounts", findings.get("stale_accounts", {}).get("count", 0), "blue"),
        ("🛤️ Privesc Paths", findings.get("privesc_paths", {}).get("count", 0), "red"),
    ]

    table = Table(
        title="[bold]📈 Findings Summary[/bold]",
        box=box.ROUNDED,
        border_style="white",
        show_lines=False,
    )
    table.add_column("Check", style="white", width=25)
    table.add_column("Count", justify="center", width=8)
    table.add_column("Severity", justify="center", width=10)

    for name, count, color in checks:
        count_style = f"bold {color}" if count > 0 else "dim"
        severity = "CRITICAL" if color == "red" and count > 0 else (
            "MEDIUM" if color == "yellow" and count > 0 else (
                "INFO" if count > 0 else "—"
            )
        )
        sev_style = SEVERITY_COLORS.get(severity, "dim")
        table.add_row(
            name,
            f"[{count_style}]{count}[/]",
            f"[{sev_style}]{severity}[/]" if count > 0 else "[dim]—[/]",
        )

    console.print()
    console.print(table)
    console.print()
