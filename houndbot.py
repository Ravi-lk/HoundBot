#!/usr/bin/env python3
"""
houndbot.py — AI-Powered BloodHound Analyzer

CLI entry point for HoundBot. Parses BloodHound SharpHound dumps,
runs static analysis for AD vulnerabilities, and uses Ollama AI
to generate exploitation commands.

Usage:
    python houndbot.py --zip bloodhound.zip --owned-user "Ravindu.Lakmina" --dc-ip 172.16.101.200
    python houndbot.py --zip bloodhound.zip --owned-user "Ravindu.Lakmina,K.Dennings" --dc-ip 172.16.101.200
    python houndbot.py --zip bloodhound.zip --no-ai
    python houndbot.py --zip bloodhound.zip --owned-user "Ravindu.Lakmina" --dc-ip 172.16.101.200 --output report.md
"""

import argparse
import sys
import os
import time

# Load .env file before anything else
from dotenv import load_dotenv
load_dotenv()

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

from parser import parse_zip, get_domain_name
from analyzer import run_all_checks, format_findings_for_ai
from ai_engine import OllamaEngine
from reporter import (
    print_banner,
    print_all_findings,
    print_summary_stats,
    generate_markdown_report,
    generate_html_report,
    generate_json_report,
    calculate_risk_score,
    console,
)

VERSION = "1.0.0"


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="🐕 HoundBot — AI-Powered BloodHound Analyzer",
        formatter_class=argparse.RichHelpFormatter
        if hasattr(argparse, "RichHelpFormatter")
        else argparse.HelpFormatter,
    )

    parser.add_argument(
        "--zip", "-z",
        required=True,
        help="Path to BloodHound SharpHound ZIP file",
    )
    parser.add_argument(
        "--owned-user", "-u",
        default=None,
        help="Owned username(s), comma-separated (e.g., 'Ravindu.Lakmina' or 'Ravindu.Lakmina,K.Dennings')",
    )
    parser.add_argument(
        "--dc-ip", "-d",
        default=None,
        help="Domain Controller IP address",
    )
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Skip AI analysis, run static checks only",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output report base path without extension (default: report_<domain>)",
    )
    parser.add_argument(
        "--format", "-f",
        default="all",
        choices=["md", "html", "json", "all"],
        help="Report format: md, html, json, or all (default: all = md + html)",
    )
    parser.add_argument(
        "--api-key",
        default=None,
        help="Ollama API key (overrides OLLAMA_API_KEY env var)",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Ollama model name (default: qwen3.5:397b)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"HoundBot v{VERSION}",
    )

    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_args()

    # Print banner
    print_banner()

    # Validate ZIP file
    if not os.path.isfile(args.zip):
        console.print(f"[bold red]✗[/] ZIP file not found: {args.zip}")
        sys.exit(1)

    # ── Phase 1: Parse BloodHound Data ─────────────────────────────────
    console.print(Panel(
        "[bold cyan]Phase 1:[/] Parsing BloodHound data...",
        border_style="cyan",
        box=box.HEAVY,
    ))

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Extracting and parsing SharpHound JSON...", total=None)
            data = parse_zip(args.zip)
            progress.update(task, description="[green]✓ Parsing complete!")

    except FileNotFoundError as e:
        console.print(f"[bold red]✗[/] {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]✗[/] Error parsing ZIP: {e}")
        if args.verbose:
            console.print_exception()
        sys.exit(1)

    # Print parse summary
    domain_name = get_domain_name(data)
    meta = data["meta"]

    console.print(f"\n  [green]✓[/] Parsed [bold]{meta['total_objects']}[/] objects from "
                  f"[bold]{len(meta['files_parsed'])}[/] files")
    console.print(f"  [green]✓[/] Domain: [bold cyan]{domain_name}[/]")

    if args.verbose:
        for f in meta["files_parsed"]:
            status_icon = "✓" if f["status"] == "ok" else "✗"
            console.print(f"    {status_icon} {f['file']} ({f.get('type', '?')}: {f.get('count', 0)})")

    # ── Phase 2: Static Analysis ──────────────────────────────────────
    console.print()
    console.print(Panel(
        "[bold cyan]Phase 2:[/] Running static analysis...",
        border_style="cyan",
        box=box.HEAVY,
    ))

    # Resolve owned users (comma-separated list)
    owned_users_raw = args.owned_user
    if not owned_users_raw:
        console.print()
        owned_users_raw = Prompt.ask(
            "[bold yellow]Enter owned username(s)[/] comma-separated, or press Enter to skip",
            default="",
        )
        if not owned_users_raw:
            owned_users_raw = None
            console.print("  [dim]Skipping privilege escalation path analysis[/dim]")

    # Parse comma-separated list into a clean list
    owned_users = None
    if owned_users_raw:
        owned_users = [u.strip() for u in owned_users_raw.split(",") if u.strip()]
        if not owned_users:
            owned_users = None

    dc_ip = args.dc_ip
    if not dc_ip and not args.no_ai:
        dc_ip = Prompt.ask(
            "[bold yellow]Enter DC IP address[/] (or press Enter to skip)",
            default="",
        )
        if not dc_ip:
            dc_ip = "$TARGET_IP"

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Analyzing AD objects for vulnerabilities...", total=None)
        findings = run_all_checks(data, owned_users)
        progress.update(task, description="[green]✓ Analysis complete!")

    # Print all findings
    console.print()
    print_all_findings(findings, data)
    print_summary_stats(findings)

    # ── Phase 3: AI Analysis ──────────────────────────────────────────
    ai_response = None

    if not args.no_ai:
        console.print(Panel(
            "[bold cyan]Phase 3:[/] AI-powered exploitation analysis...",
            border_style="cyan",
            box=box.HEAVY,
        ))

        # Initialize AI engine
        engine = OllamaEngine(
            api_key=args.api_key,
            model=args.model,
        )

        if not engine.is_configured():
            console.print(
                "\n[bold yellow]⚠ AI engine not configured.[/]\n"
                "  Set OLLAMA_API_KEY in .env file or pass --api-key flag.\n"
                "  Running static analysis only.\n"
            )
        else:
            # Test connection
            console.print("  Testing API connection...", end=" ")
            if engine.test_connection():
                console.print("[green]✓ Connected![/]")
            else:
                console.print("[yellow]⚠ Connection test failed, attempting analysis anyway...[/]")

            # Format findings for AI
            findings_text = format_findings_for_ai(findings, data)

            # Send to AI
            console.print(f"  Sending findings to [bold]{engine.model}[/]...")
            console.print(f"  [dim]This may take 1-3 minutes depending on findings complexity[/dim]")
            console.print()

            owned_users_str = ", ".join(owned_users) if owned_users else "N/A"

            ai_response = engine.analyze(
                findings_summary=findings_text,
                domain_info=domain_name,
                owned_user=owned_users_str,
                dc_ip=dc_ip or "$TARGET_IP",
                stream=True,
            )

            console.print()

            if ai_response and not ai_response.startswith("⚠️"):
                console.print("[green]✓ AI analysis complete![/]")
            else:
                console.print(f"[yellow]{ai_response}[/]")
    else:
        console.print()
        console.print("[dim]AI analysis skipped (--no-ai flag)[/dim]")

    # ── Phase 4: Generate Report ──────────────────────────────────────
    base_name = args.output or f"report_{domain_name.replace('.', '_').lower()}"
    # Strip extension if user provided one
    if base_name.endswith(('.md', '.html', '.json')):
        base_name = os.path.splitext(base_name)[0]

    report_format = args.format

    console.print()
    console.print(Panel(
        "[bold cyan]Phase 4:[/] Generating report...",
        border_style="cyan",
        box=box.HEAVY,
    ))

    owned_users_str = ", ".join(owned_users) if owned_users else None

    # Calculate risk score
    risk = calculate_risk_score(findings)

    # Display risk score in terminal
    risk_color_map = {
        "F": "bold red",
        "D": "bold red",
        "C": "bold yellow",
        "B": "bold green",
        "A": "bold green",
    }
    risk_style = risk_color_map.get(risk["grade"], "white")
    console.print(f"\n  [{risk_style}]⛨ Risk Score: {risk['score']}/100 (Grade {risk['grade']} — {risk['label']})[/]")

    generated_reports = []

    # Generate Markdown report
    if report_format in ("md", "all"):
        md_path = f"{base_name}.md"
        generate_markdown_report(
            findings=findings,
            ai_response=ai_response,
            owned_user=owned_users_str,
            dc_ip=dc_ip,
            output_path=md_path,
        )
        generated_reports.append(("📄", "Markdown", md_path))
        console.print(f"  [green]✓[/] Markdown report: [bold]{md_path}[/]")

        # Generate HTML report from the markdown content
        if report_format == "all":
            md_content = open(md_path, "r", encoding="utf-8").read()
            html_path = f"{base_name}.html"
            generate_html_report(
                markdown_content=md_content,
                output_path=html_path,
                risk=risk,
            )
            generated_reports.append(("🌐", "HTML", html_path))
            console.print(f"  [green]✓[/] HTML report:     [bold link=file://{os.path.abspath(html_path)}]{html_path}[/]")

    # Generate HTML-only report
    if report_format == "html":
        # Need to generate markdown content first (in memory)
        md_path_tmp = f"{base_name}.md"
        generate_markdown_report(
            findings=findings,
            ai_response=ai_response,
            owned_user=owned_users_str,
            dc_ip=dc_ip,
            output_path=md_path_tmp,
        )
        md_content = open(md_path_tmp, "r", encoding="utf-8").read()
        os.remove(md_path_tmp)  # Clean up temp markdown

        html_path = f"{base_name}.html"
        generate_html_report(
            markdown_content=md_content,
            output_path=html_path,
            risk=risk,
        )
        generated_reports.append(("🌐", "HTML", html_path))
        console.print(f"  [green]✓[/] HTML report: [bold link=file://{os.path.abspath(html_path)}]{html_path}[/]")

    # Generate JSON report
    if report_format in ("json", "all"):
        json_path = f"{base_name}.json"
        generate_json_report(
            findings=findings,
            ai_response=ai_response,
            owned_user=owned_users_str,
            dc_ip=dc_ip,
            risk=risk,
            output_path=json_path,
        )
        generated_reports.append(("📊", "JSON", json_path))
        console.print(f"  [green]✓[/] JSON report:     [bold]{json_path}[/]")

    # Final summary
    report_lines = "\n".join(
        f"  {icon} {fmt}: [bold]{path}[/]" for icon, fmt, path in generated_reports
    )

    console.print()
    console.print(Panel(
        f"[bold green]✓ Analysis complete![/]\n\n"
        f"{report_lines}\n"
        f"  ⛨ Risk Score: [bold]{risk['score']}/100[/] (Grade [bold]{risk['grade']}[/] — {risk['label']})\n"
        f"  🏰 Domain: [bold]{domain_name}[/]\n"
        f"  👤 Owned Users: [bold]{', '.join(owned_users) if owned_users else 'N/A'}[/]\n"
        f"  🤖 AI Analysis: [bold]{'Yes' if ai_response and not ai_response.startswith('⚠️') else 'No'}[/]",
        title="[bold]🐕 HoundBot — Built by Ravindu[/]",
        border_style="green",
        box=box.DOUBLE,
    ))


if __name__ == "__main__":
    main()
