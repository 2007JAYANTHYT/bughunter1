#!/usr/bin/env python3
"""
Bug Hunter Agent - Main CLI Entry Point
"""

import asyncio
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt, Confirm

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.config_manager import get_config, ConfigManager
from core.database import db_manager, ProgramCRUD, FindingCRUD, StatsCRUD
from core.scope_fetcher import ScopeFetcher, PolicyEngine, ScopeChecker


app = typer.Typer(
    name="bug-hunter",
    help="Universal Bug Hunting AI Agent",
    add_completion=False,
)
console = Console()
config = get_config()


# =============================================================================
# Helper Functions
# =============================================================================

async def init_db():
    """Initialize database connection"""
    await db_manager.initialize()


def print_banner():
    """Print the bug hunter banner"""
    banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                        🐛 BUG HUNTER AGENT v1.0                              ║
║              Universal Autonomous Bug Hunting System                        ║
║                  Recon → Hunt → Validate → Report                           ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
    console.print(banner, style="bold cyan")


# =============================================================================
# Program Commands
# =============================================================================

program_app = typer.Typer(help="Manage bug bounty programs")
app.add_typer(program_app, name="program")


@program_app.command("list")
def list_programs():
    """List all configured programs"""
    asyncio.run(_list_programs())


async def _list_programs():
    await init_db()
    async with db_manager.get_session() as session:
        programs = await ProgramCRUD.list(session)

    if not programs:
        console.print("[yellow]No programs configured. Run 'bug-hunter program add' to add one.[/yellow]")
        return

    table = Table(title="Configured Programs")
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="bold")
    table.add_column("Platform", style="green")
    table.add_column("Handle", style="blue")
    table.add_column("Enabled", style="magenta")
    table.add_column("Status", style="yellow")

    for p in programs:
        table.add_row(
            str(p.id),
            p.name,
            p.platform,
            p.handle or "-",
            "✓" if p.enabled else "✗",
            "Active" if p.enabled else "Disabled"
        )

    console.print(table)


@program_app.command("add")
def add_program(
    name: str = typer.Option(..., prompt=True, help="Program name"),
    platform: str = typer.Option("custom", prompt=True, help="Platform (hackerone, bugcrowd, intigriti, yeswehack, custom)"),
    handle: str = typer.Option("", prompt=True, help="Program handle on platform"),
):
    """Add a new bug bounty program"""
    asyncio.run(_add_program(name, platform, handle))


async def _add_program(name: str, platform: str, handle: str):
    await init_db()

    from core.database import Program

    program = Program(
        name=name,
        platform=platform.lower(),
        handle=handle,
        enabled=True,
    )

    async with db_manager.get_session() as session:
        existing = await ProgramCRUD.get_by_name(session, name)
        if existing:
            console.print(f"[red]Program '{name}' already exists![/red]")
            return

        created = await ProgramCRUD.create(session, program)
        console.print(f"[green]✓[/green] Program '{name}' created with ID {created.id}")

    # Create default scope file
    scope_dir = Path("config/scopes")
    scope_dir.mkdir(parents=True, exist_ok=True)
    scope_file = scope_dir / f"{name}.yaml"

    if not scope_file.exists():
        scope_content = f"""# Scope configuration for {name}
# Edit this file to define in-scope and out-of-scope targets

in_scope:
  - pattern: "*.example.com"
    description: "All subdomains of example.com"
  - pattern: "api.example.com"
    description: "API endpoint"

out_of_scope:
  - pattern: "blog.example.com"
    description: "Blog subdomain"
  - pattern: "192.168.1.0/24"
    description: "Internal network"
"""
        scope_file.write_text(scope_content)
        console.print(f"[green]✓[/green] Created scope template: {scope_file}")


@program_app.command("remove")
def remove_program(name: str):
    """Remove a program"""
    asyncio.run(_remove_program(name))


async def _remove_program(name: str):
    await init_db()
    async with db_manager.get_session() as session:
        program = await ProgramCRUD.get_by_name(session, name)
        if not program:
            console.print(f"[red]Program '{name}' not found![/red]")
            return

        if Confirm.ask(f"Delete program '{name}' and all associated data?"):
            await ProgramCRUD.delete(session, program.id)
            console.print(f"[green]✓[/green] Program '{name}' deleted")


# =============================================================================
# Hunt Commands
# =============================================================================

hunt_app = typer.Typer(help="Run bug hunting operations")
app.add_typer(hunt_app, name="hunt")


@hunt_app.command("recon")
def run_recon(
    program: str = typer.Option(..., help="Program name"),
    depth: str = typer.Option("normal", help="Recon depth: quick, normal, deep"),
):
    """Run reconnaissance on a program"""
    asyncio.run(_run_recon(program, depth))


async def _run_recon(program_name: str, depth: str):
    await init_db()

    console.print(f"[cyan]Starting reconnaissance on '{program_name}' (depth: {depth})[/cyan]")

    # Load program and scope
    async with db_manager.get_session() as session:
        prog = await ProgramCRUD.get_by_name(session, program_name)
        if not prog:
            console.print(f"[red]Program '{program_name}' not found![/red]")
            return

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Fetching scope...", total=None)

        async with ScopeFetcher(config) as fetcher:
            scope = await fetcher.fetch_program_scope(program_name)

        progress.update(task, description=f"Found {len(scope.in_scope)} in-scope rules")

        # Save scope to checklist
        progress.update(task, description="Creating scope checklist...")
        await _create_scope_checklist(program_name, scope)

        progress.update(task, description="Running subdomain enumeration...")
        # TODO: Implement actual recon

        progress.update(task, description="Running service discovery...")
        # TODO: Implement actual recon

    console.print("[green]✓[/green] Reconnaissance complete!")


@hunt_app.command("scan")
def run_scan(
    program: str = typer.Option(..., help="Program name"),
    scanner: str = typer.Option("all", help="Scanner to use: nuclei, dalfox, sqlmap, all"),
    targets: Optional[str] = typer.Option(None, help="Comma-separated target subdomains"),
):
    """Run vulnerability scanning"""
    asyncio.run(_run_scan(program, scanner, targets))


async def _run_scan(program_name: str, scanner: str, targets: Optional[str]):
    await init_db()

    console.print(f"[cyan]Starting vulnerability scan on '{program_name}'[/cyan]")

    async with db_manager.get_session() as session:
        prog = await ProgramCRUD.get_by_name(session, program_name)
        if not prog:
            console.print(f"[red]Program '{program_name}' not found![/red]")
            return

        # Get targets
        target_list = await TargetCRUD.get_by_program(session, prog.id)
        if not target_list:
            console.print("[yellow]No targets found. Run recon first.[/yellow]")
            return

    console.print(f"[yellow]Scanner '{scanner}' not yet implemented. This is a stub.[/yellow]")
    console.print("[green]✓[/green] Scan complete (stub)!")


@hunt_app.command("full")
def run_full_hunt(
    program: str = typer.Option(..., help="Program name"),
    config_name: str = typer.Option("default", help="Hunt configuration"),
):
    """Run full hunting pipeline: recon → scan → validate → report"""
    asyncio.run(_run_full_hunt(program, config_name))


async def _run_full_hunt(program_name: str, config_name: str):
    await init_db()

    console.print(Panel.fit(
        f"[bold]Full Hunt Pipeline[/bold]\n"
        f"Program: {program_name}\n"
        f"Config: {config_name}",
        title="🚀 Starting Full Hunt",
        border_style="cyan"
    ))

    # Step 1: Recon
    console.print("\n[bold cyan]Step 1/4: Reconnaissance[/bold cyan]")
    await _run_recon(program_name, "normal")

    # Step 2: Scanning
    console.print("\n[bold cyan]Step 2/4: Vulnerability Scanning[/bold cyan]")
    await _run_scan(program_name, "all", None)

    # Step 3: Validation
    console.print("\n[bold cyan]Step 3/4: Validation[/bold cyan]")
    console.print("[yellow]Validation not yet implemented.[/yellow]")

    # Step 4: Reporting
    console.print("\n[bold cyan]Step 4/4: Reporting[/bold cyan]")
    console.print("[yellow]Reporting not yet implemented.[/yellow]")

    console.print("\n[green]✓[/green] Full hunt pipeline complete (stubs)!")


# =============================================================================
# Findings Commands
# =============================================================================

findings_app = typer.Typer(help="Manage findings")
app.add_typer(findings_app, name="findings")


@findings_app.command("list")
def list_findings(
    program: str = typer.Option(..., help="Program name"),
    status: Optional[str] = typer.Option(None, help="Filter by status"),
    severity: Optional[str] = typer.Option(None, help="Filter by severity (P1-P4)"),
    vuln_type: Optional[str] = typer.Option(None, help="Filter by vulnerability type"),
    limit: int = typer.Option(50, help="Maximum results"),
):
    """List findings for a program"""
    asyncio.run(_list_findings(program, status, severity, vuln_type, limit))


async def _list_findings(program_name: str, status: Optional[str], severity: Optional[str],
                         vuln_type: Optional[str], limit: int):
    await init_db()

    async with db_manager.get_session() as session:
        prog = await ProgramCRUD.get_by_name(session, program_name)
        if not prog:
            console.print(f"[red]Program '{program_name}' not found![/red]")
            return

        findings = await FindingCRUD.get_by_program(
            session, prog.id, status, severity, vuln_type, limit
        )

    if not findings:
        console.print("[yellow]No findings match the criteria.[/yellow]")
        return

    table = Table(title=f"Findings for {program_name}")
    table.add_column("ID", style="cyan")
    table.add_column("Type", style="magenta")
    table.add_column("Severity", style="red")
    table.add_column("Title", style="bold")
    table.add_column("Status", style="green")
    table.add_column("Created", style="blue")

    for f in findings:
        severity_color = {"P1": "red", "P2": "orange3", "P3": "yellow", "P4": "green"}.get(f.severity, "white")
        table.add_row(
            str(f.id),
            f.vuln_type,
            f"[{severity_color}]{f.severity}[/{severity_color}]",
            f.title[:60] + "..." if len(f.title) > 60 else f.title,
            f.status,
            f.created_at.strftime("%Y-%m-%d %H:%M")
        )

    console.print(table)


@findings_app.command("view")
def view_finding(finding_id: int):
    """View detailed finding information"""
    asyncio.run(_view_finding(finding_id))


async def _view_finding(finding_id: int):
    await init_db()

    async with db_manager.get_session() as session:
        finding = await FindingCRUD.get(session, finding_id)
        if not finding:
            console.print(f"[red]Finding {finding_id} not found![/red]")
            return

    console.print(Panel.fit(
        f"[bold]Type:[/bold] {finding.vuln_type}\n"
        f"[bold]Severity:[/bold] {finding.severity}\n"
        f"[bold]Status:[/bold] {finding.status}\n"
        f"[bold]CVSS:[/bold] {finding.cvss_score or 'N/A'} ({finding.cvss_vector or 'N/A'})\n"
        f"[bold]Created:[/bold] {finding.created_at}\n"
        f"[bold]Validated:[/bold] {finding.validated_at or 'Not validated'}\n"
        f"[bold]Reported:[/bold] {finding.reported_at or 'Not reported'}",
        title=f"Finding #{finding.id}: {finding.title}",
        border_style="cyan"
    ))

    console.print("\n[bold]Description:[/bold]")
    console.print(finding.description or "No description")

    if finding.poc:
        console.print("\n[bold]Proof of Concept:[/bold]")
        console.print(finding.poc)

    if finding.evidence:
        console.print("\n[bold]Evidence:[/bold]")
        for key, value in finding.evidence.items():
            console.print(f"  {key}: {value}")


@findings_app.command("validate")
def validate_finding(finding_id: int):
    """Mark finding as validated"""
    asyncio.run(_validate_finding(finding_id))


async def _validate_finding(finding_id: int):
    await init_db()

    async with db_manager.get_session() as session:
        finding = await FindingCRUD.update_status(session, finding_id, "validated")
        if finding:
            console.print(f"[green]✓[/green] Finding #{finding_id} marked as validated")
        else:
            console.print(f"[red]Finding {finding_id} not found![/red]")


@findings_app.command("report")
def report_finding(finding_id: int, report_url: str = typer.Option(..., prompt=True)):
    """Mark finding as reported"""
    asyncio.run(_report_finding(finding_id, report_url))


async def _report_finding(finding_id: int, report_url: str):
    await init_db()

    async with db_manager.get_session() as session:
        finding = await FindingCRUD.update_status(session, finding_id, "reported")
        if finding:
            console.print(f"[green]✓[/green] Finding #{finding_id} marked as reported")
            console.print(f"  Report URL: {report_url}")
        else:
            console.print(f"[red]Finding {finding_id} not found![/red]")


@findings_app.command("duplicate")
def mark_duplicate(finding_id: int, duplicate_of: int):
    """Mark finding as duplicate of another"""
    asyncio.run(_mark_duplicate(finding_id, duplicate_of))


async def _mark_duplicate(finding_id: int, duplicate_of: int):
    await init_db()

    async with db_manager.get_session() as session:
        finding = await FindingCRUD.mark_duplicate(session, finding_id, duplicate_of)
        if finding:
            console.print(f"[green]✓[/green] Finding #{finding_id} marked as duplicate of #{duplicate_of}")
        else:
            console.print(f"[red]Finding {finding_id} not found![/red]")


# =============================================================================
# Scope Commands
# =============================================================================

scope_app = typer.Typer(help="Manage scope checklists")
app.add_typer(scope_app, name="scope")


@scope_app.command("checklist")
def show_checklist(program: str = typer.Option(..., help="Program name")):
    """Show scope checklist for a program"""
    asyncio.run(_show_checklist(program))


async def _show_checklist(program_name: str):
    await init_db()

    from core.database import ScopeChecklistCRUD, ScopeStatus

    async with db_manager.get_session() as session:
        prog = await ProgramCRUD.get_by_name(session, program_name)
        if not prog:
            console.print(f"[red]Program '{program_name}' not found![/red]")
            return

        items = await ScopeChecklistCRUD.get_by_program(session, prog.id)

    if not items:
        console.print("[yellow]No scope checklist found. Run recon first.[/yellow]")
        return

    table = Table(title=f"Scope Checklist: {program_name}")
    table.add_column("ID", style="cyan")
    table.add_column("Type", style="magenta")
    table.add_column("Pattern", style="bold")
    table.add_column("Status", style="green")
    table.add_column("Tested", style="blue")
    table.add_column("Notes")

    for item in items:
        type_color = "green" if item.item_type == "in_scope" else "red"
        status_color = {
            ScopeStatus.PENDING: "yellow",
            ScopeStatus.TESTING: "blue",
            ScopeStatus.TESTED: "green",
            ScopeStatus.SKIPPED: "dim",
        }.get(item.status, "white")

        table.add_row(
            str(item.id),
            f"[{type_color}]{item.item_type}[/{type_color}]",
            item.pattern,
            f"[{status_color}]{item.status}[/{status_color}]",
            item.tested_at.strftime("%Y-%m-%d %H:%M") if item.tested_at else "-",
            item.notes or "-"
        )

    console.print(table)


@scope_app.command("update")
def update_scope_item(
    item_id: int,
    status: str = typer.Option(..., help="Status: pending, testing, tested, skipped"),
    notes: str = typer.Option("", help="Optional notes"),
):
    """Update scope checklist item status"""
    asyncio.run(_update_scope_item(item_id, status, notes))


async def _update_scope_item(item_id: int, status: str, notes: str):
    await init_db()

    async with db_manager.get_session() as session:
        item = await ScopeChecklistCRUD.update_status(session, item_id, status, notes)
        if item:
            console.print(f"[green]✓[/green] Scope item #{item_id} updated to '{status}'")
        else:
            console.print(f"[red]Scope item {item_id} not found![/red]")


# =============================================================================
# Stats Commands
# =============================================================================

stats_app = typer.Typer(help="View statistics")
app.add_typer(stats_app, name="stats")


@stats_app.command("program")
def program_stats(program: str = typer.Option(..., help="Program name")):
    """Show statistics for a program"""
    asyncio.run(_program_stats(program))


async def _program_stats(program_name: str):
    await init_db()

    async with db_manager.get_session() as session:
        prog = await ProgramCRUD.get_by_name(session, program_name)
        if not prog:
            console.print(f"[red]Program '{program_name}' not found![/red]")
            return

        stats = await StatsCRUD.get_program_stats(session, prog.id)

    console.print(Panel.fit(
        f"[bold]Total Findings:[/bold] {stats['total_findings']}\n"
        f"[bold]Scope Coverage:[/bold] {stats['scope_coverage']['tested']}/{stats['scope_coverage']['total']} "
        f"({stats['scope_coverage']['percentage']:.1f}%)",
        title=f"Statistics: {program_name}",
        border_style="cyan"
    ))

    # By status
    status_table = Table(title="By Status")
    status_table.add_column("Status", style="cyan")
    status_table.add_column("Count", style="bold")
    for status, count in stats['by_status'].items():
        status_table.add_row(status, str(count))
    console.print(status_table)

    # By severity
    sev_table = Table(title="By Severity")
    sev_table.add_column("Severity", style="red")
    sev_table.add_column("Count", style="bold")
    for sev in ["P1", "P2", "P3", "P4"]:
        sev_table.add_row(sev, str(stats['by_severity'].get(sev, 0)))
    console.print(sev_table)

    # By type
    type_table = Table(title="By Vulnerability Type")
    type_table.add_column("Type", style="magenta")
    type_table.add_column("Count", style="bold")
    for vtype, count in sorted(stats['by_type'].items(), key=lambda x: -x[1]):
        type_table.add_row(vtype, str(count))
    console.print(type_table)


# =============================================================================
# Config Commands
# =============================================================================

config_app = typer.Typer(help="Configuration management")
app.add_typer(config_app, name="config")


@config_app.command("show")
def show_config():
    """Show current configuration"""
    hunting = config.load_hunting()
    validation = config.load_validation()

    console.print(Panel.fit(
        f"[bold]Threads:[/bold] {hunting.threads}\n"
        f"[bold]Timeout:[/bold] {hunting.timeout}s\n"
        f"[bold]Rate Limit:[/bold] {hunting.rate_limit_rps} req/s\n"
        f"[bold]Strict Scope:[/bold] {hunting.strict_scope}\n"
        f"[bold]Nuclei Enabled:[/bold] {hunting.scanners.nuclei.enabled}\n"
        f"[bold]AI Hunting:[/bold] {hunting.ai_hunting.enabled}\n"
        f"[bold]Browser Headless:[/bold] {validation.browser.headless}",
        title="Current Configuration",
        border_style="cyan"
    ))


@config_app.command("edit")
def edit_config():
    """Edit configuration files"""
    console.print("[yellow]Edit config files manually:[/yellow]")
    console.print("  config/hunting.yaml")
    console.print("  config/validation.yaml")
    console.print("  config/ai_models.yaml")
    console.print("  config/programs.yaml")


# =============================================================================
# UI Command
# =============================================================================

@app.command("ui")
def launch_ui(
    host: str = typer.Option("127.0.0.1", help="Host to bind"),
    port: int = typer.Option(8000, help="Port to bind"),
):
    """Launch the web UI"""
    console.print(f"[cyan]Starting web UI on http://{host}:{port}[/cyan]")
    console.print("[yellow]Web UI not yet implemented. Run backend separately:[/yellow]")
    console.print("  cd ui/backend && uvicorn main:app --reload")


# =============================================================================
# Setup Command
# =============================================================================

@app.command("setup")
def run_setup():
    """Run initial setup"""
    console.print("[cyan]Running setup...[/cyan]")
    console.print("[yellow]Execute the setup script in WSL2 Kali:[/yellow]")
    console.print("  bash scripts/setup.sh")


# =============================================================================
# Main
# =============================================================================

if __name__ == "__main__":
    print_banner()
    app()