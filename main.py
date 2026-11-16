#!/usr/bin/env python3
"""
Bug Hunter Agent - Main Entry Point
Universal Autonomous Bug Hunting System
"""

import asyncio
import sys
import os
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

import typer
from rich.console import Console
from rich.panel import Panel

from cli.main import app
from core.config_manager import get_config
from core.database import db_manager

console = Console()


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


def check_environment():
    """Check if running in proper environment"""
    # Check for WSL2
    in_wsl = False
    try:
        with open('/proc/version', 'r') as f:
            if 'microsoft' in f.read().lower() or 'wsl' in f.read().lower():
                in_wsl = True
    except Exception:
        pass

    if not in_wsl:
        console.print("[yellow]Warning: Not running in WSL2. Some features may not work correctly.[/yellow]")
        console.print("[yellow]Recommended: Run in WSL2 Kali Linux[/yellow]")

    # Check for required tools
    required_tools = ['nuclei', 'subfinder', 'httpx', 'katana', 'dalfox', 'sqlmap', 'ffuf']
    missing = []
    for tool in required_tools:
        if not shutil.which(tool):
            missing.append(tool)

    if missing:
        console.print(f"[yellow]Missing tools: {', '.join(missing)}[/yellow]")
        console.print("[yellow]Run 'bash scripts/setup.sh' to install all tools[/yellow]")

    # Check for Ollama
    if not shutil.which('ollama'):
        console.print("[yellow]Ollama not found. AI features will not work.[/yellow]")
        console.print("[yellow]Install with: curl -fsSL https://ollama.com/install.sh | sh[/yellow]")


def init_database():
    """Initialize database"""
    asyncio.run(db_manager.initialize())
    asyncio.run(db_manager.create_tables())


# Import shutil for tool checking
import shutil


# Main CLI entry point
if __name__ == "__main__":
    print_banner()

    # Check for special commands
    if len(sys.argv) > 1:
        if sys.argv[1] == "init":
            console.print("[cyan]Initializing Bug Hunter Agent...[/cyan]")
            check_environment()
            init_database()
            console.print("[green]✓[/green] Initialization complete!")
            console.print("\nNext steps:")
            console.print("  1. Copy config/programs.yaml.example to config/programs.yaml")
            console.print("  2. Edit config/programs.yaml with your bug bounty programs")
            console.print("  3. Copy .env.example to .env and add your API tokens")
            console.print("  4. Start Ollama: ollama serve")
            console.print("  5. Run: python main.py --help")
            sys.exit(0)

        elif sys.argv[1] == "setup":
            console.print("[cyan]Running setup script...[/cyan]")
            os.system("bash scripts/setup.sh")
            sys.exit(0)

        elif sys.argv[1] == "migrate":
            from scripts.migrate import run_migrations
            asyncio.run(run_migrations())
            sys.exit(0)

        elif sys.argv[1] == "backup":
            os.system("bash scripts/backup.sh")
            sys.exit(0)

    # Run the main CLI
    try:
        app()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        sys.exit(1)