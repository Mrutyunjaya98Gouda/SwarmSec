"""Terminal live dashboard for SwarmSec using Rich.

Visualizes ranked threat indicators, corroboration scores, and real-time
flags for correlated-evidence down-weighting.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

MANDATORY_ADVISORY_DISCLAIMER = (
    "ADVISORY ONLY: SwarmSec computes local corroboration scores and trust rankings. "
    "This output is NOT an automated block/allow decision. "
    "A human analyst must review context and make the operational mitigation call."
)


def fetch_node_feed(node_url: str, timeout: float = 3.0) -> Optional[Dict[str, Any]]:
    """Fetch current ranked feed from the node."""
    try:
        url = node_url.rstrip("/") + "/feed"
        resp = httpx.get(url, timeout=timeout)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None


def generate_dashboard_renderable(
    node_url: str, feed_data: Optional[Dict[str, Any]]
) -> Group:
    """Build the Rich renderable group for the dashboard."""
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")

    # Header Panel
    header_text = Text()
    header_text.append("SwarmSec ", style="bold cyan")
    header_text.append("— Peer-to-Peer CTI Exchange Local Monitor\n", style="bold white")
    header_text.append(f"Node: {node_url}  |  Time: {now_utc}  |  ", style="dim")

    if feed_data:
        total_ioc = feed_data.get("total_indicators", 0)
        total_msg = feed_data.get("total_messages", 0)
        header_text.append(f"Indicators: {total_ioc}  |  Messages: {total_msg}", style="green")
    else:
        header_text.append("Status: Offline / Connecting...", style="bold red")

    header_panel = Panel(header_text, border_style="cyan")

    # Ranked Indicators Table
    table = Table(
        title="Local Trust Ranking & Corroboration Feed",
        title_style="bold magenta",
        expand=True,
        header_style="bold bold",
    )
    table.add_column("Rank", justify="center", style="cyan", no_wrap=True, width=6)
    table.add_column("Indicator Pattern (IoC)", style="white", ratio=3)
    table.add_column("Trust Ranking", justify="center", style="bold", width=15)
    table.add_column("Status", style="yellow", ratio=2)
    table.add_column("Sources", justify="center", width=9)
    table.add_column("Down-Weighting Status", justify="center", width=22)

    indicators: List[Dict[str, Any]] = (
        feed_data.get("ranked_indicators", []) if feed_data else []
    )

    downweighted_items: List[Dict[str, Any]] = []

    if not indicators:
        table.add_row(
            "-",
            "[dim]No indicators observed yet. Awaiting gossip...[/dim]",
            "-",
            "-",
            "-",
            "-",
        )
    else:
        for idx, item in enumerate(indicators, 1):
            pattern = item.get("pattern", "unknown")
            score = item.get("local_corroboration_score", 0.0)
            status = item.get("status", "UNKNOWN")
            sources = str(item.get("independent_sources", 1))
            flags = item.get("flags", [])
            downweighted = item.get("downweighted", False)

            # Score styling
            if score >= 0.8:
                score_str = f"[bold green]{score:.2f}[/bold green]"
            elif score >= 0.4:
                score_str = f"[bold yellow]{score:.2f}[/bold yellow]"
            else:
                score_str = f"[bold red]{score:.2f}[/bold red]"

            # Down-weighting column
            if downweighted or "feedback_downweighted" in flags:
                dw_status = "[bold white on red] TRIGGERED [/bold white on red]"
                downweighted_items.append(item)
            elif "feed_overlap" in flags:
                dw_status = "[bold yellow]FEED OVERLAP[/bold yellow]"
            else:
                dw_status = "[green]CLEAN[/green]"

            table.add_row(
                f"#{idx}",
                pattern,
                score_str,
                status,
                sources,
                dw_status,
            )

    # Correlated-Evidence Analysis Panel (if any down-weighting occurred)
    if downweighted_items:
        alert_text = Text()
        alert_text.append(
            "⚠️  CORRELATED-EVIDENCE DOWN-WEIGHTING ACTIVE:\n",
            style="bold red",
        )
        for dw in downweighted_items:
            alert_text.append(
                f" • Pattern: {dw.get('pattern')} | Score: {dw.get('local_corroboration_score')} | "
                f"Reports: {dw.get('reports_count')} | Feedback: {dw.get('feedback_count')}\n",
                style="yellow",
            )
            alert_text.append(
                "   Notice: Mutual endorsement / cluster density penalty triggered by fixed-parameter formula.\n",
                style="dim",
            )
        alert_panel = Panel(
            alert_text,
            title="Credentialed Collusion Resistance Alert",
            border_style="red",
        )
    else:
        alert_panel = None

    # Advisory Footer
    advisory_panel = Panel(
        Text(MANDATORY_ADVISORY_DISCLAIMER, style="bold yellow"),
        title="Operational Advisory",
        border_style="yellow",
    )

    panels = [header_panel, table]
    if alert_panel:
        panels.append(alert_panel)
    panels.append(advisory_panel)

    return Group(*panels)


def render_dashboard_once(node_url: str, console: Optional[Console] = None) -> None:
    """Print the dashboard once to stdout."""
    c = console or Console()
    feed_data = fetch_node_feed(node_url)
    renderable = generate_dashboard_renderable(node_url, feed_data)
    c.print(renderable)


def run_live_dashboard(
    node_url: str,
    refresh_rate: float = 1.0,
    max_iterations: Optional[int] = None,
    console: Optional[Console] = None,
) -> None:
    """Run interactive live dashboard."""
    c = console or Console()
    iterations = 0

    with Live(console=c, refresh_per_second=int(1.0 / max(refresh_rate, 0.2))) as live:
        try:
            while True:
                feed_data = fetch_node_feed(node_url)
                renderable = generate_dashboard_renderable(node_url, feed_data)
                live.update(renderable)

                iterations += 1
                if max_iterations and iterations >= max_iterations:
                    break

                time.sleep(refresh_rate)
        except KeyboardInterrupt:
            pass
