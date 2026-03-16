#!/usr/bin/env python3
"""SENTINEL CLI - Rich command-line interface for the AI SOC Analyst."""

import argparse
import json
import signal
import sys
import time
from datetime import datetime

try:
    import requests
except ImportError:
    requests = None

# Default API base URL
DEFAULT_API = "http://localhost:8080/api"


# ── Color helpers (no dependencies) ─────────────────────────────────

class Style:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GREY = "\033[90m"
    BG_RED = "\033[41m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"

    SEVERITY = {
        "critical": f"\033[41m\033[97m",
        "high": f"\033[91m",
        "medium": f"\033[93m",
        "low": f"\033[94m",
        "info": f"\033[90m",
    }


def styled(text, *styles):
    return "".join(styles) + str(text) + Style.RESET


def severity_color(sev):
    return Style.SEVERITY.get((sev or "info").lower(), Style.GREY)


# ── API client ───────────────────────────────────────────────────────

class SentinelAPI:
    def __init__(self, base_url=DEFAULT_API):
        self.base_url = base_url.rstrip("/")

    def get(self, endpoint, params=None):
        if requests is None:
            print(styled("Error: 'requests' package required. Install with: pip install requests", Style.RED))
            sys.exit(1)
        try:
            resp = requests.get(f"{self.base_url}{endpoint}", params=params, timeout=10)
            resp.raise_for_status()
            return resp.json()
        except requests.ConnectionError:
            return None
        except Exception as e:
            print(styled(f"API error: {e}", Style.RED))
            return None


# ── Banner ───────────────────────────────────────────────────────────

BANNER = f"""
{Style.CYAN}{Style.BOLD}
  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
{Style.RESET}{Style.DIM}  AI-Powered Security Operations Center Analyst{Style.RESET}
"""


# ── Commands ─────────────────────────────────────────────────────────

def cmd_status(api, args):
    """Show engine status and system health."""
    stats = api.get("/stats")
    if stats is None:
        print(styled("  SENTINEL engine is not reachable.", Style.RED))
        print(styled(f"  Ensure the server is running at {api.base_url}", Style.DIM))
        return

    engine = stats.get("engine", {})
    print()
    print(styled("  ENGINE STATUS", Style.BOLD, Style.CYAN))
    print(styled("  " + "─" * 45, Style.DIM))

    # Uptime
    start_time = engine.get("start_time")
    if start_time:
        try:
            started = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
            uptime = datetime.now(started.tzinfo) - started if started.tzinfo else datetime.now() - started
            hours, remainder = divmod(int(uptime.total_seconds()), 3600)
            mins, secs = divmod(remainder, 60)
            print(f"  {styled('Uptime:', Style.DIM)}       {hours}h {mins}m {secs}s")
        except (ValueError, TypeError):
            pass

    print(f"  {styled('Events:', Style.DIM)}       {styled(stats.get('events_total', engine.get('events_processed', 0)), Style.CYAN)}")
    print(f"  {styled('Alerts:', Style.DIM)}       {styled(stats.get('alerts_total', 0), Style.YELLOW)}")
    print(f"  {styled('Incidents:', Style.DIM)}    {styled(stats.get('incidents_total', 0), Style.RED)}")

    # Severity breakdown
    sev = stats.get("severity_counts", {})
    if sev:
        print()
        print(styled("  SEVERITY BREAKDOWN", Style.BOLD, Style.CYAN))
        print(styled("  " + "─" * 45, Style.DIM))
        for level in ["critical", "high", "medium", "low", "info"]:
            count = sev.get(level, 0)
            bar = "█" * min(count, 40)
            print(f"  {severity_color(level)}{level.upper():>10}{Style.RESET}  {bar} {count}")

    # Rules
    rules_data = api.get("/rules")
    if rules_data:
        rules = rules_data.get("rules", rules_data) if isinstance(rules_data, dict) else rules_data
        if isinstance(rules, list):
            print(f"\n  {styled('Rules:', Style.DIM)}        {styled(len(rules), Style.MAGENTA)} loaded")

    # Threat intel
    threats = api.get("/threats")
    if threats:
        blocked = threats.get("blocked_ips", [])
        print(f"  {styled('Blocked IPs:', Style.DIM)}  {styled(len(blocked), Style.RED)}")

    print()


def cmd_monitor(api, args):
    """Live event monitoring stream."""
    print(BANNER)
    print(styled("  Live Monitor — Ctrl+C to exit", Style.DIM))
    print(styled("  " + "═" * 50, Style.DIM))
    print()

    seen_ids = set()
    running = True

    def handle_sigint(sig, frame):
        nonlocal running
        running = False
        print(styled("\n  Monitor stopped.", Style.YELLOW))

    signal.signal(signal.SIGINT, handle_sigint)

    while running:
        data = api.get("/events", {"limit": 30})
        if data is None:
            print(styled("  Connection lost. Retrying in 5s...", Style.RED))
            time.sleep(5)
            continue

        events = data.get("events", data) if isinstance(data, dict) else data
        if not isinstance(events, list):
            events = []

        new_events = []
        for ev in events:
            eid = ev.get("id") or id(ev)
            if eid not in seen_ids:
                seen_ids.add(eid)
                new_events.append(ev)

        for ev in reversed(new_events):
            ts = ev.get("timestamp", "")
            if ts:
                try:
                    ts = ts.split("T")[1][:8] if "T" in ts else ts[:8]
                except (IndexError, TypeError):
                    ts = ts[:8]

            sev = (ev.get("severity") or "info").lower()
            sev_display = f"{severity_color(sev)} {sev.upper():>8} {Style.RESET}"

            etype = ev.get("event_type", "unknown")
            src_ip = ev.get("src_ip", "")
            user = ev.get("username", "")

            detail = etype
            if src_ip:
                detail += f" {styled(src_ip, Style.CYAN)}"
            if user:
                detail += f" ({styled(user, Style.MAGENTA)})"

            print(f"  {styled(ts, Style.DIM)} {sev_display} {detail}")

        time.sleep(args.interval if hasattr(args, "interval") else 3)


def cmd_alerts(api, args):
    """Show recent alerts."""
    data = api.get("/alerts", {"limit": args.limit, "severity": args.severity})
    if data is None:
        print(styled("  Cannot connect to SENTINEL.", Style.RED))
        return

    alerts = data.get("alerts", data) if isinstance(data, dict) else data
    if not isinstance(alerts, list):
        alerts = []

    print()
    print(styled(f"  ALERTS ({len(alerts)})", Style.BOLD, Style.YELLOW))
    print(styled("  " + "─" * 60, Style.DIM))

    if not alerts:
        print(styled("  No alerts found.", Style.DIM))
        print()
        return

    for alert in alerts:
        sev = (alert.get("severity") or "info").lower()
        ts = alert.get("timestamp", "")
        rule = alert.get("rule_name") or alert.get("description") or "Unknown"
        source = alert.get("source", "")

        print(f"\n  {severity_color(sev)}{Style.BOLD}[{sev.upper()}]{Style.RESET} {styled(rule, Style.WHITE, Style.BOLD)}")
        print(f"    {styled('Time:', Style.DIM)}    {ts}")
        if source:
            print(f"    {styled('Source:', Style.DIM)}  {source}")
        if alert.get("description"):
            print(f"    {styled('Detail:', Style.DIM)} {alert['description']}")
        if alert.get("ai_analysis"):
            analysis = alert["ai_analysis"]
            if isinstance(analysis, str):
                print(f"    {styled('AI:', Style.DIM)}     {analysis[:120]}")
            elif isinstance(analysis, dict):
                print(f"    {styled('AI:', Style.DIM)}     {analysis.get('analysis', '')[:120]}")

    print()


def cmd_scan(api, args):
    """Trigger a scan or show current threat intel status."""
    print()
    print(styled("  THREAT INTELLIGENCE SCAN", Style.BOLD, Style.CYAN))
    print(styled("  " + "─" * 45, Style.DIM))

    threats = api.get("/threats")
    if threats is None:
        print(styled("  Cannot connect to SENTINEL.", Style.RED))
        return

    feed_stats = threats.get("feed_stats", {})
    blocked = threats.get("blocked_ips", [])
    response_log = threats.get("response_log", [])

    print(f"  {styled('Feed Status:', Style.DIM)}")
    if feed_stats:
        for feed, info in feed_stats.items():
            status = info if isinstance(info, str) else info.get("status", "unknown")
            color = Style.GREEN if status in ("active", "ok") else Style.YELLOW
            print(f"    {styled('●', color)} {feed}: {status}")
    else:
        print(styled("    No feed data available", Style.DIM))

    print(f"\n  {styled('Blocked IPs:', Style.DIM)} {styled(len(blocked), Style.RED)}")
    for ip in blocked[:10]:
        print(f"    {styled('⊘', Style.RED)} {styled(ip, Style.CYAN)}")
    if len(blocked) > 10:
        print(styled(f"    ... and {len(blocked) - 10} more", Style.DIM))

    print(f"\n  {styled('Response Actions:', Style.DIM)} {len(response_log)} total")
    for action in response_log[-5:]:
        action_type = action.get("type", "unknown")
        target = action.get("target", "")
        status = action.get("status", "")
        status_color = Style.GREEN if status == "success" else Style.YELLOW if status == "pending" else Style.RED
        print(f"    {styled(action_type, Style.WHITE):30s} {styled(target, Style.CYAN):20s} [{styled(status, status_color)}]")

    print()


# ── Main ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="SENTINEL - AI SOC Analyst CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"{Style.CYAN}Commands:{Style.RESET}\n"
               f"  monitor    Live event monitoring stream\n"
               f"  status     Show engine status and health\n"
               f"  alerts     View recent security alerts\n"
               f"  scan       Threat intelligence overview\n",
    )
    parser.add_argument("--api", default=DEFAULT_API, help="API base URL")

    subparsers = parser.add_subparsers(dest="command")

    # monitor
    mon_parser = subparsers.add_parser("monitor", help="Live event monitoring")
    mon_parser.add_argument("-i", "--interval", type=int, default=3, help="Refresh interval in seconds")

    # status
    subparsers.add_parser("status", help="Engine status and health")

    # alerts
    alert_parser = subparsers.add_parser("alerts", help="View recent alerts")
    alert_parser.add_argument("-n", "--limit", type=int, default=20, help="Number of alerts")
    alert_parser.add_argument("-s", "--severity", default=None, help="Filter by severity")

    # scan
    subparsers.add_parser("scan", help="Threat intelligence scan")

    args = parser.parse_args()
    api = SentinelAPI(args.api)

    commands = {
        "monitor": cmd_monitor,
        "status": cmd_status,
        "alerts": cmd_alerts,
        "scan": cmd_scan,
    }

    if args.command in commands:
        commands[args.command](api, args)
    else:
        print(BANNER)
        parser.print_help()


if __name__ == "__main__":
    main()
