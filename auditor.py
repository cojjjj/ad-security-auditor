"""Offline Active Directory security posture auditor."""

from __future__ import annotations

import argparse
import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from collectors.computers import collect_computer_findings
from collectors.groups import collect_group_findings
from collectors.users import collect_user_findings


DEFAULT_REPORT_PATH = Path("reports/report.html")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit an offline Active Directory JSON export and generate a security report."
    )
    parser.add_argument("input", type=Path, help="Path to the AD JSON export.")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=DEFAULT_REPORT_PATH,
        help="HTML report path. Defaults to reports/report.html.",
    )
    parser.add_argument(
        "--inactive-days",
        type=int,
        default=90,
        help="Number of days without logon before a user or computer is stale.",
    )
    return parser.parse_args()


def load_export(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")

    with path.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, dict):
        raise ValueError("The AD export must be a JSON object.")

    return data


def calculate_security_score(
    user_findings: dict[str, Any],
    group_findings: dict[str, Any],
    computer_findings: dict[str, Any],
    password_policy: dict[str, Any],
) -> tuple[int, list[str]]:
    score = 100
    notes: list[str] = []

    total_users = max(user_findings["total_users"], 1)
    password_never_expires = user_findings["password_never_expires_count"]
    inactive_users = user_findings["inactive_users_count"]
    domain_admins = group_findings["domain_admin_count"]
    stale_computers = computer_findings["stale_computers_count"]

    if password_never_expires:
        penalty = min(10, password_never_expires * 2)
        score -= penalty
        notes.append(f"-{penalty}: {password_never_expires} users have passwords that never expire.")

    inactive_ratio = inactive_users / total_users
    if inactive_ratio >= 0.25:
        score -= 6
        notes.append("-6: Inactive users are 25% or more of the user population.")
    elif inactive_ratio >= 0.10:
        score -= 3
        notes.append("-3: Inactive users are 10% or more of the user population.")

    if domain_admins > 5:
        score -= 8
        notes.append("-8: Domain Admin membership is larger than recommended.")
    elif domain_admins > 3:
        score -= 4
        notes.append("-4: Domain Admin membership should be reviewed.")

    if stale_computers:
        penalty = min(6, stale_computers)
        score -= penalty
        notes.append(f"-{penalty}: {stale_computers} stale computer accounts were found.")

    min_length = int(password_policy.get("minimumPasswordLength", 0) or 0)
    max_age_days = int(password_policy.get("maximumPasswordAgeDays", 0) or 0)
    lockout_threshold = int(password_policy.get("lockoutThreshold", 0) or 0)
    complexity_enabled = bool(password_policy.get("complexityEnabled", False))

    if min_length < 12:
        score -= 4
        notes.append("-4: Minimum password length is below 12 characters.")

    if not complexity_enabled:
        score -= 6
        notes.append("-6: Password complexity is disabled.")

    if max_age_days == 0 or max_age_days > 365:
        score -= 4
        notes.append("-4: Maximum password age is missing or longer than one year.")

    if lockout_threshold == 0 or lockout_threshold > 10:
        score -= 3
        notes.append("-3: Account lockout threshold is missing or too permissive.")

    return max(0, min(100, score)), notes


def risk_level(score: int) -> str:
    if score >= 85:
        return "Low"
    if score >= 70:
        return "Moderate"
    if score >= 50:
        return "High"
    return "Critical"


def render_table(title: str, rows: list[dict[str, Any]], columns: list[str]) -> str:
    if not rows:
        return f"<section><h2>{html.escape(title)}</h2><p>No findings.</p></section>"

    headers = "".join(f"<th>{html.escape(column)}</th>" for column in columns)
    body_rows = []
    for row in rows:
        cells = "".join(
            f"<td>{html.escape(str(row.get(column, '')))}</td>" for column in columns
        )
        body_rows.append(f"<tr>{cells}</tr>")

    return (
        f"<section><h2>{html.escape(title)}</h2>"
        f"<table><thead><tr>{headers}</tr></thead><tbody>{''.join(body_rows)}</tbody></table>"
        "</section>"
    )


def generate_html_report(
    output_path: Path,
    export_name: str,
    audit_date: datetime,
    score: int,
    score_notes: list[str],
    user_findings: dict[str, Any],
    group_findings: dict[str, Any],
    computer_findings: dict[str, Any],
    password_policy: dict[str, Any],
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    summary_cards = {
        "Total Users": user_findings["total_users"],
        "Disabled Users": user_findings["disabled_users_count"],
        "Inactive Users": user_findings["inactive_users_count"],
        "Password Never Expires": user_findings["password_never_expires_count"],
        "Domain Admins": group_findings["domain_admin_count"],
        "Service Accounts": user_findings["service_accounts_count"],
        "Stale Computers": computer_findings["stale_computers_count"],
        "Security Score": f"{score}/100",
    }

    cards_html = "".join(
        f"<article><span>{html.escape(label)}</span><strong>{html.escape(str(value))}</strong></article>"
        for label, value in summary_cards.items()
    )

    score_notes_html = "".join(f"<li>{html.escape(note)}</li>" for note in score_notes)
    if not score_notes_html:
        score_notes_html = "<li>No score deductions were applied.</li>"

    policy_rows = [
        {"Setting": "Minimum password length", "Value": password_policy.get("minimumPasswordLength", "Unknown")},
        {"Setting": "Password complexity enabled", "Value": password_policy.get("complexityEnabled", "Unknown")},
        {"Setting": "Maximum password age days", "Value": password_policy.get("maximumPasswordAgeDays", "Unknown")},
        {"Setting": "Lockout threshold", "Value": password_policy.get("lockoutThreshold", "Unknown")},
        {"Setting": "Password history count", "Value": password_policy.get("passwordHistoryCount", "Unknown")},
    ]

    document = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AD Security Audit Report</title>
  <style>
    :root {{
      color-scheme: light;
      --background: #f6f8fb;
      --text: #182233;
      --muted: #5d6a7d;
      --line: #d9e0ea;
      --panel: #ffffff;
      --accent: #0f766e;
      --warning: #b45309;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--background);
      color: var(--text);
      font: 15px/1.5 Arial, Helvetica, sans-serif;
    }}
    header {{
      background: #182233;
      color: #fff;
      padding: 32px max(24px, calc((100vw - 1100px) / 2));
    }}
    header p {{ color: #cbd5e1; margin: 6px 0 0; }}
    main {{
      max-width: 1100px;
      margin: 0 auto;
      padding: 28px 24px 44px;
    }}
    h1, h2 {{ margin: 0; line-height: 1.2; }}
    h2 {{ margin-bottom: 14px; font-size: 20px; }}
    section {{ margin-top: 28px; }}
    .cards {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
      gap: 14px;
    }}
    article {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 16px;
    }}
    article span {{
      display: block;
      color: var(--muted);
      font-size: 13px;
    }}
    article strong {{
      display: block;
      margin-top: 8px;
      font-size: 28px;
    }}
    .score {{
      border-left: 5px solid var(--accent);
      background: var(--panel);
      border-radius: 8px;
      padding: 18px 20px;
    }}
    .score strong {{ color: var(--accent); }}
    .score ul {{ margin: 12px 0 0; padding-left: 20px; color: var(--muted); }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      overflow: hidden;
    }}
    th, td {{
      border-bottom: 1px solid var(--line);
      padding: 10px 12px;
      text-align: left;
      vertical-align: top;
    }}
    th {{ background: #edf2f7; font-size: 13px; }}
    tr:last-child td {{ border-bottom: 0; }}
    .muted {{ color: var(--muted); }}
  </style>
</head>
<body>
  <header>
    <h1>AD Security Audit Report</h1>
    <p>Source: {html.escape(export_name)} | Generated: {html.escape(audit_date.strftime("%Y-%m-%d %H:%M UTC"))}</p>
  </header>
  <main>
    <section class="cards">{cards_html}</section>
    <section class="score">
      <h2>Security Score: <strong>{score}/100</strong> <span class="muted">({html.escape(risk_level(score))} risk)</span></h2>
      <ul>{score_notes_html}</ul>
    </section>
    {render_table("Password Policy", policy_rows, ["Setting", "Value"])}
    {render_table("Domain Admin Members", group_findings["domain_admins"], ["name", "sAMAccountName", "enabled"])}
    {render_table("Password Never Expires", user_findings["password_never_expires"], ["name", "sAMAccountName", "lastLogonDate"])}
    {render_table("Inactive Users", user_findings["inactive_users"], ["name", "sAMAccountName", "enabled", "lastLogonDate"])}
    {render_table("Service Accounts", user_findings["service_accounts"], ["name", "sAMAccountName", "enabled", "lastLogonDate"])}
    {render_table("Stale Computers", computer_findings["stale_computers"], ["name", "operatingSystem", "enabled", "lastLogonDate"])}
  </main>
</body>
</html>
"""

    output_path.write_text(document, encoding="utf-8")


def print_summary(
    score: int,
    user_findings: dict[str, Any],
    group_findings: dict[str, Any],
    computer_findings: dict[str, Any],
    report_path: Path,
) -> None:
    print("AD Security Audit Report")
    print()
    print(f"Users: {user_findings['total_users']}")
    print(f"Disabled Users: {user_findings['disabled_users_count']}")
    print(f"Password Never Expires: {user_findings['password_never_expires_count']}")
    print(f"Inactive Users: {user_findings['inactive_users_count']}")
    print(f"Users With No Recent Logon: {user_findings['no_recent_logon_count']}")
    print(f"Domain Admins: {group_findings['domain_admin_count']}")
    print(f"Service Accounts: {user_findings['service_accounts_count']}")
    print(f"Stale Computers: {computer_findings['stale_computers_count']}")
    print()
    print(f"Security Score: {score}/100")
    print(f"Report written to: {report_path}")


def main() -> int:
    args = parse_args()
    data = load_export(args.input)
    audit_date = datetime.now(timezone.utc)

    user_findings = collect_user_findings(data, audit_date, args.inactive_days)
    group_findings = collect_group_findings(data)
    computer_findings = collect_computer_findings(data, audit_date, args.inactive_days)
    password_policy = data.get("password_policy", {})

    score, score_notes = calculate_security_score(
        user_findings,
        group_findings,
        computer_findings,
        password_policy,
    )

    generate_html_report(
        args.output,
        args.input.name,
        audit_date,
        score,
        score_notes,
        user_findings,
        group_findings,
        computer_findings,
        password_policy,
    )
    print_summary(score, user_findings, group_findings, computer_findings, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
