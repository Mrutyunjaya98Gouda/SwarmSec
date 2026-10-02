"""Click-based CLI for SwarmSec.

Provides commands for:
- Key generation
- Registration
- Credential verification
- Transparency log verification
"""

import base64
import json
import sys
from pathlib import Path

import click
import httpx

from swarmsec.crypto.keys import (
    deserialize_public_key,
    generate_keypair,
    load_private_key,
    load_public_key,
    save_keypair,
    serialize_private_key,
    serialize_public_key,
)
from swarmsec.registrar.credential import verify_credential
from swarmsec.registrar.models import Credential

ADVISORY_DISCLAIMER = (
    "ADVISORY ONLY: SwarmSec computes local corroboration scores and trust rankings. "
    "This is NOT an automated block/allow decision; a human analyst must make that call."
)


@click.group()
def cli():
    """SwarmSec Command Line Interface."""
    pass


@cli.command()
@click.option("--out", type=click.Path(), default=".", help="Directory to save keys.")
def keygen(out):
    """Generate a new Ed25519 pseudonym keypair."""
    priv, pub = generate_keypair()
    priv_path, pub_path = save_keypair(priv, out)
    click.echo(f"Generated keypair:")
    click.echo(f"  Private: {priv_path}")
    click.echo(f"  Public:  {pub_path}")


@cli.command()
@click.option("--registrar", required=True, help="URL of the registrar service.")
@click.option("--identity", required=True, help="Your real-world organization ID.")
@click.option("--key", required=True, type=click.Path(exists=True), help="Path to your public key (.pub).")
@click.option("--out", type=click.Path(), default="credential.json", help="Path to save issued credential.")
def register(registrar, identity, key, out):
    """Register with the registrar to receive a credential."""
    pub_key = load_public_key(key)
    raw_pub = serialize_public_key(pub_key)
    b64_pub = base64.b64encode(raw_pub).decode("ascii")

    req_data = {
        "org_id": identity,
        "pseudonym_public_key": b64_pub,
    }

    try:
        resp = httpx.post(f"{registrar}/register", json=req_data, timeout=10.0)
    except httpx.RequestError as e:
        click.secho(f"Error connecting to registrar: {e}", fg="red")
        sys.exit(1)

    if resp.status_code == 403:
        click.secho(f"Registration rejected: {resp.json().get('detail')}", fg="red")
        sys.exit(1)
    elif resp.status_code != 200:
        click.secho(f"Registration failed ({resp.status_code}): {resp.text}", fg="red")
        sys.exit(1)

    data = resp.json()
    cred = data["credential"]

    with open(out, "w") as f:
        json.dump(cred, f, indent=2)

    click.secho("Registration successful!", fg="green")
    click.echo(f"Credential saved to {out}")
    click.echo(f"Log entry index: {data['log_entry']['index']}")


@cli.command()
@click.option("--credential", required=True, type=click.Path(exists=True), help="Path to the credential.json file.")
@click.option("--registrar-pubkey", required=True, type=click.Path(exists=True), help="Path to the registrar's public key.")
def verify_credential_cmd(credential, registrar_pubkey):
    """Verify a credential offline against the registrar's public key."""
    with open(credential, "r") as f:
        cred_dict = json.load(f)

    cred = Credential(**cred_dict)
    reg_pub = load_public_key(registrar_pubkey)

    is_valid = verify_credential(cred, reg_pub)
    if is_valid:
        click.secho("Credential signature is VALID.", fg="green")
        click.echo(f"Status: {cred.status}")
        click.echo(f"Expires: {cred.expires_at}")
    else:
        click.secho("Credential signature is INVALID or tampered.", fg="red")
        sys.exit(1)


@cli.command()
@click.option("--registrar", required=True, help="URL of the registrar service.")
def log_verify(registrar):
    """Ask the registrar to verify its transparency log integrity."""
    try:
        resp = httpx.get(f"{registrar}/log/verify", timeout=10.0)
    except httpx.RequestError as e:
        click.secho(f"Error connecting to registrar: {e}", fg="red")
        sys.exit(1)

    if resp.status_code == 200:
        data = resp.json()
        if data["is_valid"]:
            click.secho(f"Log verified: {data['message']}", fg="green")
        else:
            click.secho(f"Log corruption detected: {data['message']}", fg="red")
            sys.exit(1)
    else:
        click.secho(f"Request failed ({resp.status_code})", fg="red")
        sys.exit(1)


@cli.command()
@click.option("--node", default="http://localhost:8001", help="URL of the local SwarmSec node daemon.")
@click.option("--credential", required=True, type=click.Path(exists=True), help="Path to credential.json.")
@click.option("--key", required=True, type=click.Path(exists=True), help="Path to private key (.key).")
@click.option("--pattern", required=True, help="STIX pattern (e.g. [ipv4-addr:value = '198.51.100.1']).")
def submit(node, credential, key, pattern):
    """Publish a new indicator report to the SwarmSec node."""
    with open(credential, "r") as f:
        cred = json.load(f)

    priv = load_private_key(key)
    raw_priv = serialize_private_key(priv)
    b64_priv = base64.b64encode(raw_priv).decode("ascii")

    req_data = {
        "credential_id": cred["credential_id"],
        "private_key_b64": b64_priv,
        "pattern": pattern,
    }

    try:
        resp = httpx.post(f"{node.rstrip('/')}/publish", json=req_data, timeout=10.0)
    except httpx.RequestError as e:
        click.secho(f"Error connecting to node daemon: {e}", fg="red")
        sys.exit(1)

    if resp.status_code != 200:
        click.secho(f"Failed to publish indicator ({resp.status_code}): {resp.text}", fg="red")
        sys.exit(1)

    res = resp.json()
    click.secho(f"Indicator published successfully.", fg="green")
    click.echo(f"  Message ID: {res.get('message_id')}")
    click.echo(f"  Pattern:    {pattern}")
    click.secho(f"\n{ADVISORY_DISCLAIMER}", fg="yellow")


@cli.command()
@click.option("--node", default="http://localhost:8001", help="URL of the local SwarmSec node daemon.")
@click.option("--credential", required=True, type=click.Path(exists=True), help="Path to credential.json.")
@click.option("--key", required=True, type=click.Path(exists=True), help="Path to private key (.key).")
@click.option("--indicator-id", required=True, help="Target indicator ID (e.g. indicator--...).")
@click.option(
    "--opinion",
    default="agree",
    type=click.Choice(["strongly-agree", "agree", "neutral", "disagree", "strongly-disagree"]),
    help="STIX opinion verdict.",
)
def feedback(node, credential, key, indicator_id, opinion):
    """Publish an endorsement or disagreement for an indicator."""
    with open(credential, "r") as f:
        cred = json.load(f)

    priv = load_private_key(key)
    raw_priv = serialize_private_key(priv)
    b64_priv = base64.b64encode(raw_priv).decode("ascii")

    req_data = {
        "credential_id": cred["credential_id"],
        "private_key_b64": b64_priv,
        "indicator_id": indicator_id,
        "opinion": opinion,
    }

    try:
        resp = httpx.post(f"{node.rstrip('/')}/feedback", json=req_data, timeout=10.0)
    except httpx.RequestError as e:
        click.secho(f"Error connecting to node daemon: {e}", fg="red")
        sys.exit(1)

    if resp.status_code != 200:
        click.secho(f"Failed to publish feedback ({resp.status_code}): {resp.text}", fg="red")
        sys.exit(1)

    res = resp.json()
    click.secho(f"Feedback published successfully.", fg="green")
    click.echo(f"  Message ID:   {res.get('message_id')}")
    click.echo(f"  Target ID:    {indicator_id}")
    click.echo(f"  Verdict:      {opinion}")
    click.secho(f"\n{ADVISORY_DISCLAIMER}", fg="yellow")


@cli.command()
@click.option("--node", default="http://localhost:8001", help="URL of the local SwarmSec node daemon.")
@click.option("--pattern", required=True, help="Indicator pattern to query.")
def query(node, pattern):
    """Query local trust ranking and corroboration breakdown for an indicator."""
    try:
        resp = httpx.get(f"{node.rstrip('/')}/query", params={"pattern": pattern}, timeout=10.0)
    except httpx.RequestError as e:
        click.secho(f"Error connecting to node daemon: {e}", fg="red")
        sys.exit(1)

    if resp.status_code == 404:
        click.secho(f"Indicator not found on local node: {pattern}", fg="yellow")
        click.secho(f"\n{ADVISORY_DISCLAIMER}", fg="yellow")
        sys.exit(1)
    elif resp.status_code != 200:
        click.secho(f"Query error ({resp.status_code}): {resp.text}", fg="red")
        sys.exit(1)

    data = resp.json()
    score = data.get("local_corroboration_score", 0.0)
    status = data.get("status", "UNKNOWN")
    sources = data.get("independent_sources", 0)
    flags = data.get("flags", [])

    click.echo("=" * 68)
    click.secho("SwarmSec Local Corroboration & Trust Ranking Report", bold=True, fg="cyan")
    click.echo("=" * 68)
    click.echo(f"  Pattern:                 {pattern}")
    
    if score >= 0.8:
        score_color = "green"
    elif score >= 0.4:
        score_color = "yellow"
    else:
        score_color = "red"

    click.echo("  Trust Ranking:           ", nl=False)
    click.secho(f"{score:.2f}", bold=True, fg=score_color)
    click.echo(f"  Status:                  {status}")
    click.echo(f"  Independent Sources:     {sources}")

    if "feedback_downweighted" in flags:
        click.echo("  Down-Weighting Status:   ", nl=False)
        click.secho("TRIGGERED (correlated-evidence down-weighting)", bold=True, fg="red")
        click.echo("  Annotation:              Dense cluster or mutual endorsement detected by formula.")
    elif "feed_overlap" in flags:
        click.echo("  Down-Weighting Status:   ", nl=False)
        click.secho("FLAGGED (feed overlap)", bold=True, fg="yellow")
        click.echo("  Annotation:              Reports share common public feed reference.")
    else:
        click.echo("  Down-Weighting Status:   ", nl=False)
        click.secho("CLEAN (independent observations)", fg="green")

    click.echo("-" * 68)
    click.secho(ADVISORY_DISCLAIMER, fg="yellow")
    click.echo("=" * 68)


@cli.command()
@click.option("--node", default="http://localhost:8001", help="URL of the local SwarmSec node daemon.")
def feed(node):
    """Display the full ranked threat intelligence feed with annotations."""
    try:
        resp = httpx.get(f"{node.rstrip('/')}/feed", timeout=10.0)
    except httpx.RequestError as e:
        click.secho(f"Error connecting to node daemon: {e}", fg="red")
        sys.exit(1)

    if resp.status_code != 200:
        click.secho(f"Failed to fetch feed ({resp.status_code}): {resp.text}", fg="red")
        sys.exit(1)

    data = resp.json()
    indicators = data.get("ranked_indicators", [])

    click.echo("=" * 78)
    click.secho("SwarmSec Local Threat Intelligence Feed — Ranked by Corroboration", bold=True, fg="cyan")
    click.echo(f"Total Indicators: {len(indicators)}  |  Total Messages: {data.get('total_messages', 0)}")
    click.echo("=" * 78)

    if not indicators:
        click.echo("No threat indicators observed yet.")
    else:
        header = f"{'Rank':<6} {'Score':<8} {'Sources':<9} {'Downweighted':<14} {'Pattern'}"
        click.secho(header, bold=True)
        click.echo("-" * 78)

        for idx, item in enumerate(indicators, 1):
            score = item.get("local_corroboration_score", 0.0)
            sources = item.get("independent_sources", 0)
            pattern = item.get("pattern", "")
            dw = item.get("downweighted", False) or ("feedback_downweighted" in item.get("flags", []))
            dw_str = "YES (PENALTY)" if dw else "NO"

            rank_str = f"#{idx:<4}"
            score_str = f"{score:<7.2f}"
            sources_str = f"{sources:<8}"
            dw_formatted = f"{dw_str:<13}"

            line = f"{rank_str} {score_str} {sources_str} {dw_formatted} {pattern}"
            if dw:
                click.secho(line, fg="red")
            elif score >= 0.8:
                click.secho(line, fg="green")
            else:
                click.echo(line)

    click.echo("-" * 78)
    click.secho(ADVISORY_DISCLAIMER, fg="yellow")
    click.echo("=" * 78)


@cli.command()
@click.option("--node", default="http://localhost:8001", help="URL of the local SwarmSec node daemon.")
@click.option("--once", is_flag=True, help="Render dashboard once and exit.")
@click.option("--refresh-rate", default=1.0, type=float, help="Refresh interval in seconds.")
def dashboard(node, once, refresh_rate):
    """Launch the terminal live dashboard."""
    from swarmsec.cli.dashboard import render_dashboard_once, run_live_dashboard
    if once:
        render_dashboard_once(node)
    else:
        run_live_dashboard(node, refresh_rate=refresh_rate)


if __name__ == "__main__":
    cli()

