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
    load_public_key,
    save_keypair,
    serialize_public_key,
)
from swarmsec.registrar.credential import verify_credential
from swarmsec.registrar.models import Credential


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
def register(registrar, identity, key):
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
    
    cred_file = "credential.json"
    with open(cred_file, "w") as f:
        json.dump(cred, f, indent=2)

    click.secho("Registration successful!", fg="green")
    click.echo(f"Credential saved to {cred_file}")
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


if __name__ == "__main__":
    cli()
