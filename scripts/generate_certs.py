import datetime
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_certs():
    os.makedirs("certs", exist_ok=True)
    
    # 1. Generate Root CA
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SwarmSec Root CA")])
    ca_cert = x509.CertificateBuilder().subject_name(
        ca_subject
    ).issuer_name(
        ca_subject
    ).public_key(
        ca_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.UTC)
    ).not_valid_after(
        datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
    ).sign(ca_key, hashes.SHA256())

    with open("certs/ca.key", "wb") as f:
        f.write(ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("certs/ca.pem", "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    # 2. Generate Certs for Entities
    entities = ["registrar", "node1", "node2", "node3"]
    for entity in entities:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, entity)])
        
        sans = [
            x509.DNSName(entity),
            x509.DNSName("localhost"),
            x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1")),
            x509.IPAddress(__import__("ipaddress").ip_address("0.0.0.0")),
        ]
        # Dynamically add all local host IPv4 addresses so peers can reach across LAN
        try:
            import socket
            hostname = socket.gethostname()
            sans.append(x509.DNSName(hostname))
            local_ips = socket.gethostbyname_ex(hostname)[2]
            for ip_str in local_ips:
                sans.append(x509.IPAddress(__import__("ipaddress").ip_address(ip_str)))
        except Exception:
            pass

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            ca_subject
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.UTC)
        ).not_valid_after(
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName(sans),
            critical=False,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        ).sign(ca_key, hashes.SHA256())

        with open(f"certs/{entity}.key", "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(f"certs/{entity}.pem", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

if __name__ == "__main__":
    generate_certs()
    print("Successfully generated mTLS certificates in the 'certs/' directory.")
