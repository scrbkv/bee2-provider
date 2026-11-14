#!/usr/bin/env python3
"""Exercise BIGN PKCS#8/SPKI PEM/DER conversion via OpenSSL file loading."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import tempfile


def openssl_run(openssl: str, provider_path: str, args: list[str]) -> bytes:
    command = [openssl, args[0], "-provider-path", provider_path,
               "-provider", "default", "-provider", "bee2_provider", *args[1:]]
    env = os.environ.copy()
    env["OPENSSL_CONF"] = os.devnull
    result = subprocess.run(command, env=env, capture_output=True)
    if result.returncode:
        raise RuntimeError(
            f"{' '.join(command)} failed with exit {result.returncode}:\n"
            f"{result.stderr.decode(errors='replace')}")
    return result.stdout


def check_curve(openssl: str, provider_path: str, directory: Path, bits: int) -> None:
    prefix = directory / f"bign-{bits}"
    key_pem = prefix.with_suffix(".key.pem")
    key_der = prefix.with_suffix(".key.der")
    key_reencoded = prefix.with_suffix(".reencoded.pem")
    key_roundtrip = prefix.with_suffix(".roundtrip.der")
    pub_der = prefix.with_suffix(".pub.der")
    pub_pem = prefix.with_suffix(".pub.pem")
    pub_roundtrip = prefix.with_suffix(".pub.roundtrip.der")
    pub_again = prefix.with_suffix(".pub.again.der")

    openssl_run(openssl, provider_path,
                ["genpkey", "-algorithm", f"bign-{bits}", "-out", str(key_pem)])
    openssl_run(openssl, provider_path,
                ["pkey", "-in", str(key_pem), "-outform", "DER", "-out", str(key_der)])
    openssl_run(openssl, provider_path,
                ["pkey", "-inform", "DER", "-in", str(key_der),
                 "-outform", "PEM", "-out", str(key_reencoded)])
    openssl_run(openssl, provider_path,
                ["pkey", "-in", str(key_reencoded), "-outform", "DER", "-out", str(key_roundtrip)])
    if key_roundtrip.read_bytes() != key_der.read_bytes():
        raise RuntimeError(f"BIGN-{bits}: PKCS#8 PEM/DER roundtrip changed the key")

    openssl_run(openssl, provider_path,
                ["pkey", "-in", str(key_pem), "-pubout", "-outform", "DER", "-out", str(pub_der)])
    openssl_run(openssl, provider_path,
                ["pkey", "-pubin", "-inform", "DER", "-in", str(pub_der),
                 "-pubout", "-outform", "PEM", "-out", str(pub_pem)])
    openssl_run(openssl, provider_path,
                ["pkey", "-pubin", "-in", str(pub_pem),
                 "-pubout", "-outform", "DER", "-out", str(pub_roundtrip)])
    openssl_run(openssl, provider_path,
                ["pkey", "-in", str(key_reencoded),
                 "-pubout", "-outform", "DER", "-out", str(pub_again)])
    for file in (pub_roundtrip, pub_again):
        if file.read_bytes() != pub_der.read_bytes():
            raise RuntimeError(f"BIGN-{bits}: SPKI roundtrip changed the public key")

    explicit_pem = prefix.with_suffix(".explicit.pem")
    explicit_der = prefix.with_suffix(".explicit.der")
    explicit_roundtrip = prefix.with_suffix(".explicit.roundtrip.pem")
    explicit_reencoded_der = prefix.with_suffix(".explicit.reencoded.der")
    openssl_run(openssl, provider_path,
                ["genpkey", "-algorithm", f"bign-{bits}",
                 "-pkeyopt", "encoding:explicit", "-pkeyopt", "enc_params:cofactor",
                 "-out", str(explicit_pem)])
    openssl_run(openssl, provider_path,
                ["pkey", "-in", str(explicit_pem),
                 "-outform", "DER", "-out", str(explicit_der)])
    openssl_run(openssl, provider_path,
                ["pkey", "-inform", "DER", "-in", str(explicit_der),
                 "-out", str(explicit_roundtrip)])
    openssl_run(openssl, provider_path,
                ["pkey", "-in", str(explicit_roundtrip),
                 "-outform", "DER", "-out", str(explicit_reencoded_der)])
    if explicit_reencoded_der.read_bytes() != explicit_der.read_bytes():
        raise RuntimeError(f"BIGN-{bits}: explicit curve parameters changed on roundtrip")

    # The standard OpenSSL file STORE provider delegates key decoding to
    # bee2_provider's PKCS#8/SPKI decoders. No private bign: URI is needed.
    for key_path in (key_pem, key_der, explicit_pem, explicit_der,
                     pub_pem, pub_der):
        for uri in ("file:" + str(key_path), str(key_path)):
            result = openssl_run(openssl, provider_path,
                                 ["storeutl", uri])
            expected_type = (b"-----BEGIN PUBLIC KEY-----" if key_path in (pub_pem, pub_der)
                             else b"-----BEGIN PRIVATE KEY-----")
            if expected_type not in result or b"Total found: 1" not in result:
                raise RuntimeError(f"BIGN-{bits}: file STORE did not load {uri}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider-path", required=True)
    parser.add_argument("--openssl", default="openssl")
    options = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="bee2-bign-codec-") as tmp:
        for bits in (256, 384, 512):
            check_curve(options.openssl, options.provider_path, Path(tmp), bits)
    print("BIGN PKCS#8/SPKI PEM/DER and OpenSSL file STORE roundtrips passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
