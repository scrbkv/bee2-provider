#!/usr/bin/env python3
"""Test malformed BIGN PKCS#8 and SPKI through the OpenSSL pkey CLI.

The CLI reads one ASN.1 object and can ignore following bytes even for RSA.
Root framing and trailing-byte rejection are tested by bign_der_framing.c.
"""

import argparse
import base64
import os
from pathlib import Path
import subprocess
import tempfile


def execute(openssl: str, provider_args: list[str], env: dict[str, str],
            arguments: list[str], expected_success: bool) -> None:
    command = [openssl, *arguments[:1], *provider_args, *arguments[1:]]
    result = subprocess.run(command, capture_output=True, env=env, text=True)
    if (result.returncode == 0) != expected_success:
        raise RuntimeError(
            f"unexpected exit status for {' '.join(arguments)}: {result.stderr.strip()}"
        )


def pem_der(path: Path) -> bytes:
    lines = path.read_text(encoding="ascii").splitlines()
    body = "".join(line for line in lines if line and not line.startswith("-----"))
    return base64.b64decode(body, validate=True)


def check_der(openssl: str, provider_args: list[str], env: dict[str, str],
              directory: Path, name: str, data: bytes, public: bool,
              expected_success: bool) -> None:
    filename = directory / f"{name}.der"
    filename.write_bytes(data)
    command = ["pkey", "-inform", "DER", "-in", str(filename), "-noout"]
    if public:
        command.insert(1, "-pubin")
    execute(openssl, provider_args, env, command, expected_success)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider-path", required=True)
    parser.add_argument("--openssl", default="openssl")
    arguments = parser.parse_args()
    env = os.environ.copy()
    env["OPENSSL_CONF"] = os.devnull
    providers = [
        "-provider-path", arguments.provider_path,
        "-provider", "default", "-provider", "bee2_provider",
    ]

    with tempfile.TemporaryDirectory(prefix="bee2-asn1-") as temporary:
        directory = Path(temporary)
        for bits in (256, 384, 512):
            name = f"bign-{bits}"
            private_pem = directory / f"{name}.pem"
            public_der = directory / f"{name}.spki.der"
            execute(arguments.openssl, providers, env,
                    ["genpkey", "-algorithm", name, "-out", str(private_pem)], True)
            execute(arguments.openssl, providers, env,
                    ["pkey", "-in", str(private_pem), "-pubout",
                     "-outform", "DER", "-out", str(public_der)], True)

            pub = public_der.read_bytes()
            priv = pem_der(private_pem)
            pubsize = bits // 4
            privsize = bits // 8
            if len(pub) <= pubsize + 1 or len(priv) <= privsize:
                raise RuntimeError(f"unexpected encoded key size for {name}")
            check_der(arguments.openssl, providers, env, directory,
                      f"{name}-pub-valid", pub, True, True)
            check_der(arguments.openssl, providers, env, directory,
                      f"{name}-priv-valid", priv, False, True)

            zero_point = pub[:-pubsize] + bytes(pubsize)
            invalid_bit = bytearray(pub)
            invalid_bit[-pubsize - 1] = 1
            zero_scalar = priv[:-privsize] + bytes(privsize)
            cases = [
                ("pub-truncated", pub[:-1], True),
                ("pub-invalid-point", zero_point, True),
                ("pub-unused-bits", bytes(invalid_bit), True),
                ("priv-truncated", priv[:-1], False),
                ("priv-zero-scalar", zero_scalar, False),
            ]
            for suffix, data, is_public in cases:
                check_der(arguments.openssl, providers, env, directory,
                          f"{name}-{suffix}", data, is_public, False)

    print("BIGN malformed PKCS#8/SPKI rejected by OpenSSL pkey for all fixed curves")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
