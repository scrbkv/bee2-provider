#!/usr/bin/env python3
"""Exercise fixed-curve BIGN generation and encoding options."""

import argparse
import os
import subprocess
import tempfile


def run(command: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, env=env, text=True, capture_output=True, check=True)


def must_fail(command: list[str], env: dict[str, str]) -> None:
    result = subprocess.run(command, env=env, text=True, capture_output=True)
    if result.returncode == 0:
        raise RuntimeError(f"command unexpectedly succeeded: {' '.join(command)}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider-path", required=True)
    parser.add_argument("--openssl", default="openssl")
    args = parser.parse_args()

    env = os.environ.copy()
    env["OPENSSL_CONF"] = os.devnull
    provider_args = [
        "-provider-path", args.provider_path,
        "-provider", "default",
        "-provider", "bee2_provider",
    ]

    with tempfile.TemporaryDirectory(prefix="bee2-bign-options-") as directory:
        for algorithm in ("bign-256", "bign-384", "bign-512"):
            run(
                [
                    args.openssl,
                    "genpkey",
                    *provider_args,
                    "-algorithm",
                    algorithm,
                    "-out",
                    os.path.join(directory, f"{algorithm}.pem"),
                ],
                env,
            )

        named = os.path.join(directory, "bign-256.pem")
        explicit = os.path.join(directory, "bign-256-explicit.pem")
        base = [args.openssl, "genpkey", *provider_args, "-algorithm", "bign-256"]
        run(
            [
                *base,
                "-pkeyopt", "encoding:explicit",
                "-pkeyopt", "enc_params:cofactor",
                "-out", explicit,
            ],
            env,
        )

        parsed = run(
            [args.openssl, "asn1parse", "-in", explicit, "-inform", "PEM", "-i"], env
        ).stdout
        prime_field_oid = "1.2.112.0.2.0.34.101.45.4.1"
        if prime_field_oid not in parsed or "INTEGER           :01" not in parsed:
            raise RuntimeError("explicit BIGN parameters or cofactor are missing")
        if os.path.getsize(explicit) <= os.path.getsize(named):
            raise RuntimeError("explicit BIGN encoding is not larger than named encoding")

        must_fail(
            [args.openssl, "genpkey", *provider_args, "-algorithm", "bign"], env
        )
        must_fail(
            [
                *base,
                "-pkeyopt",
                "group:bign-384",
                "-out",
                os.path.join(directory, "invalid.pem"),
            ],
            env,
        )

    print("BIGN fixed-curve keygen and explicit/cofactor encoding: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
