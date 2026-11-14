#!/usr/bin/env python3
"""Check exported algorithm names against the bee2evp compatibility set.

OPENSSL_CONF is set to the null device so local OpenSSL configuration cannot
influence the result. Provider-specific algorithms and exclusions are checked.
"""

import argparse
import os
import re
import subprocess
import sys


EXPORTS = {
    "-cipher-algorithms": {
        "belt-ecb128", "belt-ecb192", "belt-ecb256",
        "belt-cbc128", "belt-cbc192", "belt-cbc256",
        "belt-cfb128", "belt-cfb192", "belt-cfb256",
        "belt-ctr128", "belt-ctr192", "belt-ctr256",
        "belt-dwp128", "belt-dwp192", "belt-dwp256",
        "belt-che128", "belt-che192", "belt-che256",
        "belt-kwp128", "belt-kwp192", "belt-kwp256",
        "bash-prg-ae2561",
    },
    "-digest-algorithms": {"belt-hash", "bash256", "bash384", "bash512"},
    "-mac-algorithms": {"belt-mac128", "belt-mac192", "belt-mac256", "belt-hmac"},
    "-kdf-algorithms": {"belt-pbkdf"},
    "-asymcipher-algorithms": {"bign-keytransport"},
    "-signature-algorithms": {
        "bign-with-hspec", "bign-with-hbelt",
        "bign-with-bash256", "bign-with-bash384", "bign-with-bash512",
    },
    "-key-managers": {"bign-256", "bign-384", "bign-512"},
    "-key-exchange-algorithms": {"bign-256", "bign-384", "bign-512"},
}

# Provider-specific algorithms and names beyond the bee2evp compatibility set.
# The common bign / bign-pubkey aliases bridge the ASN.1 public-key OID to
# the curve-specific bign-256, bign-384 and bign-512 generation interfaces.
EXTENSIONS = {
    "-cipher-algorithms": {
        "belt-bde128", "belt-bde192", "belt-bde256",
        "belt-sde128", "belt-sde192", "belt-sde256",
        "bash-prg-ae1281", "bash-prg-ae1282",
        "bash-prg-ae1921", "bash-prg-ae1922", "bash-prg-ae2562",
    },
    "-signature-algorithms": {
        "bign", "bign-256", "bign-384", "bign-512",
    },
    "-key-managers": {"bign", "bign-pubkey"},
    "-key-exchange-algorithms": {"bign"},
    "-encoders": {"bign", "bign-pubkey", "bign-256", "bign-384", "bign-512"},
    "-decoders": {"bign", "bign-pubkey"},
    "-random-generators": {"brng-ctr-hbelt", "brng-hmac-hbelt"},
    "-store-loaders": {"bign"},
}

# TLS-record cipher aliases are excluded because the corresponding record-layer
# semantics are not implemented by this provider.
INTENTIONAL_OMISSIONS = {
    "-cipher-algorithms": {
        "belt-dwp-tls", "belt-che-tls", "bash-prg-ae-tls", "belt-ctr-tls",
    },
    "-signature-algorithms": {"bign-pubkey", "bign-curve256v1", "bign-curve384v1", "bign-curve512v1"},
    "-key-managers": {"bign-curve256v1", "bign-curve384v1", "bign-curve512v1"},
    "-key-exchange-algorithms": {"bign-pubkey", "bign-curve256v1", "bign-curve384v1", "bign-curve512v1"},
    "-encoders": {"bign-curve256v1", "bign-curve384v1", "bign-curve512v1"},
    "-decoders": {"bign-curve256v1", "bign-curve384v1", "bign-curve512v1"},
}

STYLE_ONLY_OPTIONS = {
    "-random-generators", "-encoders", "-decoders", "-store-loaders"
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider-path", required=True)
    parser.add_argument("--openssl", default="openssl")
    args = parser.parse_args()

    env = os.environ.copy()
    env["OPENSSL_CONF"] = os.devnull
    failures = []

    for option in list(EXPORTS) + sorted(STYLE_ONLY_OPTIONS):
        required = EXPORTS.get(option, set())
        command = [
            args.openssl, "list", option,
            "-provider-path", args.provider_path,
            "-provider", "bee2_provider",
        ]
        result = subprocess.run(command, env=env, text=True, capture_output=True)
        if result.returncode:
            failures.append(f"{option}: command failed: {result.stderr.strip()}")
            continue
        output = result.stdout.lower()
        missing = sorted(name for name in required if name not in output)
        if missing:
            failures.append(f"{option}: missing {', '.join(missing)}")

        # Use lowercase kebab-case names, with numeric OIDs allowed as aliases.
        actual = set()
        for line in result.stdout.splitlines():
            if "@ bee2_provider" not in line:
                continue
            public_part = line.split("@ bee2_provider", 1)[0]
            if "{" in public_part:
                public_part = public_part.split("{", 1)[1].split("}", 1)[0]
            if re.search(r"[A-Z]", public_part):
                failures.append(f"{option}: non-bee2evp name in {line.strip()}")
            for name in (item.strip().lower() for item in public_part.split(",")):
                if name and not re.fullmatch(r"\d+(?:\.\d+)+", name):
                    actual.add(name)

        allowed = required | EXTENSIONS.get(option, set())
        unexpected = sorted(actual - allowed)
        if unexpected:
            failures.append(f"{option}: unexpected export(s): {', '.join(unexpected)}")

        forbidden = sorted(actual & INTENTIONAL_OMISSIONS.get(option, set()))
        if forbidden:
            failures.append(
                f"{option}: intentionally omitted export(s) present: {', '.join(forbidden)}"
            )

    if failures:
        print("bee2evp export parity failed:", file=sys.stderr)
        print("\n".join(f"  {failure}" for failure in failures), file=sys.stderr)
        return 1

    compatible = sum(len(names) for names in EXPORTS.values())
    extensions = sum(len(names) for names in EXTENSIONS.values())
    omissions = sum(len(names) for names in INTENTIONAL_OMISSIONS.values())
    print(
        f"bee2evp export parity: {compatible} names present; "
        f"{extensions} documented extensions; {omissions} deliberate omissions"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
