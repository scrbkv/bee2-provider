#!/usr/bin/env python3
"""BIGN key, CSR and certificate interoperability with bee2evp."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


SPEC_FIELDS = 10
DIGESTS = {
    "bign-256": "belt-hash",
    "bign-384": "bash384",
    "bign-512": "bash512",
}


def run_checked(cmd: list[str], env: dict[str, str] | None = None) -> bytes:
    result = subprocess.run(cmd, capture_output=True, env=env)
    if result.returncode:
        raise RuntimeError(
            f"Command failed ({result.returncode}): {' '.join(cmd)}\n"
            f"stdout:\n{result.stdout.decode(errors='replace')}\n"
            f"stderr:\n{result.stderr.decode(errors='replace')}"
        )
    return result.stdout


def resolve_executable(value: str, label: str) -> str:
    resolved = shutil.which(value) if Path(value).name == value else value
    if not resolved:
        raise RuntimeError(f"{label} OpenSSL executable not found: {value}")
    return resolved


def curve_bits(name: str) -> str:
    lowered = name.lower()
    for bits in ("256", "384", "512"):
        if bits in lowered:
            return bits
    raise RuntimeError(f"Unsupported BIGN algorithm: {name}")


def engine_env(ld_path: str, config: str) -> dict[str, str]:
    env = os.environ.copy()
    if ld_path != "-":
        current = env.get("LD_LIBRARY_PATH")
        env["LD_LIBRARY_PATH"] = f"{ld_path}:{current}" if current else ld_path
    if config != "-":
        env["OPENSSL_CONF"] = config
    return env


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: openssl_bign_cert_interop.py '<spec>'", file=sys.stderr)
        return 2
    parts = sys.argv[1].split("|")
    if len(parts) != SPEC_FIELDS:
        print(f"invalid spec: expected {SPEC_FIELDS} fields, got {len(parts)}", file=sys.stderr)
        return 2

    (provider_raw, bee2evp_raw, engine, ld_path, engine_conf,
     provider_path_raw, provider_alg_raw, bee2evp_alg, explicit_raw,
     days_raw) = parts
    provider_openssl = resolve_executable(provider_raw, "provider")
    bee2evp_openssl = resolve_executable(bee2evp_raw, "bee2evp")
    provider_bits = curve_bits(provider_alg_raw)
    bee2evp_bits = curve_bits(bee2evp_alg)
    if bee2evp_bits != provider_bits:
        raise RuntimeError("provider and bee2evp curves differ")
    provider_alg = f"bign-{provider_bits}"
    curve = f"bign-curve{bee2evp_bits}v1"
    digest = DIGESTS[provider_alg]
    days = int(days_raw)
    if days < 1:
        raise RuntimeError("days must be positive")

    provider_path = Path(provider_path_raw).resolve()
    provider_backend = [
        "-provider-path", str(provider_path), "-provider", "bee2_provider",
        "-provider", "default", "-provider", "base",
    ]
    bee2evp_backend = ["-engine", engine]
    bee2evp_env = engine_env(ld_path, engine_conf)
    check = subprocess.run(
        [bee2evp_openssl, "engine", "-t", "-c", engine],
        capture_output=True, text=True, env=bee2evp_env,
    )
    if check.returncode or "available" not in (check.stdout + check.stderr).lower():
        raise RuntimeError(f"bee2evp engine '{engine}' is unavailable")

    with tempfile.TemporaryDirectory(prefix="bee2_bee2evp_bign_") as temp:
        root = Path(temp)
        provider_key = root / "provider.key"
        bee2evp_params = root / "bee2evp.params"
        bee2evp_key = root / "bee2evp.key"
        provider_csr = root / "provider.csr"
        bee2evp_csr = root / "bee2evp.csr"
        provider_cert = root / "provider.crt"
        bee2evp_cert = root / "bee2evp.crt"

        run_checked([provider_openssl, "genpkey", *provider_backend,
                     "-algorithm", provider_alg, "-out", str(provider_key)])
        engine_params = [bee2evp_openssl, "genpkey", *bee2evp_backend,
                         "-genparam", "-algorithm", "bign",
                         "-pkeyopt", f"params:{curve}"]
        if explicit_raw == "1":
            engine_params += ["-pkeyopt", "enc_params:specified"]
        engine_params += ["-out", str(bee2evp_params)]
        run_checked(engine_params, bee2evp_env)
        run_checked([bee2evp_openssl, "genpkey", *bee2evp_backend,
                     "-paramfile", str(bee2evp_params),
                     "-out", str(bee2evp_key)], bee2evp_env)

        for openssl, backend, env, key, csr, subject in (
            (provider_openssl, provider_backend, None, provider_key, provider_csr,
             "/CN=bee2 provider"),
            (bee2evp_openssl, bee2evp_backend, bee2evp_env, bee2evp_key, bee2evp_csr,
             "/CN=bee2evp engine"),
        ):
            run_checked([openssl, "req", *backend, f"-{digest}", "-new",
                         "-key", str(key), "-subj", subject, "-out", str(csr)], env)

        for csr in (provider_csr, bee2evp_csr):
            run_checked([provider_openssl, "req", *provider_backend,
                         "-verify", "-in", str(csr)])
            run_checked([bee2evp_openssl, "req", *bee2evp_backend,
                         "-verify", "-in", str(csr)], bee2evp_env)

        for openssl, backend, env, key, cert, subject in (
            (provider_openssl, provider_backend, None, provider_key, provider_cert,
             "/CN=bee2 provider CA"),
            (bee2evp_openssl, bee2evp_backend, bee2evp_env, bee2evp_key, bee2evp_cert,
             "/CN=bee2evp engine CA"),
        ):
            run_checked([openssl, "req", *backend, f"-{digest}", "-new", "-x509",
                         "-key", str(key), "-subj", subject, "-days", str(days),
                         "-out", str(cert)], env)

        for cert in (provider_cert, bee2evp_cert):
            run_checked([provider_openssl, "x509", *provider_backend,
                         "-in", str(cert), "-noout", "-text"])
            run_checked([bee2evp_openssl, "x509", *bee2evp_backend,
                         "-in", str(cert), "-noout", "-text"], bee2evp_env)

        # -text parses X.509 without verifying signatures.
        for cert in (provider_cert, bee2evp_cert):
            for openssl, backend, env in (
                (provider_openssl, provider_backend, None),
                (bee2evp_openssl, bee2evp_backend, bee2evp_env),
            ):
                run_checked([openssl, "verify", *backend, "-CAfile", str(cert),
                             str(cert)], env)

        message = root / "message.bin"
        message.write_bytes(bytes(range(64)))
        for (label, signer, signer_backend, signer_env, key, verifier,
             verifier_backend, verifier_env) in (
                ("provider-to-bee2evp", provider_openssl, provider_backend, None,
                 provider_key, bee2evp_openssl, bee2evp_backend, bee2evp_env),
                ("bee2evp-to-provider", bee2evp_openssl, bee2evp_backend, bee2evp_env,
                 bee2evp_key, provider_openssl, provider_backend, None),
            ):
            signature = root / f"{label}.sig"
            run_checked([signer, "dgst", *signer_backend, f"-{digest}",
                         "-sign", str(key), "-out", str(signature), str(message)],
                        signer_env)
            run_checked([verifier, "dgst", *verifier_backend, f"-{digest}",
                         "-prverify", str(key), "-signature", str(signature),
                         str(message)], verifier_env)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        raise
