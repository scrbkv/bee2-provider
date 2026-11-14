#!/usr/bin/env python3
"""CLI interoperability checks between bee2_provider and bee2evp."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


SPEC_FIELDS = 14


def run_checked(cmd: list[str], env: dict[str, str] | None = None) -> None:
    result = subprocess.run(cmd, capture_output=True, env=env)
    if result.returncode:
        raise RuntimeError(
            f"Command failed ({result.returncode}): {' '.join(cmd)}\n"
            f"stdout:\n{result.stdout.decode(errors='replace')}\n"
            f"stderr:\n{result.stderr.decode(errors='replace')}"
        )


def resolve_executable(value: str, label: str) -> str:
    resolved = shutil.which(value) if Path(value).name == value else value
    if not resolved:
        raise RuntimeError(f"{label} OpenSSL executable not found: {value}")
    return resolved


def engine_env(ld_library_path: str, openssl_conf: str) -> dict[str, str]:
    env = os.environ.copy()
    if ld_library_path != "-":
        current = env.get("LD_LIBRARY_PATH")
        env["LD_LIBRARY_PATH"] = (
            f"{ld_library_path}:{current}" if current else ld_library_path
        )
    if openssl_conf != "-":
        env["OPENSSL_CONF"] = openssl_conf
    return env


def fixed_bytes(size: int, start: int) -> bytes:
    return bytes((start + i) % 256 for i in range(size))


def assert_equal(label: str, left: bytes, right: bytes) -> None:
    if left != right:
        raise AssertionError(
            f"{label} mismatch\nleft:  {left.hex().upper()}\nright: {right.hex().upper()}"
        )


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: openssl_bee2evp_interop.py '<spec>'", file=sys.stderr)
        return 2
    parts = sys.argv[1].split("|")
    if len(parts) != SPEC_FIELDS:
        print(f"invalid spec: expected {SPEC_FIELDS} fields, got {len(parts)}", file=sys.stderr)
        return 2

    (mode, provider_raw, bee2evp_raw, engine, ld_path, engine_conf,
     provider_path_raw, provider_name, bee2evp_name, data_len_raw,
     key_size_raw, iv_size_raw, provider_digest_raw,
     bee2evp_digest_raw) = parts

    provider_openssl = resolve_executable(provider_raw, "provider")
    bee2evp_openssl = resolve_executable(bee2evp_raw, "bee2evp")
    provider_path = Path(provider_path_raw).resolve()
    if not provider_path.exists():
        raise RuntimeError(f"provider path does not exist: {provider_path}")

    data_len = int(data_len_raw)
    key_size = 0 if key_size_raw == "-" else int(key_size_raw)
    iv_size = 0 if iv_size_raw == "-" else int(iv_size_raw)
    provider_digest = None if provider_digest_raw == "-" else provider_digest_raw
    bee2evp_digest = None if bee2evp_digest_raw == "-" else bee2evp_digest_raw
    if mode not in {"cipher", "digest", "mac"}:
        raise RuntimeError(f"unsupported mode: {mode}")

    provider_backend = [
        "-provider-path", str(provider_path), "-provider", "bee2_provider",
        "-provider", "default", "-provider", "base",
    ]
    bee2evp_backend = ["-engine", engine]
    bee2evp_env = engine_env(ld_path, engine_conf)

    provider_list = subprocess.run(
        [provider_openssl, "list", *provider_backend, "-providers"],
        capture_output=True, text=True,
    )
    if provider_list.returncode or "bee2_provider" not in (
        provider_list.stdout + provider_list.stderr
    ):
        raise RuntimeError("bee2_provider is not listed as an active provider")
    engine_check = subprocess.run(
        [bee2evp_openssl, "engine", "-t", "-c", engine],
        capture_output=True, text=True, env=bee2evp_env,
    )
    if engine_check.returncode or "available" not in (
        engine_check.stdout + engine_check.stderr
    ).lower():
        raise RuntimeError(f"bee2evp engine '{engine}' is unavailable")

    with tempfile.TemporaryDirectory(prefix="bee2_bee2evp_interop_") as temp:
        root = Path(temp)
        data = fixed_bytes(data_len, 0x11)
        source = root / "data.bin"
        source.write_bytes(data)

        if mode == "cipher":
            key_hex = fixed_bytes(key_size, 0x41).hex()
            iv_hex = fixed_bytes(iv_size, 0x81).hex() if iv_size else None
            provider_ct, bee2evp_ct = root / "provider.ct", root / "bee2evp.ct"
            for openssl, backend, name, output, env in (
                (provider_openssl, provider_backend, provider_name, provider_ct, None),
                (bee2evp_openssl, bee2evp_backend, bee2evp_name, bee2evp_ct, bee2evp_env),
            ):
                cmd = [openssl, "enc", *backend, f"-{name}", "-e", "-nosalt",
                       "-nopad", "-K", key_hex]
                if iv_hex:
                    cmd += ["-iv", iv_hex]
                cmd += ["-in", str(source), "-out", str(output)]
                run_checked(cmd, env)
            assert_equal("ciphertext", provider_ct.read_bytes(), bee2evp_ct.read_bytes())

            for openssl, backend, name, ciphertext, env, label in (
                (provider_openssl, provider_backend, provider_name, bee2evp_ct, None,
                 "provider decrypts bee2evp"),
                (bee2evp_openssl, bee2evp_backend, bee2evp_name, provider_ct,
                 bee2evp_env, "bee2evp decrypts provider"),
            ):
                output = root / f"{label.split()[0]}.dec"
                cmd = [openssl, "enc", *backend, f"-{name}", "-d", "-nosalt",
                       "-nopad", "-K", key_hex]
                if iv_hex:
                    cmd += ["-iv", iv_hex]
                cmd += ["-in", str(ciphertext), "-out", str(output)]
                run_checked(cmd, env)
                assert_equal(label, output.read_bytes(), data)

        elif mode == "digest":
            outputs = []
            for label, openssl, backend, name, env in (
                ("provider", provider_openssl, provider_backend, provider_name, None),
                ("bee2evp", bee2evp_openssl, bee2evp_backend, bee2evp_name, bee2evp_env),
            ):
                output = root / f"{label}.out"
                run_checked([openssl, "dgst", *backend, f"-{name}", "-binary",
                             "-out", str(output), str(source)], env)
                outputs.append(output.read_bytes())
            assert_equal("digest", outputs[0], outputs[1])

        else:
            key_hex = fixed_bytes(key_size, 0x41).hex()
            provider_out, bee2evp_out = root / "provider.mac", root / "bee2evp.mac"
            provider_cmd = [provider_openssl, "mac", *provider_backend, "-binary",
                            "-out", str(provider_out), "-in", str(source)]
            if provider_digest:
                provider_cmd += ["-macopt", f"digest:{provider_digest}"]
            provider_cmd += ["-macopt", f"hexkey:{key_hex}", provider_name]
            run_checked(provider_cmd)

            engine_cmd = [bee2evp_openssl, "dgst", *bee2evp_backend, "-mac",
                          bee2evp_name, "-macopt", f"hexkey:{key_hex}"]
            if bee2evp_digest:
                engine_cmd += ["-macopt", f"digest:{bee2evp_digest}"]
            engine_cmd += ["-binary", "-out", str(bee2evp_out), str(source)]
            run_checked(engine_cmd, bee2evp_env)
            assert_equal("mac", provider_out.read_bytes(), bee2evp_out.read_bytes())
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        raise
