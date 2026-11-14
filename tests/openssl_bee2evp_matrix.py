#!/usr/bin/env python3
"""Deterministic boundary and pseudorandom interoperability matrix.

The existing two-backend interoperability runner performs the actual
comparisons, including cross-decryption. This driver varies every input
buffer and refuses to skip a failed case.
"""
from __future__ import annotations

import hashlib
import os
import sys

import openssl_bee2evp_interop as interop


def pattern_bytes(size: int, start: int, pattern: str) -> bytes:
    if pattern == "zero":
        return bytes(size)
    if pattern == "ones":
        return bytes([0xFF]) * size
    if pattern == "walking":
        return bytes(1 << ((i + start) % 8) for i in range(size))
    if pattern == "counter":
        return bytes((start + i) % 256 for i in range(size))
    if pattern == "random":
        seed = f"bee2-provider-interop-v1:{start}:{size}".encode("ascii")
        return hashlib.shake_256(seed).digest(size)
    raise ValueError(f"unknown pattern: {pattern}")


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: openssl_bee2evp_matrix.py '<14-field-spec>'", file=sys.stderr)
        return 2
    spec = sys.argv[1].split("|")
    if len(spec) != interop.SPEC_FIELDS:
        raise ValueError("invalid interoperability specification")

    mode, name = spec[0], spec[7]
    if mode == "cipher" and (name.startswith("belt-ecb") or name.startswith("belt-cbc")):
        lengths = (16, 32, 48, 64, 256, 1024)
    elif mode == "cipher":
        lengths = (1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 257, 1024)
    else:
        lengths = (0, 1, 15, 16, 31, 32, 33, 63, 64, 65, 127,
                   128, 129, 143, 144, 145, 159, 160, 161, 257, 1024)

    original_argv = interop.sys.argv
    original_fixed_bytes = interop.fixed_bytes
    try:
        for profile in ("zero", "ones", "walking", "counter", "random"):
            interop.fixed_bytes = (
                lambda size, start, p=profile: pattern_bytes(size, start, p)
            )
            for length in lengths:
                spec[9] = str(length)
                interop.sys.argv = ["openssl_bee2evp_interop.py", "|".join(spec)]
                try:
                    result = interop.main()
                    if result != 0:
                        raise RuntimeError(f"interop returned {result}")
                except Exception as exc:
                    raise RuntimeError(
                        f"{mode}/{name}: profile={profile}, length={length}"
                    ) from exc
        print(f"[OK] {mode}/{name}: {5 * len(lengths)} interop cases")
        return 0
    finally:
        interop.sys.argv = original_argv
        interop.fixed_bytes = original_fixed_bytes


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        raise
