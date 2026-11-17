#!/usr/bin/env python3
"""Cross-version AEAD/KWP matrix: independent OpenSSL binaries, common wire form."""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import subprocess
import tempfile


def material(length: int, profile: int, salt: str) -> bytes:
    if profile == 0:
        return bytes(length)
    if profile == 1:
        return bytes((i * 37 + 91) & 255 for i in range(length))
    return hashlib.shake_256(f"bee2evp-aead:{salt}:{length}".encode()).digest(length)


def run(binary: Path, module_dir: str, alg: str, operation: str,
        key: bytes, iv: bytes, aad: bytes, data: bytes, directory: Path,
        succeeds: bool = True) -> bytes:
    src, dst = directory / "in.bin", directory / "out.bin"
    src.write_bytes(data)
    dst.unlink(missing_ok=True)
    cmd = [str(binary), module_dir, alg, operation, key.hex(),
           iv.hex() if iv else "-", aad.hex() if aad else "-",
           str(src), str(dst)]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if (result.returncode == 0) != succeeds:
        raise RuntimeError(f"{alg}/{operation}: unexpected exit status "
                           f"{result.returncode}\n{result.stdout}\n{result.stderr}")
    return dst.read_bytes() if succeeds else b""


def case(provider: Path, engine: Path, module_dir: str, alg: str,
         length: int, profile: int, directory: Path,
         check_integrity: bool) -> None:
    bash = alg.startswith("bash-")
    kwp = alg.startswith("belt-kwp")
    bits = 256 if bash else int(alg[-3:])
    key = material(bits // 8, profile, "key")
    iv = b"" if bash or kwp else material(16, profile, "iv")
    aad = b"" if kwp else material((0, 1, 16, 33)[length % 4], profile, "aad")
    data = material(length, profile, "data")
    legacy = run(engine, "-", alg, "enc", key, iv, aad, data, directory)
    modern = run(provider, module_dir, alg, "enc", key, iv, aad, data, directory)
    if modern != legacy:
        raise AssertionError(f"{alg}/{length}/{profile}: ciphertext or tag differs: "
                             f"legacy={legacy.hex()} provider={modern.hex()}")
    for binary, backend in ((provider, module_dir), (engine, "-")):
        recovered = run(binary, backend, alg, "dec", key, iv, aad, legacy, directory)
        if recovered != data:
            raise AssertionError(f"{alg}/{binary.name}: cross-decryption mismatch")
        if check_integrity:
            tampered = bytearray(legacy)
            tampered[-1] ^= 1
            run(binary, backend, alg, "dec", key, iv, aad,
                bytes(tampered), directory, succeeds=False)
            if aad:
                changed = bytearray(aad)
                changed[0] ^= 0x80
                run(binary, backend, alg, "dec", key, iv, bytes(changed),
                    legacy, directory, succeeds=False)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider-tool", type=Path, required=True)
    parser.add_argument("--engine-tool", type=Path, required=True)
    parser.add_argument("--provider-path", required=True)
    args = parser.parse_args()
    for binary in (args.provider_tool, args.engine_tool):
        if not binary.is_file():
            parser.error(f"missing interop executable: {binary}")
    algorithms = [f"belt-{mode}{bits}" for mode in ("dwp", "che", "kwp")
                  for bits in (128, 192, 256)] + ["bash-prg-ae2561"]
    total = 0
    with tempfile.TemporaryDirectory(prefix="bee2evp-extended-") as root:
        directory = Path(root)
        for algorithm in algorithms:
            # The historical engine cannot verify the tag after decrypting a
            # zero-length BASH message. Bee2 direct interop covers that case.
            if algorithm.startswith("belt-kwp"):
                lengths = (16, 17, 31, 32, 33, 64, 257)
            elif algorithm.startswith("bash-"):
                lengths = (1, 15, 16, 17, 31, 32, 33, 64, 257)
            else:
                lengths = (0, 1, 15, 16, 17, 31, 32, 33, 64, 257)
            for length in lengths:
                for profile in range(3):
                    try:
                        # Check authentication failures for each algorithm on
                        # random boundary inputs, not for every equivalent
                        # plaintext profile. Both decrypt directions are
                        # still checked for every case.
                        check_integrity = (profile == 2 and
                                           length in (0, 1, 15, 16, 17, 31, 33, 257))
                        case(args.provider_tool, args.engine_tool,
                             args.provider_path, algorithm, length, profile,
                             directory, check_integrity)
                    except Exception as exc:
                        raise RuntimeError(f"{algorithm}: length={length}, profile={profile}") from exc
                    total += 1
    print(f"[OK] {total} legacy engine AEAD/KWP interoperability cases")


if __name__ == "__main__":
    main()
