#!/usr/bin/env python3
"""
OpenSSL CLI KAT tests for bee2_provider.

Vectors are taken from:
  - STB 34.101.31-2020, Appendix A (tables A.9/A.11/A.13/A.15/A.17/A.23/A.27)
  - STB 34.101.47-2012, Appendix B (tables B.1)
  - STB 34.101.77-2020, Appendix A (table A.3)
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable


# STB 34.101.31, Appendix A
BELT_PT_384 = (
    "B194BAC80A08F53B366D008E584A5DE4"
    "8504FA9D1BB6C7AC252E72C202FDCE0D"
    "5BE3D61217B96181FE6786AD716B890B"
)
BELT_PT_256 = (
    "B194BAC80A08F53B366D008E584A5DE4"
    "8504FA9D1BB6C7AC252E72C202FDCE0D"
)
BELT_KEY_256 = (
    "E9DEE72C8F0C0FA62DDB49F46F739647"
    "06075316ED247A3739CBA38303A98BF6"
)
BELT_IV = "BE32971343FC9A48A02A885F194B09A1"

BELT_ECB_384 = (
    "69CCA1C93557C9E3D66BC3E0FA88FA6E"
    "5F23102EF109710775017F73806DA9DC"
    "46FB2ED2CE771F26DCB5E5D1569F9AB0"
)
BELT_CBC_384 = (
    "10116EFAE6AD58EE14852E11DA1B8A74"
    "5CF2480E8D03F1C19492E53ED3A70F60"
    "657C1EE8C0E0AE5B58388BF8A68E3309"
)
BELT_CFB_384 = (
    "C31E490A90EFA374626CC99E4B7B8540"
    "A6E48685464A5A06849C9CA769A1B0AE"
    "55C2CC5939303EC832DD2FE16C8E5A1B"
)
BELT_CTR_384 = (
    "52C9AF96FF50F64435FC43DEF56BD797"
    "D5B5B1FF79FB41257AB9CDF6E63E81F8"
    "F00341473EAE409833622DE05213773A"
)
BELT_MAC_384 = "2DAB59771B4B16D0"
BELT_HASH_256 = "749E4C3653AECE5E48DB4761227742EB6DBE13F4A80F7BEFF1A9CF8D10EE7786"

# STB 34.101.31-2020, table A.27 (n=4 and n=6)
BELT_KEY_128 = "E9DEE72C8F0C0FA62DDB49F46F739647"
BELT_KEY_192 = "E9DEE72C8F0C0FA62DDB49F46F73964706075316ED247A37"
BELT_KEY_128_EXPANDED = (
    "E9DEE72C8F0C0FA62DDB49F46F739647"
    "E9DEE72C8F0C0FA62DDB49F46F739647"
)
BELT_KEY_192_EXPANDED = (
    "E9DEE72C8F0C0FA62DDB49F46F739647"
    "06075316ED247A374B09A17E8450BF66"
)

# STB 34.101.47, table B.1 (HMAC-HBELT)
HMAC_HBELT_KEY_29 = "E9DEE72C8F0C0FA62DDB49F46F73964706075316ED247A3739CBA38303"
HMAC_HBELT_KEY_32 = BELT_KEY_256
HMAC_HBELT_KEY_42 = BELT_KEY_256 + "92BD9B1CE5D141015445"
HMAC_HBELT_MSG_32 = "BE32971343FC9A48A02A885F194B09A17ECDA4D01544AF8CA58450BF66D2E88A"
HMAC_HBELT_B1_1 = "D4828E6312B08BB83C9FA6535A4635549E411FD11C0D8289359A1130E930676B"
HMAC_HBELT_B1_2 = "41FFE8645AEC0612E952D2CDF8DD508F3E4A1D9B53F6A1DB293B19FE76B1879F"
HMAC_HBELT_B1_3 = "7D01B84D2315C332277B3653D7EC64707EBA7CDFF7FF70077B1DECBD68F2A144"

# STB 34.101.77, table A.2 (X) and table A.3 (hashes over X[:n])
BASH_X_192 = (
    "B194BAC80A08F53B366D008E584A5DE4"
    "8504FA9D1BB6C7AC252E72C202FDCE0D"
    "5BE3D61217B96181FE6786AD716B890B"
    "5CB0C0FF33C356B835C405AED8E07F99"
    "E12BDC1AE28257EC703FCCF095EE8DF1"
    "C1AB76389FE678CAF7C6F860D5BB9C4F"
    "F33C657B637C306ADD4EA7799EB23D31"
    "3E98B56E27D3BCCF591E181F4C5AB793"
    "E9DEE72C8F0C0FA62DDB49F46F739647"
    "06075316ED247A3739CBA38303A98BF6"
    "92BD9B1CE5D141015445FBC95E4D0EF2"
    "682080AA227D642F2687F93490405511"
)
BASH256_N128 = "D7F428311254B8B2D00F7F9EEFBD8F3025FA87C4BABD1BDDBE87E35B7AC80DD6"
BASH384_N96 = (
    "D06EFBC16FD6C0880CBFC6A4E3D65AB101FA82826934190F"
    "AABEBFBFFEDE93B22B85EA72A7FB3147A133A5A8FEBD8320"
)
BASH512_N64 = (
    "07ABBF8580E7E5A321E9B940F667AE209E2952CEF557978AE743DB086BAB4885"
    "B708233C3F5541DF8AAFC3611482FDE498E58B3379A6622DAC2664C9C118A162"
)


def to_bytes(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)


def to_hex(data: bytes) -> str:
    return data.hex().upper()


def run_checked(cmd: list[str]) -> subprocess.CompletedProcess:
    p = subprocess.run(cmd, capture_output=True, text=False)
    if p.returncode != 0:
        stderr = p.stderr.decode("utf-8", errors="replace")
        stdout = p.stdout.decode("utf-8", errors="replace")
        raise RuntimeError(
            f"Command failed ({p.returncode}): {' '.join(cmd)}\n"
            f"stdout:\n{stdout}\n"
            f"stderr:\n{stderr}"
        )
    return p


class OpenSSLRunner:
    def __init__(self, openssl_bin: str, provider_path: Path, tmp: Path) -> None:
        self.openssl_bin = openssl_bin
        self.provider_path = provider_path
        self.tmp = tmp

    def _cmd(self, subcmd: str, args: list[str]) -> list[str]:
        return [
            self.openssl_bin,
            subcmd,
            "-propquery",
            "provider=bee2",
            "-provider-path",
            str(self.provider_path),
            "-provider",
            "bee2_provider",
            "-provider",
            "default",
            *args,
        ]

    def enc(self, cipher_name: str, key_hex: str, iv_hex: str | None, pt: bytes) -> bytes:
        in_file = self.tmp / "enc_in.bin"
        out_file = self.tmp / "enc_out.bin"
        in_file.write_bytes(pt)
        args = [
            f"-{cipher_name.lower()}",
            "-e",
            "-nosalt",
            "-nopad",
            "-K",
            key_hex,
        ]
        if iv_hex is not None:
            args += ["-iv", iv_hex]
        args += ["-in", str(in_file), "-out", str(out_file)]
        run_checked(self._cmd("enc", args))
        return out_file.read_bytes()

    def dgst(self, digest_name: str, data: bytes) -> bytes:
        in_file = self.tmp / "dgst_in.bin"
        out_file = self.tmp / "dgst_out.bin"
        in_file.write_bytes(data)
        args = [f"-{digest_name}", "-binary", "-out", str(out_file), str(in_file)]
        run_checked(self._cmd("dgst", args))
        return out_file.read_bytes()

    def mac_belt(self, key_hex: str, data: bytes,
                 algorithm: str = "belt-mac256") -> bytes:
        in_file = self.tmp / "mac_in.bin"
        out_file = self.tmp / "mac_out.bin"
        in_file.write_bytes(data)
        args = [
            "-binary",
            "-out",
            str(out_file),
            "-macopt",
            f"hexkey:{key_hex}",
            "-in",
            str(in_file),
            algorithm,
        ]
        run_checked(self._cmd("mac", args))
        return out_file.read_bytes()

    def mac_hmac(self, digest_name: str, key_hex: str, data: bytes) -> bytes:
        in_file = self.tmp / "hmac_in.bin"
        out_file = self.tmp / "hmac_out.bin"
        in_file.write_bytes(data)
        args = [
            "-binary",
            "-out",
            str(out_file),
            "-macopt",
            f"digest:{digest_name}",
            "-macopt",
            f"hexkey:{key_hex}",
            "-in",
            str(in_file),
            "belt-hmac",
        ]
        run_checked(self._cmd("mac", args))
        return out_file.read_bytes()


def assert_hex_eq(label: str, actual: bytes, expected_hex: str) -> None:
    actual_hex = to_hex(actual)
    expected = expected_hex.upper()
    if actual_hex != expected:
        raise AssertionError(
            f"{label} mismatch\n"
            f"expected: {expected}\n"
            f"actual:   {actual_hex}"
        )
    print(f"[OK] {label}")


def run_belt_block_vectors(runner: OpenSSLRunner) -> None:
    pt384 = to_bytes(BELT_PT_384)
    assert_hex_eq(
        "STB 34.101.31 A.9 belt-ecb256",
        runner.enc("belt-ecb256", BELT_KEY_256, None, pt384),
        BELT_ECB_384,
    )
    assert_hex_eq(
        "STB 34.101.31 A.11 belt-cbc256",
        runner.enc("belt-cbc256", BELT_KEY_256, BELT_IV, pt384),
        BELT_CBC_384,
    )
    assert_hex_eq(
        "STB 34.101.31 A.13 belt-cfb256",
        runner.enc("belt-cfb256", BELT_KEY_256, BELT_IV, pt384),
        BELT_CFB_384,
    )
    assert_hex_eq(
        "STB 34.101.31 A.15 belt-ctr256",
        runner.enc("belt-ctr256", BELT_KEY_256, BELT_IV, pt384),
        BELT_CTR_384,
    )


def run_belt_mac_vector(runner: OpenSSLRunner) -> None:
    pt384 = to_bytes(BELT_PT_384)
    assert_hex_eq(
        "STB 34.101.31 A.17 belt-mac256",
        runner.mac_belt(BELT_KEY_256, pt384),
        BELT_MAC_384,
    )


def run_belt_hash_vector(runner: OpenSSLRunner) -> None:
    pt256 = to_bytes(BELT_PT_256)
    assert_hex_eq(
        "STB 34.101.31 A.23 belt-hash",
        runner.dgst("belt-hash", pt256),
        BELT_HASH_256,
    )


def run_hmac_hbelt_vectors(runner: OpenSSLRunner) -> None:
    hmac_msg = to_bytes(HMAC_HBELT_MSG_32)
    assert_hex_eq(
        "STB 34.101.47 B.1-1 HMAC-HBELT",
        runner.mac_hmac("belt-hash", HMAC_HBELT_KEY_29, hmac_msg),
        HMAC_HBELT_B1_1,
    )
    assert_hex_eq(
        "STB 34.101.47 B.1-2 HMAC-HBELT",
        runner.mac_hmac("belt-hash", HMAC_HBELT_KEY_32, hmac_msg),
        HMAC_HBELT_B1_2,
    )
    assert_hex_eq(
        "STB 34.101.47 B.1-3 HMAC-HBELT",
        runner.mac_hmac("belt-hash", HMAC_HBELT_KEY_42, hmac_msg),
        HMAC_HBELT_B1_3,
    )


def run_belt_keyexpand_vectors(runner: OpenSSLRunner) -> None:
    # STB 34.101.31-2020 8.1.2 / A.27 defines the expanded keys.
    # CBC/ECB/CFB/CTR should use the identical 256-bit key schedule.
    # This checks the EVP integration; direct normative expansion is tested
    # independently in belt_keyexpand_stb.c.
    pt384 = to_bytes(BELT_PT_384)
    for mode in ("ecb", "cbc", "cfb", "ctr"):
        iv = None if mode == "ecb" else BELT_IV
        for bits, original, expanded in (
            (128, BELT_KEY_128, BELT_KEY_128_EXPANDED),
            (192, BELT_KEY_192, BELT_KEY_192_EXPANDED),
        ):
            actual = runner.enc(f"belt-{mode}{bits}", original, iv, pt384)
            expected = runner.enc(f"belt-{mode}256", expanded, iv, pt384)
            assert_hex_eq(
                f"STB 34.101.31-2020 A.27 keyexpand -> belt-{mode}{bits}",
                actual, to_hex(expected),
            )


    # STB 34.101.31 A.27 reduced BELT keys are equivalent to
    # their defined 32-byte expansions for BELT-MAC as well.
    for bits, original, expanded in (
        (128, BELT_KEY_128, BELT_KEY_128_EXPANDED),
        (192, BELT_KEY_192, BELT_KEY_192_EXPANDED),
    ):
        expected = runner.mac_belt(expanded, pt384)
        actual = runner.mac_belt(original, pt384, f"belt-mac{bits}")
        assert_hex_eq(
            f"STB 34.101.31 A.27 BELT-MAC-{bits} expansion",
            actual, to_hex(expected),
        )


def run_bash_hash_vectors(runner: OpenSSLRunner) -> None:
    x = to_bytes(BASH_X_192)
    assert_hex_eq(
        "STB 34.101.77 A.3 bash256 n=128",
        runner.dgst("bash256", x[:128]),
        BASH256_N128,
    )
    assert_hex_eq(
        "STB 34.101.77 A.3 bash384 n=96",
        runner.dgst("bash384", x[:96]),
        BASH384_N96,
    )
    assert_hex_eq(
        "STB 34.101.77 A.3 bash512 n=64",
        runner.dgst("bash512", x[:64]),
        BASH512_N64,
    )


GROUPS: tuple[tuple[str, Callable[[OpenSSLRunner], None]], ...] = (
    ("belt-block", run_belt_block_vectors),
    ("belt-mac", run_belt_mac_vector),
    ("belt-hash", run_belt_hash_vector),
    ("hmac-hbelt", run_hmac_hbelt_vectors),
    ("belt-keyexpand", run_belt_keyexpand_vectors),
    ("bash-hash", run_bash_hash_vectors),
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run OpenSSL CLI KAT tests for bee2_provider")
    parser.add_argument("--provider-path", required=True, help="Directory containing bee2_provider module")
    parser.add_argument("--openssl", default="openssl", help="Path to openssl executable")
    parser.add_argument(
        "--group",
        action="append",
        dest="groups",
        help="Algorithm group to run (can be used multiple times). "
             "If omitted, all groups are run.",
    )
    args = parser.parse_args()

    openssl_bin = shutil.which(args.openssl) if Path(args.openssl).name == args.openssl else args.openssl
    if not openssl_bin:
        print(f"openssl executable not found: {args.openssl}", file=sys.stderr)
        return 2

    provider_path = Path(args.provider_path).resolve()
    if not provider_path.exists():
        print(f"provider path does not exist: {provider_path}", file=sys.stderr)
        return 2

    group_map = {name: fn for name, fn in GROUPS}
    selected_groups = args.groups if args.groups else [name for name, _ in GROUPS]
    unknown_groups = [name for name in selected_groups if name not in group_map]
    if unknown_groups:
        print(
            "unknown --group values: "
            + ", ".join(unknown_groups)
            + "\navailable groups: "
            + ", ".join(name for name, _ in GROUPS),
            file=sys.stderr,
        )
        return 2

    with tempfile.TemporaryDirectory(prefix="bee2_openssl_kat_") as td:
        runner = OpenSSLRunner(openssl_bin, provider_path, Path(td))
        for group in selected_groups:
            print(f"[RUN] {group}")
            group_map[group](runner)
            print(f"[OK] group {group}")

    print("[OK] Selected OpenSSL KAT groups passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as e:
        print(f"[FAIL] {e}", file=sys.stderr)
        raise
