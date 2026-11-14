#!/usr/bin/env python3
"""Additional independent appendix vectors from STB 34.101.31 and 34.101.77.

These vectors are independent expected outputs, not provider-generated fixtures.
"""
from __future__ import annotations

import argparse
import shutil
import tempfile
from pathlib import Path

from openssl_kat import (
    BELT_IV,
    BELT_KEY_256,
    BELT_PT_384,
    BASH_X_192,
    OpenSSLRunner,
    assert_hex_eq,
    run_checked,
    to_bytes,
)


def check_belt(runner: OpenSSLRunner) -> None:
    h = to_bytes(BELT_PT_384)
    cases = (
        ("belt-bde256", BELT_IV, h,
         "E9CAB32D879CC50C10378EB07C10F263"
         "07257E2DBE2B854CBC9F38282D59D6A7"
         "7F952001C5D1244F53210A27C216D4BB", "A.24-1"),
        ("belt-sde256", BELT_IV, h,
         "1FCBB01852003D60B66024C508608BAA"
         "2C21AF1E884CF31154D3077D4643CF22"
         "49EB2F5A68E4BA019D90211A81D690D9", "A.24-2"),
        ("belt-kwp256", h[32:48].hex(), h[:32],
         "49A38EE108D6C742E52B774F00A6EF98"
         "B106CBD13EA4FB0680323051BC04DF76"
         "E487B055C69BCF541176169F1DC9F6C8", "A.21"),
    )
    for name, iv, plaintext, expected, appendix in cases:
        assert_hex_eq(
            f"STB 34.101.31 {appendix} {name}",
            runner.enc(name, BELT_KEY_256, iv, plaintext),
            expected,
        )

    # STB 34.101.45, appendix E.5: belt-PBKDF2 over HMAC-HBELT.
    # The password is ASCII, and the salt is the first eight bytes of H[192:].
    pbkdf_out = runner.tmp / "pbkdf_out.bin"
    run_checked(runner._cmd("kdf", [
        "-binary", "-out", str(pbkdf_out), "-keylen", "32",
        "-kdfopt", "pass:B194BAC80A08F53B",
        "-kdfopt", "hexsalt:BE32971343FC9A48",
        "-kdfopt", "iter:10000", "belt-pbkdf",
    ]))
    assert_hex_eq("STB 34.101.45 E.5 belt-pbkdf",
                  pbkdf_out.read_bytes(),
                  "3D331BBBB1FBBB40E4BF22F6CB9A689E"
                  "F13A77DC09ECF93291BFE42439A72E7D")

    assert_hex_eq("STB 34.101.31 A.23-1 belt-hash",
                  runner.dgst("belt-hash", h[:13]),
                  "ABEF9725D4C5A83597A367D14494CC25"
                  "42F20F659DDFECC961A3EC550CBA8C75")
    assert_hex_eq("STB 34.101.31 A.23-3 belt-hash",
                  runner.dgst("belt-hash", h[:48]),
                  "9D02EE446FB6A29FE5C982D4B13AF9D3"
                  "E90861BC4CEF27CF306BFB0B174A154A")


def check_bash(runner: OpenSSLRunner) -> None:
    x = to_bytes(BASH_X_192)
    cases = (
        ("bash256", 0,
         "114C3DFAE373D9BCBC3602D6386F2D6A"
         "2059BA1BF9048DBAA5146A6CB775709D", "A.3.1"),
        ("bash256", 127,
         "3D7F4EFA00E9BA33FEED259986567DCF"
         "5C6D12D51057A968F14F06CC0F905961", "A.3.2"),
        ("bash256", 135,
         "1393FA1B65172F2D18946AEAE576FA1C"
         "F54FDD354A0CB2974A997DC4865D3100", "A.3.4"),
        ("bash384", 95,
         "64334AF830D33F63E9ACDFA184E32522"
         "103FFF5C6860110A2CD369EDBC04387C"
         "501D8F92F749AE4DE15A8305C353D64D", "A.3.5"),
        ("bash384", 108,
         "FF763296571E2377E71A1538070CC0DE"
         "88888606F32EEE6B082788D246686B00"
         "FC05A17405C5517699DA44B7EF5F55AB", "A.3.7"),
        ("bash512", 63,
         "2A66C87C189C12E255239406123BDEDB"
         "F19955EAF0808B2AD705E249220845E2"
         "0F4786FB6765D0B5C48984B1B16556EF"
         "19EA8192B985E4233D9C09508D6339E7", "A.3.8"),
        ("bash512", 127,
         "526073918F97928E9D15508385F42F03"
         "ADE3211A23900A30131F8A1E3E1EE21C"
         "C09D13CFF6981101235D895746A4643F"
         "0AA62B0A7BC98A269E4507A257F0D4EE", "A.3.10"),
        ("bash512", 192,
         "8724C7FF8A2A83F22E38CB9763777B96"
         "A70ABA3444F214C763D93CD6D19FCFDE"
         "6C3D3931857C4FF6CCCD49BD99852FE9"
         "EAA7495ECCDD96B571E0EDCF47F89768", "A.3.11"),
    )
    for name, length, expected, appendix in cases:
        assert_hex_eq(
            f"STB 34.101.77 {appendix} {name}",
            runner.dgst(name, x[:length]),
            expected,
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider-path", required=True)
    parser.add_argument("--openssl", default="openssl")
    args = parser.parse_args()
    executable = shutil.which(args.openssl) if Path(args.openssl).name == args.openssl else args.openssl
    if not executable:
        parser.error("OpenSSL executable not found")
    with tempfile.TemporaryDirectory(prefix="bee2_stb_extended_") as tmp:
        runner = OpenSSLRunner(executable, Path(args.provider_path).resolve(), Path(tmp))
        check_belt(runner)
        check_bash(runner)


if __name__ == "__main__":
    main()
