# Testing Bee2 Provider

The public test suite lives in `tests/`. It runs against the OpenSSL
installation selected at CMake configuration time, not necessarily the system
installation. The tested OpenSSL executable and `libcrypto` must belong to the
same OpenSSL build.

## Standard build

Clone the GitHub repository with its Bee2 submodule:

```sh
git clone --recurse-submodules https://github.com/scrbkv/bee2-provider.git
cd bee2-provider
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
    -DBEE2_PROVIDER_BUILD_TESTS=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

The tests use public OpenSSL APIs. They exercise known-answer vectors,
provider exports, cipher round trips and negative authentication checks,
BIGN key operations, BRNG and independent library contexts.

When using a custom OpenSSL, pass its installation prefix and executable:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
    -DBEE2_PROVIDER_BUILD_TESTS=ON \
    -DOPENSSL_ROOT_DIR=/opt/openssl \
    -DBEE2_OPENSSL_EXECUTABLE=/opt/openssl/bin/openssl
```

Depending on how OpenSSL was built, the runtime loader may also need the
installation's `lib` directory in `LD_LIBRARY_PATH`, or an equivalent dynamic
library path for the platform. The CI jobs explicitly set this path.

## Optional bee2evp interoperability tests

These require a separate OpenSSL installation with the `bee2evp` engine
installed and working. Do not enable them without providing that environment.

```sh
cmake -S . -B build-interop -DBEE2_PROVIDER_BUILD_TESTS=ON \
    -DBEE2_PROVIDER_ENABLE_INTEROP=ON \
    -DBEE2_INTEROP_PROVIDER_OPENSSL=/opt/openssl/bin/openssl \
    -DBEE2_INTEROP_BEE2EVP_OPENSSL=/opt/bee2evp/bin/openssl \
    -DBEE2_INTEROP_BEE2EVP_LD_LIBRARY_PATH=/opt/bee2evp/lib \
    -DBEE2_INTEROP_BEE2EVP_OPENSSL_CONF=/opt/bee2evp/openssl.cnf
cmake --build build-interop --parallel
ctest --test-dir build-interop -L interop --output-on-failure
```

`bee2evp` tests are not a replacement for independent known-answer vectors:
comparison between two implementations cannot establish correctness when
both implement the same mistake.

## EVP and BIGN validation tests

The standard CTest run includes `bee2_evp_streaming_contract`, six
`bee2_evp_padding_*` cases, `bee2_bign_public_check` and
`bee2_bign_asn1_negative`. These cover CFB/CTR streaming, ECB/CBC PKCS#7
padding and unpadded operation, modified ciphertext rejection, malformed
PKCS#8 and SPKI structures, and public-key validation. The ASN.1 key
reader rejects inputs exceeding 1 MiB. Run them separately with:

```sh
ctest --test-dir build -L regression --output-on-failure
```

## Test categories and limitations

The test suite contains known-answer and end-to-end tests. A test name
containing `_kat` does not by itself guarantee an independent reference vector.
The suite does not yet establish complete fuzz coverage of ASN.1, all BIGN
validation paths, multithreaded calls, every size boundary, or memory safety
under malicious input. Fuzzing and additional property-based tests are release
blockers, not optional polish.
