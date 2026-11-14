#!/usr/bin/env bash
# Build a specific OpenSSL release for an isolated provider test job.
set -euo pipefail

: "${OPENSSL_TAG:?OpenSSL release tag is required}"
: "${OPENSSL_COMMIT:?Expected OpenSSL commit is required}"
: "${OPENSSL_PREFIX:?Installation prefix is required}"

source_dir="${RUNNER_TEMP:-/tmp}/openssl-src"
mkdir -p "$(dirname "$source_dir")" "$OPENSSL_PREFIX"
git clone --depth 1 --branch "$OPENSSL_TAG" \
    https://github.com/openssl/openssl.git "$source_dir"
actual_commit="$(git -C "$source_dir" rev-parse HEAD)"
if [[ "$actual_commit" != "$OPENSSL_COMMIT" ]]; then
    printf 'OpenSSL tag mismatch: expected %s, got %s\n' \
        "$OPENSSL_COMMIT" "$actual_commit" >&2
    exit 1
fi

cd "$source_dir"
./Configure --prefix="$OPENSSL_PREFIX" \
    --openssldir="$OPENSSL_PREFIX/ssl" --libdir=lib shared no-tests
make -j 4
make install_sw
export LD_LIBRARY_PATH="$OPENSSL_PREFIX/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
"$OPENSSL_PREFIX/bin/openssl" version
