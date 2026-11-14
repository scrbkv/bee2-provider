/* CFB and CTR are stream-like EVP ciphers, even for one-byte updates. */
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>

#define MESSAGE_SIZE 83

static int test_cipher(const char *name, size_t keylen)
{
    static const size_t parts[] = {1, 2, 5, 7, 11, 3, 17, 8, 29};
    unsigned char key[32] = {0};
    unsigned char iv[16] = {0};
    unsigned char input[MESSAGE_SIZE];
    unsigned char whole[MESSAGE_SIZE + 16];
    unsigned char chunks[MESSAGE_SIZE + 16];
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    int outlen, finlen, ok = 0;
    size_t i, offset, written;

    for (i = 0; i < MESSAGE_SIZE; ++i)
        input[i] = (unsigned char)(i * 17 + 9);
    for (i = 0; i < keylen; ++i)
        key[i] = (unsigned char)(i + 1);

    cipher = EVP_CIPHER_fetch(NULL, name, "provider=bee2");
    ctx = EVP_CIPHER_CTX_new();
    if (cipher == NULL || ctx == NULL)
        goto end;

    /* EVP's block_size describes Update() granularity, not BELT's block. */
    if (EVP_CIPHER_get_block_size(cipher) != 1) {
        fprintf(stderr, "%s: EVP block size must be 1 for streaming\n", name);
        goto end;
    }
    if (!EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL)
            || !EVP_EncryptUpdate(ctx, whole, &outlen, input, MESSAGE_SIZE)
            || outlen != MESSAGE_SIZE
            || !EVP_EncryptFinal_ex(ctx, whole + outlen, &finlen)
            || finlen != 0)
        goto end;

    if (!EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL))
        goto end;
    offset = written = 0;
    for (i = 0; i < sizeof(parts) / sizeof(parts[0]); ++i) {
        size_t part = parts[i];

        if (part > MESSAGE_SIZE - offset)
            part = MESSAGE_SIZE - offset;
        if (!EVP_EncryptUpdate(ctx, chunks + written, &outlen,
                               input + offset, (int)part)
                || outlen != (int)part) {
            fprintf(stderr, "%s: %zu-byte update was not streamed\n", name, part);
            goto end;
        }
        offset += part;
        written += (size_t)outlen;
    }
    if (offset != MESSAGE_SIZE
            || !EVP_EncryptFinal_ex(ctx, chunks + written, &finlen)
            || finlen != 0
            || CRYPTO_memcmp(whole, chunks, MESSAGE_SIZE) != 0) {
        fprintf(stderr, "%s: split/whole encryption mismatch\n", name);
        goto end;
    }
    ok = 1;

 end:
    if (!ok)
        fprintf(stderr, "%s: EVP streaming contract failed\n", name);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(chunks, sizeof(chunks));
    OPENSSL_cleanse(whole, sizeof(whole));
    return ok;
}

int main(int argc, char **argv)
{
    static const char *const names[] = {
        "belt-cfb128", "belt-cfb192", "belt-cfb256",
        "belt-ctr128", "belt-ctr192", "belt-ctr256"
    };
    OSSL_PROVIDER *defprov = NULL, *bee2prov = NULL;
    size_t i;
    int ok = 1;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <provider-module-directory>\n", argv[0]);
        return 2;
    }
    if (!OSSL_PROVIDER_set_default_search_path(NULL, argv[1]))
        return 1;
    defprov = OSSL_PROVIDER_load(NULL, "default");
    bee2prov = OSSL_PROVIDER_load(NULL, "bee2_provider");
    if (defprov == NULL || bee2prov == NULL) {
        ok = 0;
        goto end;
    }
    for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        if (!test_cipher(names[i], 16 + (i % 3) * 8))
            ok = 0;
    }

 end:
    OSSL_PROVIDER_unload(bee2prov);
    OSSL_PROVIDER_unload(defprov);
    return ok ? 0 : 1;
}
