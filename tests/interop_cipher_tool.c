/* EVP adapter shared by OpenSSL 1.1.1 bee2evp and OpenSSL 3 provider.
 * The output is ciphertext || tag; KWP has no separate tag.
 */
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#if OPENSSL_VERSION_NUMBER < 0x30000000L
# include <openssl/engine.h>
#else
# include <openssl/provider.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LIMIT 1048576

static int digit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int decode(const char *s, unsigned char *out, size_t cap, size_t *n)
{
    size_t i, len;
    if (strcmp(s, "-") == 0) {
        *n = 0;
        return 1;
    }
    len = strlen(s);
    if (len % 2 != 0 || len / 2 > cap) return 0;
    for (i = 0; i < len / 2; ++i) {
        int hi = digit(s[2 * i]), lo = digit(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    *n = len / 2;
    return 1;
}

static int read_file(const char *path, unsigned char *buf, size_t *size)
{
    FILE *f = fopen(path, "rb");
    size_t n;
    if (f == NULL) return 0;
    n = fread(buf, 1, LIMIT + 1, f);
    if (ferror(f) || n > LIMIT || fgetc(f) != EOF) {
        fclose(f);
        return 0;
    }
    fclose(f);
    *size = n;
    return 1;
}

static int write_file(const char *path, const unsigned char *buf, size_t size)
{
    FILE *f = fopen(path, "wb");
    int ok;
    if (f == NULL) return 0;
    ok = fwrite(buf, 1, size, f) == size;
    return fclose(f) == 0 && ok;
}

int main(int argc, char **argv)
{
    unsigned char key[64], iv[64], aad[1024];
    unsigned char *input = NULL, *output = NULL;
    size_t keylen = 0, ivlen = 0, aadlen = 0, inlen = 0, ctlen, taglen;
    int enc, is_aead, is_bash, len = 0, last = 0, ok = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    ENGINE *engine = NULL;
#else
    EVP_CIPHER *fetched = NULL;
    OSSL_PROVIDER *def = NULL, *bee2 = NULL;
#endif

    if (argc != 9 || (strcmp(argv[3], "enc") != 0 && strcmp(argv[3], "dec") != 0)) {
        fprintf(stderr, "usage: cipher-tool <provider-path|-> <algorithm> <enc|dec> "
                "<hex-key> <hex-iv|-> <hex-aad|-> <in> <out>\n");
        return 2;
    }
    enc = strcmp(argv[3], "enc") == 0;
    is_bash = strstr(argv[2], "bash-prg-ae") != NULL;
    is_aead = is_bash || strstr(argv[2], "belt-che") != NULL ||
              strstr(argv[2], "belt-dwp") != NULL;
    taglen = is_bash ? 32 : (is_aead ? 8 : 0);
    if (!decode(argv[4], key, sizeof(key), &keylen) ||
        !decode(argv[5], iv, sizeof(iv), &ivlen) ||
        !decode(argv[6], aad, sizeof(aad), &aadlen))
        return 2;
    if (keylen != 16 && keylen != 24 && keylen != 32) return 2;
    if (is_bash && (ivlen != 0 || keylen != 32)) return 2;
    if (!is_aead && aadlen) return 2;
    if (!is_bash && is_aead && ivlen != 16) return 2;
    if (!is_aead && ivlen != 0) return 2;
    input = malloc(LIMIT + 1);
    output = malloc(LIMIT + 128);
    if (!input || !output || !read_file(argv[7], input, &inlen)) goto done;
    if (!enc && inlen < taglen) goto done;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    ENGINE_load_dynamic();
    engine = ENGINE_by_id("bee2evp");
    if (engine == NULL || !ENGINE_init(engine) ||
        !ENGINE_set_default_ciphers(engine))
        goto done;
    cipher = ENGINE_get_cipher(engine, OBJ_sn2nid(argv[2]));
#else
    if (!OSSL_PROVIDER_set_default_search_path(NULL, argv[1])) goto done;
    def = OSSL_PROVIDER_load(NULL, "default");
    bee2 = OSSL_PROVIDER_load(NULL, "bee2_provider");
    if (!def || !bee2) goto done;
    fetched = EVP_CIPHER_fetch(NULL, argv[2], "provider=bee2");
    cipher = fetched;
#endif
    if (cipher == NULL) goto done;
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL || !EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, enc))
        goto done;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (is_bash && !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 0, NULL))
        goto done;
#endif
    if (!EVP_CipherInit_ex(ctx, NULL, NULL, key, ivlen ? iv : NULL, enc))
        goto done;
    if (aadlen && !EVP_CipherUpdate(ctx, NULL, &len, aad, (int)aadlen))
        goto done;
    ctlen = inlen;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (is_aead && !enc) {
        ctlen -= taglen;
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)taglen,
                                 input + ctlen))
            goto done;
    }
#endif
    if (!EVP_CipherUpdate(ctx, output, &len, input, (int)ctlen)) goto done;
    if (len < 0 || (size_t)len > LIMIT + 64) goto done;
    if (!EVP_CipherFinal_ex(ctx, output + len, &last)) goto done;
    if (last < 0 || (size_t)(len + last) > LIMIT + 64) goto done;
    ctlen = (size_t)(len + last);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (is_aead && enc) {
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, (int)taglen,
                                 output + ctlen))
            goto done;
        ctlen += taglen;
    }
#endif
    ok = write_file(argv[8], output, ctlen);
done:
    if (!ok) {
        fprintf(stderr, "cipher adapter failed: %s (%s)\n", argv[2], argv[3]);
        ERR_print_errors_fp(stderr);
    }
    EVP_CIPHER_CTX_free(ctx);
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    if (engine != NULL) {
        ENGINE_finish(engine);
        ENGINE_free(engine);
    }
#else
    EVP_CIPHER_free(fetched);
    OSSL_PROVIDER_unload(bee2);
    OSSL_PROVIDER_unload(def);
#endif
    if (input) { OPENSSL_cleanse(input, LIMIT + 1); free(input); }
    if (output) { OPENSSL_cleanse(output, LIMIT + 128); free(output); }
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(iv, sizeof(iv));
    return ok ? 0 : 1;
}
