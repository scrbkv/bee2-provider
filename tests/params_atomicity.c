/* A rejected parameter batch must not change the working MAC/KDF context. */
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/provider.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int check_hmac(void)
{
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "belt-hmac", "provider=bee2");
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    char bash[] = "bash512", belt[] = "belt-hash";
    size_t wide = 64;
    OSSL_PARAM good[] = {
        OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, bash, sizeof(bash)),
        OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, &wide),
        OSSL_PARAM_END
    };
    OSSL_PARAM bad[] = {
        OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, belt, sizeof(belt)),
        OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, &wide),
        OSSL_PARAM_END
    };
    int ok = ctx != NULL && EVP_MAC_CTX_set_params(ctx, good) > 0 &&
             EVP_MAC_CTX_get_mac_size(ctx) == wide &&
             EVP_MAC_CTX_set_params(ctx, bad) <= 0 &&
             EVP_MAC_CTX_get_mac_size(ctx) == wide;

    if (!ok)
        fprintf(stderr, "HMAC rejected parameters corrupted context\n");
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return ok;
}

static int check_pbkdf(void)
{
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "belt-pbkdf", "provider=bee2");
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    unsigned char original[32], again[32];
    char password[] = "stb-password", other[] = "changed-password";
    unsigned char salt[] = {0x0a, 0x11, 0x28, 0x37, 0x46, 0x55, 0x64, 0x73};
    uint64_t iterations = 10000, invalid = 0;
    OSSL_PARAM good[] = {
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_PASSWORD, password, sizeof(password) - 1),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, salt, sizeof(salt)),
        OSSL_PARAM_uint64(OSSL_KDF_PARAM_ITER, &iterations),
        OSSL_PARAM_END
    };
    OSSL_PARAM bad[] = {
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_PASSWORD, other, sizeof(other) - 1),
        OSSL_PARAM_uint64(OSSL_KDF_PARAM_ITER, &invalid),
        OSSL_PARAM_END
    };
    int ok = ctx != NULL && EVP_KDF_CTX_set_params(ctx, good) > 0 &&
             EVP_KDF_derive(ctx, original, sizeof(original), NULL) > 0 &&
             EVP_KDF_CTX_set_params(ctx, bad) <= 0 &&
             EVP_KDF_derive(ctx, again, sizeof(again), NULL) > 0 &&
             CRYPTO_memcmp(original, again, sizeof(original)) == 0;

    if (!ok)
        fprintf(stderr, "BELT PBKDF rejected parameters corrupted context\n");
    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(kdf);
    OPENSSL_cleanse(original, sizeof(original));
    OPENSSL_cleanse(again, sizeof(again));
    return ok;
}

static int check_bign_digest(void)
{
    EVP_PKEY_CTX *gen = NULL, *sign = NULL;
    EVP_PKEY *key = NULL;
    char belt[] = "belt-hash", sha[] = "SHA1";
    char digest[64] = {0};
    OSSL_PARAM good[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, belt, sizeof(belt)),
        OSSL_PARAM_END
    };
    OSSL_PARAM bad[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, sha, sizeof(sha)),
        OSSL_PARAM_END
    };
    OSSL_PARAM query[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, digest, sizeof(digest)),
        OSSL_PARAM_END
    };
    int ok = 0;

    gen = EVP_PKEY_CTX_new_from_name(NULL, "bign-256", "provider=bee2");
    if (gen == NULL || EVP_PKEY_keygen_init(gen) <= 0 ||
        EVP_PKEY_keygen(gen, &key) <= 0)
        goto end;
    sign = EVP_PKEY_CTX_new_from_pkey(NULL, key, "provider=bee2");
    if (sign == NULL || EVP_PKEY_sign_init(sign) <= 0 ||
        EVP_PKEY_CTX_set_params(sign, good) <= 0 ||
        EVP_PKEY_CTX_set_params(sign, bad) > 0 ||
        EVP_PKEY_CTX_get_params(sign, query) <= 0 ||
        strcmp(digest, belt) != 0)
        goto end;
    ok = 1;
end:
    if (!ok)
        fprintf(stderr, "BIGN rejected digest changed the signature context\n");
    EVP_PKEY_CTX_free(sign);
    EVP_PKEY_CTX_free(gen);
    EVP_PKEY_free(key);
    return ok;
}

int main(int argc, char **argv)
{
    OSSL_PROVIDER *def = NULL, *bee2 = NULL;
    int ok = 0;

    if (argc != 2)
        return 2;
    if (!OSSL_PROVIDER_set_default_search_path(NULL, argv[1]))
        return 1;
    def = OSSL_PROVIDER_load(NULL, "default");
    bee2 = OSSL_PROVIDER_load(NULL, "bee2_provider");
    if (def == NULL || bee2 == NULL)
        goto end;
    ok = check_hmac() && check_pbkdf() && check_bign_digest();
end:
    OSSL_PROVIDER_unload(bee2);
    OSSL_PROVIDER_unload(def);
    return ok ? 0 : 1;
}
