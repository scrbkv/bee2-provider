/* Real BIGN ASN.1 seeds generated through public OpenSSL encoders. */
#include <openssl/core_names.h>
#include <openssl/encoder.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/crypto.h>
#include <stdio.h>

static int save(EVP_PKEY *key, const char *dir, const char *filename,
                unsigned char selector, const char *format,
                const char *structure, int encrypted)
{
    static const unsigned char password[] = "fuzz-password";
    unsigned int iterations = 2;
    OSSL_PARAM params[] = {
        OSSL_PARAM_uint("stb-pbkdf2-iterations", &iterations),
        OSSL_PARAM_END
    };
    OSSL_ENCODER_CTX *ctx = NULL;
    unsigned char *out = NULL;
    size_t len = 0;
    FILE *f = NULL;
    char path[1024];
    int ok = 0;

    if (snprintf(path, sizeof(path), "%s/%s", dir, filename) >= (int)sizeof(path))
        goto end;
    ctx = OSSL_ENCODER_CTX_new_for_pkey(key, OSSL_KEYMGMT_SELECT_KEYPAIR,
                                        format, structure, "provider=bee2");
    if (!ctx)
        goto end;
    if (encrypted && (!OSSL_ENCODER_CTX_set_cipher(ctx, "belt-kwp256", NULL) ||
                      !OSSL_ENCODER_CTX_set_params(ctx, params) ||
                      !OSSL_ENCODER_CTX_set_passphrase(ctx, password,
                                                       sizeof(password) - 1)))
        goto end;
    if (!OSSL_ENCODER_to_data(ctx, &out, &len) || !out || !len)
        goto end;
    f = fopen(path, "wb");
    if (!f || fwrite(&selector, 1, 1, f) != 1 ||
        fwrite(out, 1, len, f) != len)
        goto end;
    ok = 1;
end:
    if (f && fclose(f) != 0)
        ok = 0;
    OPENSSL_clear_free(out, len);
    OSSL_ENCODER_CTX_free(ctx);
    return ok;
}

int main(int argc, char **argv)
{
    OSSL_PROVIDER *def = NULL, *bee2 = NULL;
    EVP_PKEY_CTX *gen = NULL;
    EVP_PKEY *key = NULL;
    int ok = 0;

    if (argc != 3 || !OSSL_PROVIDER_set_default_search_path(NULL, argv[1]))
        return 2;
    def = OSSL_PROVIDER_load(NULL, "default");
    bee2 = OSSL_PROVIDER_load(NULL, "bee2_provider");
    gen = EVP_PKEY_CTX_new_from_name(NULL, "bign-256", "provider=bee2");
    if (!def || !bee2 || !gen ||
        EVP_PKEY_keygen_init(gen) <= 0 || EVP_PKEY_keygen(gen, &key) <= 0 ||
        !save(key, argv[2], "private.der", 0, "DER", "PrivateKeyInfo", 0) ||
        !save(key, argv[2], "public.der", 1, "DER", "SubjectPublicKeyInfo", 0) ||
        !save(key, argv[2], "encrypted.der", 2, "DER", "PrivateKeyInfo", 1) ||
        !save(key, argv[2], "private.pem", 3, "PEM", "PrivateKeyInfo", 0))
        goto end;
    ok = 1;
end:
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(gen);
    OSSL_PROVIDER_unload(bee2);
    OSSL_PROVIDER_unload(def);
    if (!ok)
        fputs("Failed to create BIGN ASN.1 fuzz corpus\n", stderr);
    return ok ? 0 : 1;
}
