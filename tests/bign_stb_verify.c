/* STB 34.101.45 Appendix G.1-G.3: BIGN key, DH and signatures. */
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>

static int from_hex(unsigned char *dst, size_t n, const char *hex)
{
    size_t i;
    if (strlen(hex) != 2 * n)
        return 0;
    for (i = 0; i < n; ++i) {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%2x", &byte) != 1)
            return 0;
        dst[i] = (unsigned char)byte;
    }
    return 1;
}

static int run_vector(EVP_PKEY *key, const char *hash_hex, const char *sig_hex)
{
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char hash[32], signature[48];
    int ok = 0;

    if (!from_hex(hash, sizeof(hash), hash_hex) ||
        !from_hex(signature, sizeof(signature), sig_hex))
        return 0;
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, "provider=bee2");
    if (ctx == NULL || EVP_PKEY_verify_init(ctx) <= 0 ||
        EVP_PKEY_verify(ctx, signature, sizeof(signature), hash, sizeof(hash)) <= 0)
        goto end;
    signature[0] ^= 1u;
    if (EVP_PKEY_verify(ctx, signature, sizeof(signature), hash, sizeof(hash)) > 0)
        goto end;
    signature[0] ^= 1u;
    hash[0] ^= 1u;
    if (EVP_PKEY_verify(ctx, signature, sizeof(signature), hash, sizeof(hash)) > 0)
        goto end;
    ok = 1;

end:
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_cleanse(hash, sizeof(hash));
    return ok;
}

static int check_dh(const unsigned char expected_public[64])
{
    static const char *const private_hex =
        "1F66B5B84B7339674533F0329C74F218"
        "34281FED0732429E0C79235FC273E269";
    static const char *const generator_y_hex =
        "936A510418CF291E52F608C466399178"
        "5D83D651A3C9E45C9FD616FB3CFCF76B";
    unsigned char private_bytes[32], generator[64] = {0}, shared[64];
    OSSL_PARAM private_params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
                                private_bytes, sizeof(private_bytes)),
        OSSL_PARAM_END
    };
    OSSL_PARAM public_params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                generator, sizeof(generator)),
        OSSL_PARAM_END
    };
    EVP_PKEY_CTX *import_ctx = NULL, *derive_ctx = NULL;
    EVP_PKEY *private_key = NULL, *base_point = NULL;
    size_t shared_len = sizeof(shared);
    int ok = 0;

    if (!from_hex(private_bytes, sizeof(private_bytes), private_hex) ||
        !from_hex(generator + 32, 32, generator_y_hex))
        goto end;
    import_ctx = EVP_PKEY_CTX_new_from_name(NULL, "bign-256", "provider=bee2");
    if (import_ctx == NULL || EVP_PKEY_fromdata_init(import_ctx) <= 0 ||
        EVP_PKEY_fromdata(import_ctx, &private_key, EVP_PKEY_KEYPAIR,
                          private_params) <= 0 ||
        EVP_PKEY_fromdata(import_ctx, &base_point, EVP_PKEY_PUBLIC_KEY,
                          public_params) <= 0)
        goto end;
    derive_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, private_key, "provider=bee2");
    if (derive_ctx == NULL || EVP_PKEY_derive_init(derive_ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(derive_ctx, base_point) <= 0 ||
        EVP_PKEY_derive(derive_ctx, shared, &shared_len) <= 0 ||
        shared_len != sizeof(shared) ||
        CRYPTO_memcmp(shared, expected_public, shared_len) != 0)
        goto end;
    ok = 1;

end:
    EVP_PKEY_CTX_free(derive_ctx);
    EVP_PKEY_CTX_free(import_ctx);
    EVP_PKEY_free(private_key);
    EVP_PKEY_free(base_point);
    OPENSSL_cleanse(private_bytes, sizeof(private_bytes));
    OPENSSL_cleanse(shared, sizeof(shared));
    return ok;
}

int main(int argc, char **argv)
{
    static const char *const pub_hex =
        "BD1A5650179D79E03FCEE49D4C2BD5DD"
        "F54CE46D0CF11E4FF87BF7A890857FD0"
        "7AC6A60361E8C8173491686D461B2826"
        "190C2EDA5909054A9AB84D2AB9D99A90";
    static const char *const hash_g2 =
        "ABEF9725D4C5A83597A367D14494CC25"
        "42F20F659DDFECC961A3EC550CBA8C75";
    static const char *const sig_g2 =
        "E36B7F0377AE4C524027C387FADF1B20"
        "CE72F1530B71F2B5FD3A8C584FE2E1AE"
        "D20082E30C8AF65011F4FB54649DFD3D";
    static const char *const hash_g3 =
        "9D02EE446FB6A29FE5C982D4B13AF9D3"
        "E90861BC4CEF27CF306BFB0B174A154A";
    static const char *const sig_g3 =
        "47A63C8B9C936E94B5FAB3D9CBD78366"
        "290F3210E163EEC8DB4E921E8479D413"
        "8F112CC23E6DCE65EC5FF21DF4231C28";
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    OSSL_PROVIDER *def = NULL, *bee2 = NULL;
    unsigned char pub[64];
    OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, pub, sizeof(pub)),
        OSSL_PARAM_END
    };
    int ok = 0;

    if (argc != 2)
        return 2;
    if (!OSSL_PROVIDER_set_default_search_path(NULL, argv[1]))
        return 1;
    def = OSSL_PROVIDER_load(NULL, "default");
    bee2 = OSSL_PROVIDER_load(NULL, "bee2_provider");
    if (def == NULL || bee2 == NULL || !from_hex(pub, sizeof(pub), pub_hex))
        goto end;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "bign-256", "provider=bee2");
    if (ctx == NULL || EVP_PKEY_fromdata_init(ctx) <= 0 ||
        EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_PUBLIC_KEY, params) <= 0 ||
        !run_vector(key, hash_g2, sig_g2) ||
        !run_vector(key, hash_g3, sig_g3) ||
        !check_dh(pub))
        goto end;
    ok = 1;

end:
    if (!ok)
        fprintf(stderr, "STB BIGN-256 Appendix G known-answer verification failed\n");
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PROVIDER_unload(bee2);
    OSSL_PROVIDER_unload(def);
    return ok ? 0 : 1;
}
