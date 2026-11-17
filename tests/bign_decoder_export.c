/* Exercise DECODER_EXPORT_OBJECT with a valid provider-native BIGN key.
 * Most decoder clients take the object-reference path through keymgmt.
 */
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    const unsigned char *private_key;
    unsigned char public_key[64];
    unsigned int callbacks;
} expected_key_t;

static int has_name(const char *aliases, const char *name)
{
    const char *s = aliases;
    size_t length = strlen(name);

    while (*s) {
        const char *end = strchr(s, ':');
        size_t part = end ? (size_t)(end - s) : strlen(s);

        if (part == length && OPENSSL_strncasecmp(s, name, length) == 0)
            return 1;
        if (!end)
            break;
        s = end + 1;
    }
    return 0;
}

static int check_exported(const OSSL_PARAM params[], void *arg)
{
    expected_key_t *expected = arg;
    const OSSL_PARAM *private_param =
        OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    const OSSL_PARAM *public_param =
        OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    const void *private_key = NULL, *public_key = NULL;
    size_t private_len = 0, public_len = 0;

    if (!private_param || !public_param ||
        !OSSL_PARAM_get_octet_string_ptr(private_param, &private_key, &private_len) ||
        !OSSL_PARAM_get_octet_string_ptr(public_param, &public_key, &public_len) ||
        private_len != 32 || public_len != sizeof(expected->public_key) ||
        CRYPTO_memcmp(private_key, expected->private_key, private_len) != 0 ||
        CRYPTO_memcmp(public_key, expected->public_key, public_len) != 0)
        return 0;
    expected->callbacks++;
    return 1;
}

/* EVP keygen always requests a keypair. Direct dispatch exercises the
 * public-only and private-only selections promised by KEYMGMT_GEN. */
static int check_generation_selections(
    OSSL_PROVIDER *provider,
    OSSL_FUNC_keymgmt_gen_init_fn *gen_init,
    OSSL_FUNC_keymgmt_gen_fn *generate,
    OSSL_FUNC_keymgmt_gen_cleanup_fn *gen_cleanup,
    OSSL_FUNC_keymgmt_free_fn *key_free,
    OSSL_FUNC_keymgmt_has_fn *key_has,
    OSSL_FUNC_keymgmt_validate_fn *key_validate,
    OSSL_FUNC_keymgmt_get_params_fn *key_get_params,
    OSSL_FUNC_keymgmt_dup_fn *key_dup)
{
    static const int selections[] = {
        OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
        OSSL_KEYMGMT_SELECT_PRIVATE_KEY
    };
    unsigned char public_bytes[64], copied_bytes[64], private_bytes[32];
    size_t i;
    int ok = 0;

    for (i = 0; i < sizeof(selections) / sizeof(selections[0]); ++i) {
        const int selection = selections[i];
        const int other = selection == OSSL_KEYMGMT_SELECT_PUBLIC_KEY ?
                          OSSL_KEYMGMT_SELECT_PRIVATE_KEY : OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
        OSSL_PARAM public_params[] = {
            OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                    public_bytes, sizeof(public_bytes)),
            OSSL_PARAM_END
        };
        OSSL_PARAM private_params[] = {
            OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
                                    private_bytes, sizeof(private_bytes)),
            OSSL_PARAM_END
        };
        OSSL_PARAM copied_params[] = {
            OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                    copied_bytes, sizeof(copied_bytes)),
            OSSL_PARAM_END
        };
        void *genctx = gen_init(OSSL_PROVIDER_get0_provider_ctx(provider), selection, NULL);
        void *native = NULL, *public_copy = NULL;
        int valid = 0;

        if (genctx != NULL)
            native = generate(genctx, NULL, NULL);
        if (native != NULL &&
            key_has(native, selection) == 1 &&
            key_has(native, other) == 0 &&
            key_validate(native, selection, OSSL_KEYMGMT_VALIDATE_FULL_CHECK) == 1 &&
            key_get_params(native, public_params) == 1) {
            if (selection == OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
                valid = key_get_params(native, private_params) == 0;
            } else {
                /* Deriving the public bytes must not modify the private-only key. */
                public_copy = key_dup(native, OSSL_KEYMGMT_SELECT_PUBLIC_KEY);
                valid = key_has(native, OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0 &&
                        public_copy != NULL &&
                        key_has(public_copy, OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 1 &&
                        key_has(public_copy, OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == 0 &&
                        key_get_params(public_copy, copied_params) == 1 &&
                        CRYPTO_memcmp(public_bytes, copied_bytes,
                                      sizeof(public_bytes)) == 0;
            }
        }
        key_free(public_copy);
        key_free(native);
        if (genctx != NULL)
            gen_cleanup(genctx);
        if (!valid)
            goto done;
    }
    {
        void *invalid = gen_init(OSSL_PROVIDER_get0_provider_ctx(provider), 0, NULL);

        if (invalid != NULL) {
            gen_cleanup(invalid);
            goto done;
        }
    }
    ok = 1;

done:
    OPENSSL_cleanse(private_bytes, sizeof(private_bytes));
    OPENSSL_cleanse(public_bytes, sizeof(public_bytes));
    OPENSSL_cleanse(copied_bytes, sizeof(copied_bytes));
    if (!ok)
        fprintf(stderr, "BIGN KEYMGMT generation selection contract failed\n");
    return ok;
}

int main(int argc, char **argv)
{
    const OSSL_ALGORITHM *keyalgs = NULL, *decalgs = NULL, *alg;
    const OSSL_DISPATCH *fn;
    OSSL_PROVIDER *default_provider = NULL, *provider = NULL;
    OSSL_FUNC_keymgmt_new_fn *key_new = NULL;
    OSSL_FUNC_keymgmt_free_fn *key_free = NULL;
    OSSL_FUNC_keymgmt_import_fn *key_import = NULL;
    OSSL_FUNC_keymgmt_match_fn *key_match = NULL;
    OSSL_FUNC_keymgmt_dup_fn *key_dup = NULL;
    OSSL_FUNC_keymgmt_gen_init_fn *key_gen_init = NULL;
    OSSL_FUNC_keymgmt_gen_fn *key_generate = NULL;
    OSSL_FUNC_keymgmt_gen_cleanup_fn *key_gen_cleanup = NULL;
    OSSL_FUNC_keymgmt_has_fn *key_has = NULL;
    OSSL_FUNC_keymgmt_validate_fn *key_validate = NULL;
    OSSL_FUNC_keymgmt_get_params_fn *key_get_params = NULL;
    OSSL_FUNC_decoder_newctx_fn *decoder_new = NULL;
    OSSL_FUNC_decoder_freectx_fn *decoder_free = NULL;
    OSSL_FUNC_decoder_export_object_fn *decoder_export = NULL;
    EVP_PKEY_CTX *evp_import = NULL;
    EVP_PKEY *expected_pkey = NULL;
    expected_key_t expected;
    void *key = NULL, *clone = NULL, *public_only = NULL;
    void *different = NULL, *decoder = NULL, *reference;
    unsigned char private_key[32] = {3, 1, 4, 1, 5, 9};
    unsigned char other_private[32] = {5, 3, 1, 4};
    char group[] = "bign-256";
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group, sizeof(group)),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, private_key, sizeof(private_key)),
        OSSL_PARAM_END
    };
    size_t got = 0;
    int nocache = 0, ok = 0;

    if (argc != 2)
        return 2;
    if (!OSSL_PROVIDER_set_default_search_path(NULL, argv[1]))
        return 1;
    default_provider = OSSL_PROVIDER_load(NULL, "default");
    provider = OSSL_PROVIDER_load(NULL, "bee2_provider");
    if (!default_provider || !provider)
        goto done;

    keyalgs = OSSL_PROVIDER_query_operation(provider, OSSL_OP_KEYMGMT, &nocache);
    decalgs = OSSL_PROVIDER_query_operation(provider, OSSL_OP_DECODER, &nocache);
    if (!keyalgs || !decalgs)
        goto done;

    for (alg = keyalgs; alg->algorithm_names; ++alg) {
        if (!has_name(alg->algorithm_names, "bign-256"))
            continue;
        for (fn = alg->implementation; fn->function_id; ++fn) {
            switch (fn->function_id) {
            case OSSL_FUNC_KEYMGMT_NEW: key_new = OSSL_FUNC_keymgmt_new(fn); break;
            case OSSL_FUNC_KEYMGMT_FREE: key_free = OSSL_FUNC_keymgmt_free(fn); break;
            case OSSL_FUNC_KEYMGMT_IMPORT: key_import = OSSL_FUNC_keymgmt_import(fn); break;
            case OSSL_FUNC_KEYMGMT_MATCH: key_match = OSSL_FUNC_keymgmt_match(fn); break;
            case OSSL_FUNC_KEYMGMT_DUP: key_dup = OSSL_FUNC_keymgmt_dup(fn); break;
            case OSSL_FUNC_KEYMGMT_GEN_INIT:
                key_gen_init = OSSL_FUNC_keymgmt_gen_init(fn); break;
            case OSSL_FUNC_KEYMGMT_GEN:
                key_generate = OSSL_FUNC_keymgmt_gen(fn); break;
            case OSSL_FUNC_KEYMGMT_GEN_CLEANUP:
                key_gen_cleanup = OSSL_FUNC_keymgmt_gen_cleanup(fn); break;
            case OSSL_FUNC_KEYMGMT_HAS:
                key_has = OSSL_FUNC_keymgmt_has(fn); break;
            case OSSL_FUNC_KEYMGMT_VALIDATE:
                key_validate = OSSL_FUNC_keymgmt_validate(fn); break;
            case OSSL_FUNC_KEYMGMT_GET_PARAMS:
                key_get_params = OSSL_FUNC_keymgmt_get_params(fn); break;
            }
        }
        break;
    }
    for (alg = decalgs; alg->algorithm_names; ++alg) {
        if (!has_name(alg->algorithm_names, "bign") ||
            !strstr(alg->property_definition, "structure=PrivateKeyInfo"))
            continue;
        for (fn = alg->implementation; fn->function_id; ++fn) {
            switch (fn->function_id) {
            case OSSL_FUNC_DECODER_NEWCTX: decoder_new = OSSL_FUNC_decoder_newctx(fn); break;
            case OSSL_FUNC_DECODER_FREECTX: decoder_free = OSSL_FUNC_decoder_freectx(fn); break;
            case OSSL_FUNC_DECODER_EXPORT_OBJECT:
                decoder_export = OSSL_FUNC_decoder_export_object(fn); break;
            }
        }
        break;
    }
    if (!key_new || !key_free || !key_import || !key_match || !key_dup ||
        !key_gen_init || !key_generate || !key_gen_cleanup || !key_has ||
        !key_validate || !key_get_params || !decoder_new ||
        !decoder_free || !decoder_export)
        goto done;

    key = key_new(OSSL_PROVIDER_get0_provider_ctx(provider));
    decoder = decoder_new(OSSL_PROVIDER_get0_provider_ctx(provider));
    evp_import = EVP_PKEY_CTX_new_from_name(NULL, "bign-256", "provider=bee2");
    if (!key || !decoder || !evp_import ||
        !key_import(key, OSSL_KEYMGMT_SELECT_KEYPAIR, params) ||
        EVP_PKEY_fromdata_init(evp_import) <= 0 ||
        EVP_PKEY_fromdata(evp_import, &expected_pkey,
                          EVP_PKEY_KEYPAIR, params) <= 0)
        goto done;
    memset(&expected, 0, sizeof(expected));
    expected.private_key = private_key;
    if (EVP_PKEY_get_octet_string_param(expected_pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                        expected.public_key,
                                        sizeof(expected.public_key), &got) <= 0 ||
        got != sizeof(expected.public_key))
        goto done;

    /* The native KEYMGMT match contract distinguishes public and private
     * selections, and duplication must preserve both without sharing memory.
     */
    clone = key_dup(key, OSSL_KEYMGMT_SELECT_KEYPAIR);
    public_only = key_new(OSSL_PROVIDER_get0_provider_ctx(provider));
    different = key_new(OSSL_PROVIDER_get0_provider_ctx(provider));
    if (!clone || !public_only || !different ||
        !key_match(key, clone, OSSL_KEYMGMT_SELECT_KEYPAIR))
        goto done;
    {
        OSSL_PARAM pub_params[] = {
            OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group, sizeof(group)),
            OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                    expected.public_key, sizeof(expected.public_key)),
            OSSL_PARAM_END
        };
        OSSL_PARAM other_params[] = {
            OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group, sizeof(group)),
            OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
                                    other_private, sizeof(other_private)),
            OSSL_PARAM_END
        };
        if (!key_import(public_only, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, pub_params) ||
            !key_import(different, OSSL_KEYMGMT_SELECT_KEYPAIR, other_params) ||
            !key_match(key, public_only, OSSL_KEYMGMT_SELECT_PUBLIC_KEY) ||
            key_match(key, public_only, OSSL_KEYMGMT_SELECT_PRIVATE_KEY) ||
            key_match(key, different, OSSL_KEYMGMT_SELECT_KEYPAIR) ||
            key_match(key, different, OSSL_KEYMGMT_SELECT_PUBLIC_KEY))
            goto done;
    }

    if (!check_generation_selections(provider, key_gen_init, key_generate,
                                     key_gen_cleanup, key_free, key_has,
                                     key_validate, key_get_params, key_dup))
        goto done;

    reference = key;
    if (!decoder_export(decoder, &reference, sizeof(reference),
                        check_exported, &expected) || expected.callbacks != 1)
        goto done;
    if (decoder_export(decoder, &reference, sizeof(reference) - 1u,
                       check_exported, &expected) ||
        expected.callbacks != 1)
        goto done;
    ok = 1;
done:
    if (!ok)
        fprintf(stderr, "BIGN decoder object-reference export contract failed\n");
    EVP_PKEY_free(expected_pkey);
    EVP_PKEY_CTX_free(evp_import);
    if (decoder && decoder_free) decoder_free(decoder);
    if (different && key_free) key_free(different);
    if (public_only && key_free) key_free(public_only);
    if (clone && key_free) key_free(clone);
    if (key && key_free) key_free(key);
    if (decalgs) OSSL_PROVIDER_unquery_operation(provider, OSSL_OP_DECODER, decalgs);
    if (keyalgs) OSSL_PROVIDER_unquery_operation(provider, OSSL_OP_KEYMGMT, keyalgs);
    OSSL_PROVIDER_unload(provider);
    OSSL_PROVIDER_unload(default_provider);
    OPENSSL_cleanse(private_key, sizeof(private_key));
    return ok ? 0 : 1;
}
