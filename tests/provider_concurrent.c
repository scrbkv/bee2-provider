/* Exercise concurrently cloned EVP contexts through one OSSL_LIB_CTX. */
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#define WORKERS 8
#define ROUNDS 48

typedef struct {
    OSSL_LIB_CTX *libctx;
    const unsigned char *message;
    unsigned char expected[32];
    int failed;
} worker_state;

static void *exercise(void *arg)
{
    worker_state *s = arg;
    EVP_MD *md = EVP_MD_fetch(s->libctx, "belt-hash", "provider=bee2");
    EVP_MAC *mac = EVP_MAC_fetch(s->libctx, "belt-hmac", "provider=bee2");
    EVP_PKEY_CTX *keygen = NULL, *sign = NULL, *verify = NULL;
    EVP_PKEY *key = NULL;
    unsigned char digest[64], signature[128], tag[64], ref_tag[64];
    unsigned char keybytes[32];
    size_t siglen = sizeof(signature), taglen = 0, ref_len = 0;
    unsigned int digestlen = 0;
    int i;
    char name[] = "belt-hash";
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, name, sizeof(name)),
        OSSL_PARAM_END
    };
    EVP_MAC_CTX *m = NULL;

    for (i = 0; i < (int)sizeof(keybytes); ++i)
        keybytes[i] = (unsigned char)(i + 5);
    if (!md || !mac) goto error;
    for (i = 0; i < ROUNDS; ++i) {
        EVP_MD_CTX *a = EVP_MD_CTX_new(), *b = EVP_MD_CTX_new();
        EVP_MAC_CTX *mdup = NULL;
        if (!a || !b || EVP_DigestInit_ex2(a, md, NULL) <= 0 ||
            EVP_DigestUpdate(a, s->message, 13) <= 0 ||
            EVP_MD_CTX_copy_ex(b, a) <= 0 ||
            EVP_DigestUpdate(a, s->message + 13, 244) <= 0 ||
            EVP_DigestUpdate(b, s->message + 13, 7) <= 0 ||
            EVP_DigestUpdate(b, s->message + 20, 237) <= 0 ||
            EVP_DigestFinal_ex(a, digest, &digestlen) <= 0 ||
            digestlen != sizeof(s->expected) ||
            CRYPTO_memcmp(digest, s->expected, sizeof(s->expected)) != 0 ||
            EVP_DigestFinal_ex(b, digest, &digestlen) <= 0 ||
            digestlen != sizeof(s->expected) ||
            CRYPTO_memcmp(digest, s->expected, sizeof(s->expected)) != 0) {
            EVP_MD_CTX_free(b);
            EVP_MD_CTX_free(a);
            goto error;
        }
        EVP_MD_CTX_free(b);
        EVP_MD_CTX_free(a);
        m = EVP_MAC_CTX_new(mac);
        if (!m || EVP_MAC_init(m, keybytes, sizeof(keybytes), params) <= 0 ||
            EVP_MAC_update(m, s->message, 13) <= 0 ||
            !(mdup = EVP_MAC_CTX_dup(m)) ||
            EVP_MAC_update(m, s->message + 13, 244) <= 0 ||
            EVP_MAC_update(mdup, s->message + 13, 244) <= 0 ||
            EVP_MAC_final(m, tag, &taglen, sizeof(tag)) <= 0 ||
            EVP_MAC_final(mdup, ref_tag, &ref_len, sizeof(ref_tag)) <= 0 ||
            taglen != ref_len || CRYPTO_memcmp(tag, ref_tag, taglen) != 0) {
            EVP_MAC_CTX_free(mdup);
            goto error;
        }
        EVP_MAC_CTX_free(mdup);
        EVP_MAC_CTX_free(m);
        m = NULL;
    }
    keygen = EVP_PKEY_CTX_new_from_name(s->libctx, "bign-256", "provider=bee2");
    if (!keygen || EVP_PKEY_keygen_init(keygen) <= 0 ||
        EVP_PKEY_keygen(keygen, &key) <= 0)
        goto error;
    sign = EVP_PKEY_CTX_new_from_pkey(s->libctx, key, "provider=bee2");
    verify = EVP_PKEY_CTX_new_from_pkey(s->libctx, key, "provider=bee2");
    if (!sign || !verify || EVP_PKEY_sign_init(sign) <= 0 ||
        EVP_PKEY_sign(sign, signature, &siglen, s->expected, 32) <= 0 ||
        EVP_PKEY_verify_init(verify) <= 0 ||
        EVP_PKEY_verify(verify, signature, siglen, s->expected, 32) <= 0)
        goto error;
    goto done;
error:
    s->failed = 1;
done:
    EVP_MAC_CTX_free(m);
    EVP_PKEY_CTX_free(verify);
    EVP_PKEY_CTX_free(sign);
    EVP_PKEY_CTX_free(keygen);
    EVP_PKEY_free(key);
    EVP_MAC_free(mac);
    EVP_MD_free(md);
    return NULL;
}

int main(int argc, char **argv)
{
    unsigned char message[257];
    pthread_t tids[WORKERS];
    worker_state workers[WORKERS];
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *default_provider = NULL, *provider = NULL;
    size_t n;
    int i, started = 0, ok = 0;

    if (argc != 2) return 2;
    for (i = 0; i < (int)sizeof(message); ++i)
        message[i] = (unsigned char)(i * 7 + 1);
    libctx = OSSL_LIB_CTX_new();
    if (!libctx || !OSSL_PROVIDER_set_default_search_path(libctx, argv[1]))
        goto done;
    default_provider = OSSL_PROVIDER_load(libctx, "default");
    provider = OSSL_PROVIDER_load(libctx, "bee2_provider");
    if (!default_provider || !provider) goto done;
    memset(workers, 0, sizeof(workers));
    for (i = 0; i < WORKERS; ++i) {
        workers[i].libctx = libctx;
        workers[i].message = message;
        if (EVP_Q_digest(libctx, "belt-hash", "provider=bee2", message,
                         sizeof(message), workers[i].expected, &n) <= 0 || n != 32)
            goto done;
    }
    for (i = 0; i < WORKERS; ++i) {
        if (pthread_create(&tids[i], NULL, exercise, &workers[i]))
            break;
        ++started;
    }
    if (started != WORKERS) goto join;
    ok = 1;
join:
    for (i = 0; i < started; ++i)
        if (pthread_join(tids[i], NULL) || workers[i].failed)
            ok = 0;
done:
    if (!ok) fprintf(stderr, "Concurrent provider operation failed\n");
    OSSL_PROVIDER_unload(provider);
    OSSL_PROVIDER_unload(default_provider);
    OSSL_LIB_CTX_free(libctx);
    return ok ? 0 : 1;
}
