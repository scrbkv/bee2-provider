/* BELT-BDE is not XTS or any other OpenSSL-defined cipher mode. */
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    static const char *const names[] = {"belt-bde128", "belt-bde192", "belt-bde256"};
    OSSL_PROVIDER *def = NULL, *bee2 = NULL;
    EVP_CIPHER *cipher = NULL;
    size_t i;
    int ok = 0;

    if (argc != 2)
        return 2;
    if (!OSSL_PROVIDER_set_default_search_path(NULL, argv[1]))
        goto end;
    def = OSSL_PROVIDER_load(NULL, "default");
    bee2 = OSSL_PROVIDER_load(NULL, "bee2_provider");
    if (!def || !bee2)
        goto end;

    for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        char mode_name[32] = {0};
        OSSL_PARAM p[] = {
            OSSL_PARAM_construct_utf8_string("bee2-mode", mode_name, sizeof(mode_name)),
            OSSL_PARAM_construct_end()};
        cipher = EVP_CIPHER_fetch(NULL, names[i], "provider=bee2");
        if (!cipher || EVP_CIPHER_get_mode(cipher) != EVP_CIPH_STREAM_CIPHER ||
            !EVP_CIPHER_get_params(cipher, p) || strcmp(mode_name, "belt-bde") != 0) {
            fprintf(stderr, "BELT-BDE mode metadata mismatch for %s\n", names[i]);
            goto end;
        }
        EVP_CIPHER_free(cipher);
        cipher = NULL;
    }
    ok = 1;

end:
    EVP_CIPHER_free(cipher);
    OSSL_PROVIDER_unload(bee2);
    OSSL_PROVIDER_unload(def);
    return ok ? 0 : 1;
}
