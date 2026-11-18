/* Published known-answer examples from STB 34.101.31, 34.101.45,
 * 34.101.47 and 34.101.77. */
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/provider.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static const char h_hex[] =
    "B194BAC80A08F53B366D008E584A5DE4"
    "8504FA9D1BB6C7AC252E72C202FDCE0D"
    "5BE3D61217B96181FE6786AD716B890B"
    "5CB0C0FF33C356B835C405AED8E07F99"
    "E12BDC1AE28257EC703FCCF095EE8DF1"
    "C1AB76389FE678CAF7C6F860D5BB9C4F"
    "F33C657B637C306ADD4EA7799EB23D31"
    "3E98B56E27D3BCCF591E181F4C5AB793"
    "E9DEE72C8F0C0FA62DDB49F46F739647"
    "06075316ED247A3739CBA38303A98BF6"
    "92BD9B1CE5D141015445FBC95E4D0EF2"
    "682080AA227D642F2687F93490405511"
    "BE32971343FC9A48A02A885F194B09A1"
    "7ECDA4D01544AF8CA58450BF66D2E88A"
    "A2D7465242A8DFB36974C551EB232921"
    "D4EFD9B43A622875911410EA776CDA1D";

static int from_hex(unsigned char *out, size_t len, const char *hex)
{
    size_t i;
    unsigned int b;

    if (strlen(hex) != len * 2)
        return 0;
    for (i = 0; i < len; ++i) {
        if (sscanf(hex + 2 * i, "%2x", &b) != 1)
            return 0;
        out[i] = (unsigned char)b;
    }
    return 1;
}

static int compare_hex(const char *label, const unsigned char *data,
                       size_t len, const char *expected)
{
    unsigned char bytes[128];
    int ok = len <= sizeof(bytes) && from_hex(bytes, len, expected) &&
             CRYPTO_memcmp(data, bytes, len) == 0;

    if (!ok)
        fprintf(stderr, "STB known-answer mismatch: %s\n", label);
    OPENSSL_cleanse(bytes, sizeof(bytes));
    return ok;
}

static int decrypt_belt(const char *name, const unsigned char h[256],
                        const char *expected)
{
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, name, "provider=bee2");
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char output[64];
    int outlen = 0, final_len = 0, ok = 0;

    if (cipher == NULL || ctx == NULL ||
        EVP_DecryptInit_ex2(ctx, cipher, h + 160, h + 208, NULL) <= 0 ||
        EVP_CIPHER_CTX_set_padding(ctx, 0) <= 0 ||
        EVP_DecryptUpdate(ctx, output, &outlen, h + 64, 48) <= 0 ||
        EVP_DecryptFinal_ex(ctx, output + outlen, &final_len) <= 0 ||
        outlen + final_len != 48 ||
        !compare_hex(name, output, 48, expected))
        goto end;
    ok = 1;
end:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    OPENSSL_cleanse(output, sizeof(output));
    return ok;
}

static int check_belt_mac(const unsigned char h[256])
{
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "belt-mac256", "provider=bee2");
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    unsigned char tag[8];
    size_t len = 0;
    int ok = ctx != NULL &&
             EVP_MAC_init(ctx, h + 128, 32, NULL) > 0 &&
             EVP_MAC_update(ctx, h, 13) > 0 &&
             EVP_MAC_final(ctx, tag, &len, sizeof(tag)) > 0 && len == 8 &&
             compare_hex("34.101.31 A.17-1 belt-mac", tag, len,
                         "7260DA60138F96C9") &&
             EVP_MAC_init(ctx, h + 128, 32, NULL) > 0 &&
             EVP_MAC_update(ctx, h, 48) > 0 &&
             EVP_MAC_final(ctx, tag, &len, sizeof(tag)) > 0 && len == 8 &&
             compare_hex("34.101.31 A.17-2 belt-mac", tag, len,
                         "2DAB59771B4B16D0");

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return ok;
}

static int check_belt_kwp_encrypt(const unsigned char h[256])
{
    static const char expected[] =
        "49A38EE108D6C742E52B774F00A6EF98"
        "B106CBD13EA4FB0680323051BC04DF76"
        "E487B055C69BCF541176169F1DC9F6C8";
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "belt-kwp256", "provider=bee2");
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char output[64];
    int outlen = 0, final_len = 0, ok = 0;

    if (cipher == NULL || ctx == NULL ||
        EVP_EncryptInit_ex2(ctx, cipher, h + 128, h + 32, NULL) <= 0 ||
        EVP_EncryptUpdate(ctx, output, &outlen, h, 32) <= 0 ||
        EVP_EncryptFinal_ex(ctx, output + outlen, &final_len) <= 0 ||
        outlen + final_len != 48 ||
        !compare_hex("34.101.31 A.21 belt-kwp", output, 48, expected))
        goto end;
    ok = 1;
end:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    OPENSSL_cleanse(output, sizeof(output));
    return ok;
}

static int check_belt_kwp_decrypt(const unsigned char h[256])
{
    static const char header_hex[] = "B5EF68D8E4A39E567153DE13D72254EE";
    static const char plaintext_hex[] =
        "92632EE0C21AD9E09A39343E5C07DAA4"
        "889B03F2E6847EB152EC99F7A4D9F154";
    unsigned char header[16], plaintext[48];
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "belt-kwp256", "provider=bee2");
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outlen = 0, final_len = 0, ok = 0;

    if (!from_hex(header, sizeof(header), header_hex) ||
        cipher == NULL || ctx == NULL ||
        EVP_DecryptInit_ex2(ctx, cipher, h + 160, header, NULL) <= 0 ||
        EVP_DecryptUpdate(ctx, plaintext, &outlen, h + 64, 48) <= 0 ||
        EVP_DecryptFinal_ex(ctx, plaintext + outlen, &final_len) <= 0 ||
        outlen + final_len != 32 ||
        !compare_hex("34.101.31 A.22 belt-kwp", plaintext, 32, plaintext_hex))
        goto end;
    ok = 1;
end:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    OPENSSL_cleanse(plaintext, sizeof(plaintext));
    return ok;
}

static int check_pbkdf_and_kwp(const unsigned char h[256])
{
    static const char pass[] = "B194BAC80A08F53B";
    static const char priv_hex[] =
        "1F66B5B84B7339674533F0329C74F218"
        "34281FED0732429E0C79235FC273E269";
    static const char token_hex[] =
        "4EA289D5F718087DD8EDB305BA1CE898"
        "0E5EC3E0B56C8BF9D5C3E909CF4C14F0"
        "7B8204E67841A165E924945CD07F37E7";
    static const char derived_hex[] =
        "3D331BBBB1FBBB40E4BF22F6CB9A689E"
        "F13A77DC09ECF93291BFE42439A72E7D";
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "belt-pbkdf", "provider=bee2");
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "belt-kwp256", "provider=bee2");
    EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new();
    unsigned char derived[32], private_key[32], wrapped[48];
    uint64_t iter = 10000;
    int len = 0, final_len = 0, ok = 0;
    OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_PASSWORD, (void *)pass, sizeof(pass) - 1),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, (void *)(h + 192), 8),
        OSSL_PARAM_uint64(OSSL_KDF_PARAM_ITER, &iter),
        OSSL_PARAM_END
    };

    if (kctx == NULL || cipher == NULL || cctx == NULL ||
        EVP_KDF_derive(kctx, derived, sizeof(derived), params) <= 0 ||
        !compare_hex("34.101.45 E.5 belt-pbkdf", derived,
                     sizeof(derived), derived_hex) ||
        !from_hex(private_key, sizeof(private_key), priv_hex) ||
        EVP_EncryptInit_ex2(cctx, cipher, derived, NULL, NULL) <= 0 ||
        EVP_EncryptUpdate(cctx, wrapped, &len, private_key,
                          sizeof(private_key)) <= 0 ||
        EVP_EncryptFinal_ex(cctx, wrapped + len, &final_len) <= 0 ||
        len + final_len != 48 ||
        !compare_hex("34.101.45 E.5 protected private key", wrapped,
                     sizeof(wrapped), token_hex))
        goto end;
    ok = 1;
end:
    EVP_CIPHER_CTX_free(cctx);
    EVP_CIPHER_free(cipher);
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    OPENSSL_cleanse(private_key, sizeof(private_key));
    OPENSSL_cleanse(derived, sizeof(derived));
    OPENSSL_cleanse(wrapped, sizeof(wrapped));
    return ok;
}

static int check_bign_transport(const unsigned char h[256],
                                const char *label, const char *hex,
                                size_t token_len, size_t plaintext_len,
                                size_t header_offset)
{
    unsigned char private_key[32], token[80], plaintext[64];
    static const char private_hex[] =
        "1F66B5B84B7339674533F0329C74F218"
        "34281FED0732429E0C79235FC273E269";
    EVP_PKEY_CTX *import = NULL, *decrypt = NULL;
    EVP_PKEY *key = NULL;
    size_t recovered = sizeof(plaintext);
    OSSL_PARAM params[2];
    int ok = 0;

    if (!from_hex(private_key, sizeof(private_key), private_hex) ||
        !from_hex(token, token_len, hex))
        goto end;
    import = EVP_PKEY_CTX_new_from_name(NULL, "bign-256", "provider=bee2");
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
                                                   private_key, sizeof(private_key));
    params[1] = OSSL_PARAM_construct_end();
    if (import == NULL || EVP_PKEY_fromdata_init(import) <= 0 ||
        EVP_PKEY_fromdata(import, &key, EVP_PKEY_KEYPAIR, params) <= 0)
        goto end;
    decrypt = EVP_PKEY_CTX_new_from_pkey(NULL, key, "provider=bee2");
    params[0] = OSSL_PARAM_construct_octet_string("header", (void *)(h + header_offset), 16);
    if (decrypt == NULL || EVP_PKEY_decrypt_init(decrypt) <= 0 ||
        EVP_PKEY_CTX_set_params(decrypt, params) <= 0 ||
        EVP_PKEY_decrypt(decrypt, plaintext, &recovered, token, token_len) <= 0 ||
        recovered != plaintext_len ||
        CRYPTO_memcmp(plaintext, h, plaintext_len) != 0) {
        fprintf(stderr, "STB 34.101.45 %s BIGN token mismatch\n", label);
        goto end;
    }
    ok = 1;
end:
    EVP_PKEY_CTX_free(decrypt);
    EVP_PKEY_CTX_free(import);
    EVP_PKEY_free(key);
    OPENSSL_cleanse(private_key, sizeof(private_key));
    OPENSSL_cleanse(token, sizeof(token));
    OPENSSL_cleanse(plaintext, sizeof(plaintext));
    return ok;
}

static int belt_encrypt_vector(const char *name,
                               const unsigned char *key,
                               const unsigned char *iv, const unsigned char *input,
                               size_t length, const char *expected)
{
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, name, "provider=bee2");
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char output[128];
    int outlen = 0, final_len = 0, ok = 0;

    if (cipher == NULL || ctx == NULL ||
        EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL) <= 0 ||
        EVP_CIPHER_CTX_set_padding(ctx, 0) <= 0 ||
        EVP_EncryptUpdate(ctx, output, &outlen, input, (int)length) <= 0 ||
        EVP_EncryptFinal_ex(ctx, output + outlen, &final_len) <= 0 ||
        (size_t)(outlen + final_len) != length ||
        !compare_hex(name, output, length, expected))
        goto end;
    ok = 1;
end:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    OPENSSL_cleanse(output, sizeof(output));
    return ok;
}

static int belt_decrypt_vector(const unsigned char h[256], const char *name,
                               size_t length, const char *expected)
{
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, name, "provider=bee2");
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char output[128];
    int outlen = 0, final_len = 0, ok = 0;
    const unsigned char *iv = strstr(name, "ecb") ? NULL : h + 208;

    if (cipher == NULL || ctx == NULL ||
        EVP_DecryptInit_ex2(ctx, cipher, h + 160, iv, NULL) <= 0 ||
        EVP_CIPHER_CTX_set_padding(ctx, 0) <= 0 ||
        EVP_DecryptUpdate(ctx, output, &outlen, h + 64, (int)length) <= 0 ||
        EVP_DecryptFinal_ex(ctx, output + outlen, &final_len) <= 0 ||
        (size_t)(outlen + final_len) != length ||
        !compare_hex(name, output, length, expected))
        goto end;
    ok = 1;
end:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    OPENSSL_cleanse(output, sizeof(output));
    return ok;
}

static int check_belt_block_vectors(const unsigned char h[256])
{
    static const struct {
        const char *name;
        const char *expected;
    } encrypt_vectors[] = {
        {"belt-ecb256",
         "69CCA1C93557C9E3D66BC3E0FA88FA6E"
         "5F23102EF109710775017F73806DA9DC"
         "46FB2ED2CE771F26DCB5E5D1569F9AB0"},
        {"belt-cbc256",
         "10116EFAE6AD58EE14852E11DA1B8A74"
         "5CF2480E8D03F1C19492E53ED3A70F60"
         "657C1EE8C0E0AE5B58388BF8A68E3309"},
        {"belt-cfb256",
         "C31E490A90EFA374626CC99E4B7B8540"
         "A6E48685464A5A06849C9CA769A1B0AE"
         "55C2CC5939303EC832DD2FE16C8E5A1B"},
        {"belt-ctr256",
         "52C9AF96FF50F64435FC43DEF56BD797"
         "D5B5B1FF79FB41257AB9CDF6E63E81F8"
         "F00341473EAE409833622DE05213773A"},
        {"belt-bde256",
         "E9CAB32D879CC50C10378EB07C10F263"
         "07257E2DBE2B854CBC9F38282D59D6A7"
         "7F952001C5D1244F53210A27C216D4BB"},
        {"belt-sde256",
         "1FCBB01852003D60B66024C508608BAA"
         "2C21AF1E884CF31154D3077D4643CF22"
         "49EB2F5A68E4BA019D90211A81D690D9"}
    };
    static const struct {
        const char *name;
        size_t length;
        const char *expected;
    } decrypt_vectors[] = {
        {"belt-ecb256", 48,
         "0DC5300600CAB840B38448E5E993F421"
         "E55A239F2AB5C5D5FDB6E81B40938E2A"
         "54120CA3E6E19C7AD750FC3531DAEAB7"},
        {"belt-cbc256", 48,
         "730894D6158E17CC1600185A8F411CAB"
         "0471FF85C83792398D8924EBD57D03DB"
         "95B97A9B7907E4B020960455E46176F8"},
        {"belt-cfb256", 48,
         "FA9D107A86F375EE65CD1DB881224BD0"
         "16AFF814938ED39B3361ABB0BF0851B6"
         "52244EB06842DD4C94AA4500774E40BB"},
        {"belt-ctr256", 44,
         "DF181ED008A20F43DCBBB93650DAD34B"
         "389CDEE5826D40E2D4BD80F49A93F5D2"
         "12F6333166456F169043CC5F"}
    };
    /* Normative ciphertext-stealing cases: STB 34.101.31 A.9-2/A.11-2.
     * One Update must contain the complete final partial block. */
    static const struct {
        const char *name;
        size_t length;
        const char *expected;
    } partial_encrypt_vectors[] = {
        {"belt-ecb256", 47,
         "69CCA1C93557C9E3D66BC3E0FA88FA6E"
         "36F00CFED6D1CA1498C12798F4BEB207"
         "5F23102EF109710775017F73806DA9"},
        {"belt-cbc256", 36,
         "10116EFAE6AD58EE14852E11DA1B8A74"
         "6A9BBADCAF73F968F875DEDC0A44F6B1"
         "5CF2480E"}
    };
    /* Independent reference decryption answers, not round trips. */
    static const struct {
        const char *name;
        size_t length;
        const char *expected;
    } partial_decrypt_vectors[] = {
        {"belt-ecb256", 36,
         "0DC5300600CAB840B38448E5E993F421"
         "5780A6E2B69EAFBB258726D7B6718523"
         "E55A239F"},
        {"belt-cbc256", 36,
         "730894D6158E17CC1600185A8F411CAB"
         "B6AB7AF8541CF85755B8EA27239F08D2"
         "166646E4"}
    };
    size_t i;

    for (i = 0; i < sizeof(encrypt_vectors) / sizeof(encrypt_vectors[0]); ++i) {
        const char *name = encrypt_vectors[i].name;
        if (!belt_encrypt_vector(name, h + 128,
                                 strstr(name, "ecb") ? NULL : h + 192,
                                 h, 48, encrypt_vectors[i].expected))
            return 0;
    }
    for (i = 0; i < sizeof(decrypt_vectors) / sizeof(decrypt_vectors[0]); ++i)
        if (!belt_decrypt_vector(h, decrypt_vectors[i].name,
                                 decrypt_vectors[i].length,
                                 decrypt_vectors[i].expected))
            return 0;
    for (i = 0; i < sizeof(partial_encrypt_vectors) /
                    sizeof(partial_encrypt_vectors[0]); ++i)
        if (!belt_encrypt_vector(partial_encrypt_vectors[i].name, h + 128,
                                 strstr(partial_encrypt_vectors[i].name, "ecb")
                                     ? NULL : h + 192,
                                 h, partial_encrypt_vectors[i].length,
                                 partial_encrypt_vectors[i].expected))
            return 0;
    for (i = 0; i < sizeof(partial_decrypt_vectors) /
                    sizeof(partial_decrypt_vectors[0]); ++i)
        if (!belt_decrypt_vector(h, partial_decrypt_vectors[i].name,
                                 partial_decrypt_vectors[i].length,
                                 partial_decrypt_vectors[i].expected))
            return 0;
    return 1;
}

static int check_belt_hashes(const unsigned char h[256])
{
    static const struct {
        size_t length;
        const char *expected;
    } vectors[] = {
        {13, "ABEF9725D4C5A83597A367D14494CC25"
             "42F20F659DDFECC961A3EC550CBA8C75"},
        {32, "749E4C3653AECE5E48DB4761227742EB"
             "6DBE13F4A80F7BEFF1A9CF8D10EE7786"},
        {48, "9D02EE446FB6A29FE5C982D4B13AF9D3"
             "E90861BC4CEF27CF306BFB0B174A154A"}
    };
    unsigned char digest[64];
    size_t i, digest_len = 0;

    for (i = 0; i < sizeof(vectors) / sizeof(vectors[0]); ++i)
        if (EVP_Q_digest(NULL, "belt-hash", "provider=bee2", h,
                         vectors[i].length, digest, &digest_len) <= 0 ||
            digest_len != 32 ||
            !compare_hex("34.101.31 A.23 belt-hash", digest,
                         digest_len, vectors[i].expected))
            return 0;
    return 1;
}

static int check_bash_hashes(const unsigned char h[256])
{
    static const struct {
        const char *name;
        size_t length;
        const char *expected;
    } vectors[] = {
        {"bash256", 0,
         "114C3DFAE373D9BCBC3602D6386F2D6A"
         "2059BA1BF9048DBAA5146A6CB775709D"},
        {"bash256", 127,
         "3D7F4EFA00E9BA33FEED259986567DCF"
         "5C6D12D51057A968F14F06CC0F905961"},
        {"bash256", 128,
         "D7F428311254B8B2D00F7F9EEFBD8F30"
         "25FA87C4BABD1BDDBE87E35B7AC80DD6"},
        {"bash256", 135,
         "1393FA1B65172F2D18946AEAE576FA1C"
         "F54FDD354A0CB2974A997DC4865D3100"},
        {"bash384", 95,
         "64334AF830D33F63E9ACDFA184E32522"
         "103FFF5C6860110A2CD369EDBC04387C"
         "501D8F92F749AE4DE15A8305C353D64D"},
        {"bash384", 96,
         "D06EFBC16FD6C0880CBFC6A4E3D65AB1"
         "01FA82826934190FAABEBFBFFEDE93B2"
         "2B85EA72A7FB3147A133A5A8FEBD8320"},
        {"bash384", 108,
         "FF763296571E2377E71A1538070CC0DE"
         "88888606F32EEE6B082788D246686B00"
         "FC05A17405C5517699DA44B7EF5F55AB"},
        {"bash512", 63,
         "2A66C87C189C12E255239406123BDEDB"
         "F19955EAF0808B2AD705E249220845E2"
         "0F4786FB6765D0B5C48984B1B16556EF"
         "19EA8192B985E4233D9C09508D6339E7"},
        {"bash512", 64,
         "07ABBF8580E7E5A321E9B940F667AE20"
         "9E2952CEF557978AE743DB086BAB4885"
         "B708233C3F5541DF8AAFC3611482FDE4"
         "98E58B3379A6622DAC2664C9C118A162"},
        {"bash512", 127,
         "526073918F97928E9D15508385F42F03"
         "ADE3211A23900A30131F8A1E3E1EE21C"
         "C09D13CFF6981101235D895746A4643F"
         "0AA62B0A7BC98A269E4507A257F0D4EE"},
        {"bash512", 192,
         "8724C7FF8A2A83F22E38CB9763777B96"
         "A70ABA3444F214C763D93CD6D19FCFDE"
         "6C3D3931857C4FF6CCCD49BD99852FE9"
         "EAA7495ECCDD96B571E0EDCF47F89768"}
    };
    unsigned char digest[64];
    size_t i, digest_len;

    for (i = 0; i < sizeof(vectors) / sizeof(vectors[0]); ++i)
        if (EVP_Q_digest(NULL, vectors[i].name, "provider=bee2", h,
                         vectors[i].length, digest, &digest_len) <= 0 ||
            !compare_hex("34.101.77 A.3", digest, digest_len,
                         vectors[i].expected))
            return 0;
    return 1;
}

static int check_hmac_hbelt(const unsigned char h[256])
{
    static const struct {
        size_t key_len;
        const char *expected;
    } vectors[] = {
        {29, "D4828E6312B08BB83C9FA6535A463554"
             "9E411FD11C0D8289359A1130E930676B"},
        {32, "41FFE8645AEC0612E952D2CDF8DD508F"
             "3E4A1D9B53F6A1DB293B19FE76B1879F"},
        {42, "7D01B84D2315C332277B3653D7EC6470"
             "7EBA7CDFF7FF70077B1DECBD68F2A144"}
    };
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "belt-hmac", "provider=bee2");
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    unsigned char result[64];
    size_t i, result_len;
    char digest_name[] = "belt-hash";
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, digest_name, sizeof(digest_name)),
        OSSL_PARAM_END
    };
    int ok = 0;

    if (ctx == NULL)
        goto end;
    for (i = 0; i < sizeof(vectors) / sizeof(vectors[0]); ++i)
        if (EVP_MAC_init(ctx, h + 128, vectors[i].key_len, params) <= 0 ||
            EVP_MAC_update(ctx, h + 192, 32) <= 0 ||
            EVP_MAC_final(ctx, result, &result_len, sizeof(result)) <= 0 ||
            result_len != 32 ||
            !compare_hex("34.101.47 B.1 HMAC-HBELT", result,
                         result_len, vectors[i].expected))
            goto end;
    ok = 1;
end:
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    OPENSSL_cleanse(result, sizeof(result));
    return ok;
}

static int check_belt_key_expansion(const unsigned char h[256])
{
    static const char *const modes[] = {"ecb", "cbc", "cfb", "ctr"};
    unsigned char key128[32], key192[32], msg[48], actual[48], expanded[48];
    unsigned char reference128[32], reference192[32];
    unsigned char mac_small[8], mac_expanded[8];
    unsigned char *keys[] = {key128, key192};
    unsigned char *references[] = {reference128, reference192};
    size_t lengths[] = {16, 24};
    EVP_CIPHER *small_cipher = NULL, *wide_cipher = NULL;
    EVP_CIPHER_CTX *small = NULL, *wide = NULL;
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *mc = NULL;
    size_t i, j, len_a, len_b;
    int out_a, out_b, fin_a, fin_b, ok = 0;
    char small_name[32], wide_name[32];

    memcpy(key128, h + 128, 16);
    memcpy(key192, h + 128, 24);
    memcpy(reference128, h + 128, 16);
    memcpy(reference128 + 16, h + 128, 16);
    memcpy(reference192, h + 128, 24);
    /* STB 34.101.31 A.27: last two words of an expanded 192-bit key. */
    if (!from_hex(reference192 + 24, 8, "4B09A17E8450BF66"))
        goto end;
    memcpy(msg, h, sizeof(msg));
    for (i = 0; i < 2; ++i) {
        for (j = 0; j < sizeof(modes) / sizeof(modes[0]); ++j) {
            snprintf(small_name, sizeof(small_name), "belt-%s%u",
                     modes[j], (unsigned)(lengths[i] * 8));
            snprintf(wide_name, sizeof(wide_name), "belt-%s256", modes[j]);
            small_cipher = EVP_CIPHER_fetch(NULL, small_name, "provider=bee2");
            wide_cipher = EVP_CIPHER_fetch(NULL, wide_name, "provider=bee2");
            small = EVP_CIPHER_CTX_new();
            wide = EVP_CIPHER_CTX_new();
            if (small == NULL || wide == NULL || small_cipher == NULL || wide_cipher == NULL ||
                EVP_EncryptInit_ex2(small, small_cipher, keys[i],
                                    j == 0 ? NULL : h + 192, NULL) <= 0 ||
                EVP_EncryptInit_ex2(wide, wide_cipher, references[i],
                                    j == 0 ? NULL : h + 192, NULL) <= 0 ||
                EVP_CIPHER_CTX_set_padding(small, 0) <= 0 ||
                EVP_CIPHER_CTX_set_padding(wide, 0) <= 0 ||
                EVP_EncryptUpdate(small, actual, &out_a, msg, sizeof(msg)) <= 0 ||
                EVP_EncryptUpdate(wide, expanded, &out_b, msg, sizeof(msg)) <= 0 ||
                EVP_EncryptFinal_ex(small, actual + out_a, &fin_a) <= 0 ||
                EVP_EncryptFinal_ex(wide, expanded + out_b, &fin_b) <= 0 ||
                out_a + fin_a != out_b + fin_b ||
                CRYPTO_memcmp(actual, expanded, (size_t)(out_a + fin_a)) != 0)
                goto end;
            EVP_CIPHER_CTX_free(small);
            EVP_CIPHER_CTX_free(wide);
            EVP_CIPHER_free(small_cipher);
            EVP_CIPHER_free(wide_cipher);
            small = wide = NULL;
            small_cipher = wide_cipher = NULL;
        }
    }
    mac = EVP_MAC_fetch(NULL, "belt-mac256", "provider=bee2");
    mc = EVP_MAC_CTX_new(mac);
    if (mc == NULL)
        goto end;
    for (i = 0; i < 2; ++i) {
        EVP_MAC *small_mac = EVP_MAC_fetch(NULL,
                            i == 0 ? "belt-mac128" : "belt-mac192", "provider=bee2");
        EVP_MAC_CTX *small_ctx = EVP_MAC_CTX_new(small_mac);
        int passed = small_ctx != NULL &&
                     EVP_MAC_init(small_ctx, keys[i], lengths[i], NULL) > 0 &&
                     EVP_MAC_update(small_ctx, msg, sizeof(msg)) > 0 &&
                     EVP_MAC_final(small_ctx, mac_small, &len_a, sizeof(mac_small)) > 0 &&
                     EVP_MAC_init(mc, references[i], 32, NULL) > 0 &&
                     EVP_MAC_update(mc, msg, sizeof(msg)) > 0 &&
                     EVP_MAC_final(mc, mac_expanded, &len_b, sizeof(mac_expanded)) > 0 &&
                     len_a == 8 && len_b == 8 &&
                     CRYPTO_memcmp(mac_small, mac_expanded, 8) == 0;
        EVP_MAC_CTX_free(small_ctx);
        EVP_MAC_free(small_mac);
        if (!passed)
            goto end;
    }
    ok = 1;
end:
    EVP_MAC_CTX_free(mc);
    EVP_MAC_free(mac);
    EVP_CIPHER_CTX_free(small);
    EVP_CIPHER_CTX_free(wide);
    EVP_CIPHER_free(small_cipher);
    EVP_CIPHER_free(wide_cipher);
    OPENSSL_cleanse(key128, sizeof(key128));
    OPENSSL_cleanse(key192, sizeof(key192));
    OPENSSL_cleanse(reference128, sizeof(reference128));
    OPENSSL_cleanse(reference192, sizeof(reference192));
    OPENSSL_cleanse(msg, sizeof(msg));
    OPENSSL_cleanse(actual, sizeof(actual));
    OPENSSL_cleanse(expanded, sizeof(expanded));
    return ok;
}

int main(int argc, char **argv)
{
    static const char bde_expected[] =
        "7041BC226352C706D00EA8EF23CFE46A"
        "FAE118577D037FACDC36E4ECC1F65746"
        "09F236943FB809E1BEE4A1C686C13ACC";
    static const char sde_expected[] =
        "E9FDF3F788657332E6C46FCF5251B8A6"
        "D43543A93E3233837DB1571183A6EF4D"
        "7FEB5CDF999E1A3F51A5A3381BEB7FA5";
    static const char token_g4[] =
        "9B4EA669DABDF100A7D4B6E6EB76EE52"
        "51912531F426750AAC8A9DBB51C54D8D"
        "EB9289B50A46952D0531861E45A8814B"
        "008FDC65DE9FF1FA2A1F16B6A280E957"
        "A814";
    static const char token_g5[] =
        "4856093A0F6C13015FC8E15F1B23A762"
        "02D2F4BA6E5EC52B78658477F6486DE6"
        "87AFAEEA0EF7BC1326A7DCE7A10BA10E"
        "3F91C0126044B22267BF30BD6F1DA29E"
        "0647CF39C1D59A56BB0194E0F4F8A2BB";
    OSSL_PROVIDER *def = NULL, *bee2 = NULL;
    unsigned char h[256];
    int ok = 0;

    if (argc != 2)
        return 2;
    if (!from_hex(h, sizeof(h), h_hex) ||
        !OSSL_PROVIDER_set_default_search_path(NULL, argv[1]))
        return 1;
    def = OSSL_PROVIDER_load(NULL, "default");
    bee2 = OSSL_PROVIDER_load(NULL, "bee2_provider");
    if (def == NULL || bee2 == NULL || !check_belt_block_vectors(h) ||
        !check_belt_hashes(h) || !check_bash_hashes(h) ||
        !check_hmac_hbelt(h) || !check_belt_key_expansion(h) ||
        !check_belt_mac(h) ||
        !decrypt_belt("belt-bde256", h, bde_expected) ||
        !decrypt_belt("belt-sde256", h, sde_expected) ||
        !check_belt_kwp_encrypt(h) || !check_belt_kwp_decrypt(h) ||
        !check_pbkdf_and_kwp(h) ||
        !check_bign_transport(h, "G.4", token_g4, 66, 18, 32) ||
        !check_bign_transport(h, "G.5", token_g5, 80, 32, 64))
        goto end;
    ok = 1;
end:
    OPENSSL_cleanse(h, sizeof(h));
    OSSL_PROVIDER_unload(bee2);
    OSSL_PROVIDER_unload(def);
    return ok ? 0 : 1;
}
