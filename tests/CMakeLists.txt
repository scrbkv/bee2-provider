if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Werror)
endif()

find_package(Python3 COMPONENTS Interpreter REQUIRED)
find_program(BEE2_OPENSSL_EXECUTABLE NAMES openssl REQUIRED)

option(BEE2_PROVIDER_ENABLE_INTEROP "Register bee2evp engine interoperability tests" OFF)

add_executable(bee2_provider_algorithms provider_algorithms.c)
target_link_libraries(bee2_provider_algorithms PRIVATE OpenSSL::Crypto)
add_test(NAME bee2_provider_algorithms
    COMMAND bee2_provider_algorithms $<TARGET_FILE_DIR:bee2_provider>)
set_tests_properties(bee2_provider_algorithms PROPERTIES LABELS "crypto;registration;native")

add_executable(bee2_stb_kat stb_kat.c)
target_link_libraries(bee2_stb_kat PRIVATE OpenSSL::Crypto)
add_test(NAME bee2_stb_kat COMMAND bee2_stb_kat $<TARGET_FILE_DIR:bee2_provider>)
set_tests_properties(bee2_stb_kat PROPERTIES LABELS "stb;known_answer;crypto;native")


if(BEE2_PROVIDER_ENABLE_INTEROP)
set(BEE2_INTEROP_PROVIDER_OPENSSL "$ENV{BEE2_INTEROP_PROVIDER_OPENSSL}" CACHE STRING
    "OpenSSL executable used for bee2_provider interop commands")
if(NOT BEE2_INTEROP_PROVIDER_OPENSSL)
    set(BEE2_INTEROP_PROVIDER_OPENSSL "openssl" CACHE STRING
        "OpenSSL executable used for bee2_provider interop commands" FORCE)
endif()

set(BEE2_INTEROP_BEE2EVP_OPENSSL "$ENV{BEE2EVP_OPENSSL}" CACHE STRING
    "OpenSSL executable used for bee2evp interop commands")
if(NOT BEE2_INTEROP_BEE2EVP_OPENSSL AND DEFINED ENV{BEE2_OPENSSL})
    set(BEE2_INTEROP_BEE2EVP_OPENSSL "$ENV{BEE2_OPENSSL}" CACHE STRING
        "OpenSSL executable used for bee2evp interop commands" FORCE)
endif()
if(NOT BEE2_INTEROP_BEE2EVP_OPENSSL)
    set(BEE2_INTEROP_BEE2EVP_OPENSSL "openssl" CACHE STRING
        "OpenSSL executable used for bee2evp interop commands" FORCE)
endif()

set(BEE2_INTEROP_BEE2EVP_ENGINE "$ENV{BEE2EVP_ENGINE}" CACHE STRING
    "bee2evp engine name used in interop commands")
if(NOT BEE2_INTEROP_BEE2EVP_ENGINE)
    set(BEE2_INTEROP_BEE2EVP_ENGINE "bee2evp" CACHE STRING
        "bee2evp engine name used in interop commands" FORCE)
endif()

set(BEE2_INTEROP_BEE2EVP_LD_LIBRARY_PATH "$ENV{BEE2EVP_LD_LIBRARY_PATH}" CACHE STRING
    "LD_LIBRARY_PATH prepended for bee2evp interop commands")
if(NOT BEE2_INTEROP_BEE2EVP_LD_LIBRARY_PATH)
    set(BEE2_INTEROP_BEE2EVP_LD_LIBRARY_PATH "-" CACHE STRING
        "LD_LIBRARY_PATH prepended for bee2evp interop commands" FORCE)
endif()

set(BEE2_INTEROP_BEE2EVP_OPENSSL_CONF "$ENV{BEE2EVP_OPENSSL_CONF}" CACHE STRING
    "OPENSSL_CONF used for bee2evp interop commands")
if(NOT BEE2_INTEROP_BEE2EVP_OPENSSL_CONF)
    set(BEE2_INTEROP_BEE2EVP_OPENSSL_CONF "-" CACHE STRING
        "OPENSSL_CONF used for bee2evp interop commands" FORCE)
endif()

function(add_bee2_bee2evp_cipher_test test_name provider_name bee2evp_name key_size iv_size data_len)
    set(spec
        "cipher|${BEE2_INTEROP_PROVIDER_OPENSSL}|${BEE2_INTEROP_BEE2EVP_OPENSSL}|${BEE2_INTEROP_BEE2EVP_ENGINE}|${BEE2_INTEROP_BEE2EVP_LD_LIBRARY_PATH}|${BEE2_INTEROP_BEE2EVP_OPENSSL_CONF}|$<TARGET_FILE_DIR:bee2_provider>|${provider_name}|${bee2evp_name}|${data_len}|${key_size}|${iv_size}|-|-"
    )
    add_test(
        NAME ${test_name}
        COMMAND
            ${Python3_EXECUTABLE}
            ${CMAKE_SOURCE_DIR}/tests/openssl_bee2evp_interop.py
            "${spec}"
    )
endfunction()

function(add_bee2_bee2evp_digest_test test_name provider_name bee2evp_name data_len)
    set(spec
        "digest|${BEE2_INTEROP_PROVIDER_OPENSSL}|${BEE2_INTEROP_BEE2EVP_OPENSSL}|${BEE2_INTEROP_BEE2EVP_ENGINE}|${BEE2_INTEROP_BEE2EVP_LD_LIBRARY_PATH}|${BEE2_INTEROP_BEE2EVP_OPENSSL_CONF}|$<TARGET_FILE_DIR:bee2_provider>|${provider_name}|${bee2evp_name}|${data_len}|0|0|-|-"
    )
    add_test(
        NAME ${test_name}
        COMMAND
            ${Python3_EXECUTABLE}
            ${CMAKE_SOURCE_DIR}/tests/openssl_bee2evp_interop.py
            "${spec}"
    )
endfunction()

function(add_bee2_bee2evp_mac_test test_name provider_name bee2evp_name key_size data_len)
    set(options)
    set(one_value_args PROVIDER_DIGEST BEE2EVP_DIGEST)
    cmake_parse_arguments(MAC "${options}" "${one_value_args}" "" ${ARGN})

    set(provider_digest "-")
    set(bee2evp_digest "-")
    if(MAC_PROVIDER_DIGEST)
        set(provider_digest "${MAC_PROVIDER_DIGEST}")
    endif()
    if(MAC_BEE2EVP_DIGEST)
        set(bee2evp_digest "${MAC_BEE2EVP_DIGEST}")
    endif()
    set(spec
        "mac|${BEE2_INTEROP_PROVIDER_OPENSSL}|${BEE2_INTEROP_BEE2EVP_OPENSSL}|${BEE2_INTEROP_BEE2EVP_ENGINE}|${BEE2_INTEROP_BEE2EVP_LD_LIBRARY_PATH}|${BEE2_INTEROP_BEE2EVP_OPENSSL_CONF}|$<TARGET_FILE_DIR:bee2_provider>|${provider_name}|${bee2evp_name}|${data_len}|${key_size}|0|${provider_digest}|${bee2evp_digest}"
    )

    add_test(
        NAME ${test_name}
        COMMAND
            ${Python3_EXECUTABLE}
            ${CMAKE_SOURCE_DIR}/tests/openssl_bee2evp_interop.py
            "${spec}"
    )
endfunction()

function(add_bee2_bee2evp_bign_cert_test test_name provider_alg bee2evp_alg)
    set(options EXPLICIT_BEE2)
    set(one_value_args DAYS)
    cmake_parse_arguments(BIGN "${options}" "${one_value_args}" "" ${ARGN})

    if(NOT BIGN_DAYS)
        set(BIGN_DAYS 30)
    endif()

    set(explicit_flag 0)
    if(BIGN_EXPLICIT_BEE2)
        set(explicit_flag 1)
    endif()
    set(spec
        "${BEE2_INTEROP_PROVIDER_OPENSSL}|${BEE2_INTEROP_BEE2EVP_OPENSSL}|${BEE2_INTEROP_BEE2EVP_ENGINE}|${BEE2_INTEROP_BEE2EVP_LD_LIBRARY_PATH}|${BEE2_INTEROP_BEE2EVP_OPENSSL_CONF}|$<TARGET_FILE_DIR:bee2_provider>|${provider_alg}|${bee2evp_alg}|${explicit_flag}|${BIGN_DAYS}"
    )

    add_test(
        NAME ${test_name}
        COMMAND
            ${Python3_EXECUTABLE}
            ${CMAKE_SOURCE_DIR}/tests/openssl_bign_cert_interop.py
            "${spec}"
    )
endfunction()

add_bee2_bee2evp_cipher_test(bee2_bee2evp_interop_cipher_belt_128_ecb belt-ecb128 belt-ecb128 16 0 32)
set_property(TEST bee2_bee2evp_interop_cipher_belt_128_ecb APPEND PROPERTY LABELS interop bee2evp cipher_belt_128_ecb)
add_bee2_bee2evp_cipher_test(bee2_bee2evp_interop_cipher_belt_192_ecb belt-ecb192 belt-ecb192 24 0 32)
set_property(TEST bee2_bee2evp_interop_cipher_belt_192_ecb APPEND PROPERTY LABELS interop bee2evp cipher_belt_192_ecb)
add_bee2_bee2evp_cipher_test(bee2_bee2evp_interop_cipher_belt_256_ecb belt-ecb256 belt-ecb256 32 0 32)
set_property(TEST bee2_bee2evp_interop_cipher_belt_256_ecb APPEND PROPERTY LABELS interop bee2evp cipher_belt_256_ecb)
add_bee2_bee2evp_cipher_test(bee2_bee2evp_interop_cipher_belt_128_cbc belt-cbc128 belt-cbc128 16 16 32)
set_property(TEST bee2_bee2evp_interop_cipher_belt_128_cbc APPEND PROPERTY LABELS interop bee2evp cipher_belt_128_cbc)
add_bee2_bee2evp_cipher_test(bee2_bee2evp_interop_cipher_belt_192_cbc belt-cbc192 belt-cbc192 24 16 32)
set_property(TEST bee2_bee2evp_interop_cipher_belt_192_cbc APPEND PROPERTY LABELS interop bee2evp cipher_belt_192_cbc)
add_bee2_bee2evp_cipher_test(bee2_bee2evp_interop_cipher_belt_256_cbc belt-cbc256 belt-cbc256 32 16 32)
set_property(TEST bee2_bee2evp_interop_cipher_belt_256_cbc APPEND PROPERTY LABELS interop bee2evp cipher_belt_256_cbc)
add_bee2_bee2evp_cipher_test(bee2_bee2evp_interop_cipher_belt_128_cfb belt-cfb128 belt-cfb128 16 16 32)
set_property(TEST bee2_bee2evp_interop_cipher_belt_128_cfb APPEND PROPERTY LABELS interop bee2evp cipher_belt_128_cfb)
add_bee2_bee2evp_cipher_test(bee2_bee2evp_interop_cipher_belt_192_cfb belt-cfb192 belt-cfb192 24 16 32)
set_property(TEST bee2_bee2evp_interop_cipher_belt_192_cfb APPEND PROPERTY LABELS interop bee2evp cipher_belt_192_cfb)
add_bee2_bee2evp_cipher_test(bee2_bee2evp_interop_cipher_belt_256_cfb belt-cfb256 belt-cfb256 32 16 32)
set_property(TEST bee2_bee2evp_interop_cipher_belt_256_cfb APPEND PROPERTY LABELS interop bee2evp cipher_belt_256_cfb)
add_bee2_bee2evp_cipher_test(bee2_bee2evp_interop_cipher_belt_128_ctr belt-ctr128 belt-ctr128 16 16 32)
set_property(TEST bee2_bee2evp_interop_cipher_belt_128_ctr APPEND PROPERTY LABELS interop bee2evp cipher_belt_128_ctr)
add_bee2_bee2evp_cipher_test(bee2_bee2evp_interop_cipher_belt_192_ctr belt-ctr192 belt-ctr192 24 16 32)
set_property(TEST bee2_bee2evp_interop_cipher_belt_192_ctr APPEND PROPERTY LABELS interop bee2evp cipher_belt_192_ctr)
add_bee2_bee2evp_cipher_test(bee2_bee2evp_interop_cipher_belt_256_ctr belt-ctr256 belt-ctr256 32 16 32)
set_property(TEST bee2_bee2evp_interop_cipher_belt_256_ctr APPEND PROPERTY LABELS interop bee2evp cipher_belt_256_ctr)

add_bee2_bee2evp_mac_test(bee2_bee2evp_interop_mac_belt_mac256 belt-mac256 belt-mac256 32 257)
set_property(TEST bee2_bee2evp_interop_mac_belt_mac256 APPEND PROPERTY LABELS interop bee2evp mac_belt_mac256)
add_bee2_bee2evp_mac_test(bee2_bee2evp_interop_mac_belt_hmac belt-hmac belt-hmac 32 257 PROVIDER_DIGEST belt-hash)
set_property(TEST bee2_bee2evp_interop_mac_belt_hmac APPEND PROPERTY LABELS interop bee2evp mac_belt_hmac)

add_bee2_bee2evp_digest_test(bee2_bee2evp_interop_digest_belt_hash belt-hash belt-hash 257)
set_property(TEST bee2_bee2evp_interop_digest_belt_hash APPEND PROPERTY LABELS interop bee2evp digest_belt_hash)
add_bee2_bee2evp_digest_test(bee2_bee2evp_interop_digest_bash_256 bash256 bash256 257)
set_property(TEST bee2_bee2evp_interop_digest_bash_256 APPEND PROPERTY LABELS interop bee2evp digest_bash_256)
add_bee2_bee2evp_digest_test(bee2_bee2evp_interop_digest_bash_384 bash384 bash384 257)
set_property(TEST bee2_bee2evp_interop_digest_bash_384 APPEND PROPERTY LABELS interop bee2evp digest_bash_384)
add_bee2_bee2evp_digest_test(bee2_bee2evp_interop_digest_bash_512 bash512 bash512 257)
set_property(TEST bee2_bee2evp_interop_digest_bash_512 APPEND PROPERTY LABELS interop bee2evp digest_bash_512)

add_bee2_bee2evp_bign_cert_test(bee2_bee2evp_bign_cert_interop_bign_cert_256 bign-256 bign-256 DAYS 30)
set_property(TEST bee2_bee2evp_bign_cert_interop_bign_cert_256 APPEND PROPERTY LABELS interop bee2evp bign cert bign_cert_256)
add_bee2_bee2evp_bign_cert_test(bee2_bee2evp_bign_cert_interop_bign_cert_384 bign-384 bign-384 DAYS 30)
set_property(TEST bee2_bee2evp_bign_cert_interop_bign_cert_384 APPEND PROPERTY LABELS interop bee2evp bign cert bign_cert_384)
add_bee2_bee2evp_bign_cert_test(bee2_bee2evp_bign_cert_interop_bign_cert_512 bign-512 bign-512 DAYS 30)
set_property(TEST bee2_bee2evp_bign_cert_interop_bign_cert_512 APPEND PROPERTY LABELS interop bee2evp bign cert bign_cert_512)
add_bee2_bee2evp_bign_cert_test(bee2_bee2evp_bign_cert_interop_bign_cert_256_explicit bign-256 bign-256 EXPLICIT_BEE2 DAYS 30)
set_property(TEST bee2_bee2evp_bign_cert_interop_bign_cert_256_explicit APPEND PROPERTY LABELS interop bee2evp bign cert bign_cert_256_explicit)
add_bee2_bee2evp_bign_cert_test(bee2_bee2evp_bign_cert_interop_bign_cert_384_explicit bign-384 bign-384 EXPLICIT_BEE2 DAYS 30)
set_property(TEST bee2_bee2evp_bign_cert_interop_bign_cert_384_explicit APPEND PROPERTY LABELS interop bee2evp bign cert bign_cert_384_explicit)
add_bee2_bee2evp_bign_cert_test(bee2_bee2evp_bign_cert_interop_bign_cert_512_explicit bign-512 bign-512 EXPLICIT_BEE2 DAYS 30)
set_property(TEST bee2_bee2evp_bign_cert_interop_bign_cert_512_explicit APPEND PROPERTY LABELS interop bee2evp bign cert bign_cert_512_explicit)

endif()

# Independent key-expansion KAT from STB 34.101.31-2020, 8.1.2 / A.27.
add_executable(bee2_belt_keyexpand_stb belt_keyexpand_stb.c)
target_include_directories(bee2_belt_keyexpand_stb PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_include_directories(bee2_belt_keyexpand_stb SYSTEM PRIVATE ${CMAKE_SOURCE_DIR}/bee2/include)
target_link_libraries(bee2_belt_keyexpand_stb PRIVATE bee2_static OpenSSL::Crypto)
add_test(NAME bee2_belt_keyexpand_stb COMMAND bee2_belt_keyexpand_stb)
set_tests_properties(bee2_belt_keyexpand_stb PROPERTIES LABELS "regression;stb;belt;native")

add_executable(bee2_brng_kat brng_kat.c)
target_link_libraries(bee2_brng_kat PRIVATE OpenSSL::Crypto)

set(BEE2_BRNG_ALGS
    brng-ctr-hbelt
    brng-hmac-hbelt
)
foreach(alg IN LISTS BEE2_BRNG_ALGS)
    string(REPLACE "-" "_" alg_id "${alg}")
    set(test_name "bee2_brng_kat_${alg_id}")
    add_test(
        NAME ${test_name}
        COMMAND
            bee2_brng_kat
            $<TARGET_FILE_DIR:bee2_provider>
            ${alg}
    )
    set_property(TEST ${test_name} APPEND PROPERTY LABELS regression brng ${alg_id})
endforeach()

add_executable(bee2_bign_sign_contract bign_sign_contract.c)
target_link_libraries(bee2_bign_sign_contract PRIVATE OpenSSL::Crypto)

add_executable(bee2_bign_keyexchange_contract bign_keyexchange_contract.c)
target_link_libraries(bee2_bign_keyexchange_contract PRIVATE OpenSSL::Crypto)

add_test(
    NAME bee2_bign_options
    COMMAND
        ${Python3_EXECUTABLE}
        ${CMAKE_SOURCE_DIR}/tests/bign_options.py
        --provider-path $<TARGET_FILE_DIR:bee2_provider>
        --openssl ${BEE2_OPENSSL_EXECUTABLE}
)
set_property(TEST bee2_bign_options APPEND PROPERTY LABELS regression bign)

set(BEE2_BIGN_ALGS
    bign-256
    bign-384
    bign-512
)
foreach(alg IN LISTS BEE2_BIGN_ALGS)
    string(REPLACE "-" "_" alg_id "${alg}")
    set(test_name "bee2_bign_sign_contract_${alg_id}")
    add_test(
        NAME ${test_name}
        COMMAND
            bee2_bign_sign_contract
            $<TARGET_FILE_DIR:bee2_provider>
            ${alg}
    )
    set_property(TEST ${test_name} APPEND PROPERTY LABELS regression bign ${alg_id})

    set(keyexchange_test_name "bee2_bign_keyexchange_contract_${alg_id}")
    add_test(
        NAME ${keyexchange_test_name}
        COMMAND
            bee2_bign_keyexchange_contract
            $<TARGET_FILE_DIR:bee2_provider>
            ${alg}
    )
    set_property(TEST ${keyexchange_test_name} APPEND PROPERTY
        LABELS regression bign keyexchange ${alg_id})
endforeach()

add_executable(bee2_cipher_roundtrip cipher_roundtrip.c)
target_link_libraries(bee2_cipher_roundtrip PRIVATE OpenSSL::Crypto)

set(BEE2_CIPHER_COVERAGE_ALGS
    belt-ecb128
    belt-ecb192
    belt-ecb256
    belt-cbc128
    belt-cbc192
    belt-cbc256
    belt-cfb128
    belt-cfb192
    belt-cfb256
    belt-ctr128
    belt-ctr192
    belt-ctr256
    belt-bde128
    belt-bde192
    belt-bde256
    belt-che128
    belt-che192
    belt-che256
    belt-dwp128
    belt-dwp192
    belt-dwp256
    bash-prg-ae1281
    bash-prg-ae1282
    bash-prg-ae1921
    bash-prg-ae1922
    bash-prg-ae2561
    bash-prg-ae2562
    belt-sde128
    belt-sde192
    belt-sde256
    belt-kwp128
    belt-kwp192
    belt-kwp256
)
foreach(alg IN LISTS BEE2_CIPHER_COVERAGE_ALGS)
    string(REPLACE "-" "_" alg_id "${alg}")
    set(test_name "bee2_cipher_roundtrip_${alg_id}")
    add_test(
        NAME ${test_name}
        COMMAND
            bee2_cipher_roundtrip
            $<TARGET_FILE_DIR:bee2_provider>
            ${alg}
    )
    set_property(TEST ${test_name} APPEND PROPERTY LABELS regression cipher ${alg_id})
endforeach()

# No STB example exists for every variant: compare the provider against
# the pinned Bee2 high-level API, including deterministic random data.
add_executable(bee2_direct_interop bee2_direct_interop.c)
target_include_directories(bee2_direct_interop SYSTEM PRIVATE ${CMAKE_SOURCE_DIR}/bee2/include)
target_link_libraries(bee2_direct_interop PRIVATE bee2_static OpenSSL::Crypto)
add_test(NAME bee2_direct_interop
    COMMAND bee2_direct_interop $<TARGET_FILE_DIR:bee2_provider>)
set_tests_properties(bee2_direct_interop PROPERTIES LABELS "interop;bee2;all_variants")

add_executable(bee2_bign_direct_interop bee2_bign_direct_interop.c)
target_include_directories(bee2_bign_direct_interop SYSTEM PRIVATE ${CMAKE_SOURCE_DIR}/bee2/include)
target_link_libraries(bee2_bign_direct_interop PRIVATE bee2_static OpenSSL::Crypto)
add_test(NAME bee2_bign_direct_interop
    COMMAND bee2_bign_direct_interop $<TARGET_FILE_DIR:bee2_provider>)
set_tests_properties(bee2_bign_direct_interop PROPERTIES LABELS "interop;bee2;bign")

add_executable(bee2_params_atomicity params_atomicity.c)
target_link_libraries(bee2_params_atomicity PRIVATE OpenSSL::Crypto)
add_test(NAME bee2_params_atomicity
    COMMAND bee2_params_atomicity $<TARGET_FILE_DIR:bee2_provider>)
set_tests_properties(bee2_params_atomicity PROPERTIES LABELS "regression;params;native")

add_executable(bee2_provider_negative_contract provider_negative_contract.c)
target_link_libraries(bee2_provider_negative_contract PRIVATE OpenSSL::Crypto)
add_test(NAME bee2_provider_negative_contract
    COMMAND bee2_provider_negative_contract $<TARGET_FILE_DIR:bee2_provider>)
set_tests_properties(bee2_provider_negative_contract
    PROPERTIES LABELS "regression;negative;native")

add_executable(bee2_evp_streaming_contract evp_streaming_contract.c)
target_link_libraries(bee2_evp_streaming_contract PRIVATE OpenSSL::Crypto)
add_test(NAME bee2_evp_streaming_contract
    COMMAND bee2_evp_streaming_contract $<TARGET_FILE_DIR:bee2_provider>)
set_tests_properties(bee2_evp_streaming_contract PROPERTIES LABELS "regression;evp")

add_executable(bee2_sde_min_sector sde_min_sector.c)
target_link_libraries(bee2_sde_min_sector PRIVATE OpenSSL::Crypto)
add_test(NAME bee2_sde_min_sector
    COMMAND bee2_sde_min_sector $<TARGET_FILE_DIR:bee2_provider>)
set_tests_properties(bee2_sde_min_sector PROPERTIES LABELS "regression;evp;belt;sde")

add_executable(bee2_evp_padding_contract evp_padding_contract.c)
target_link_libraries(bee2_evp_padding_contract PRIVATE OpenSSL::Crypto)
foreach(mode IN ITEMS ecb cbc)
    foreach(bits IN ITEMS 128 192 256)
        set(test_name "bee2_evp_padding_${mode}${bits}")
        add_test(NAME ${test_name}
            COMMAND bee2_evp_padding_contract
                $<TARGET_FILE_DIR:bee2_provider> "belt-${mode}${bits}")
        set_tests_properties(${test_name} PROPERTIES LABELS "regression;evp;padding")
    endforeach()
endforeach()

add_test(NAME bee2_bign_asn1_negative
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/bign_asn1_negative.py
        --provider-path $<TARGET_FILE_DIR:bee2_provider>
        --openssl ${BEE2_OPENSSL_EXECUTABLE})
set_tests_properties(bee2_bign_asn1_negative PROPERTIES LABELS "regression;bign;asn1")

add_test(NAME bee2_bign_codec_roundtrip
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/bign_codec_roundtrip.py
        --provider-path $<TARGET_FILE_DIR:bee2_provider>
        --openssl ${BEE2_OPENSSL_EXECUTABLE})
set_tests_properties(bee2_bign_codec_roundtrip PROPERTIES LABELS "regression;bign;codec")

add_executable(bee2_bign_der_framing bign_der_framing.c)
target_link_libraries(bee2_bign_der_framing PRIVATE OpenSSL::Crypto)
add_test(NAME bee2_bign_der_framing COMMAND bee2_bign_der_framing)
set_tests_properties(bee2_bign_der_framing PROPERTIES LABELS "regression;bign;asn1")

add_executable(bee2_bign_public_check bign_public_check.c)
target_link_libraries(bee2_bign_public_check PRIVATE OpenSSL::Crypto)
add_test(NAME bee2_bign_public_check
    COMMAND bee2_bign_public_check $<TARGET_FILE_DIR:bee2_provider>)
set_tests_properties(bee2_bign_public_check PROPERTIES LABELS "regression;bign")

add_executable(bee2_provider_contexts provider_contexts.c)
target_link_libraries(bee2_provider_contexts PRIVATE OpenSSL::Crypto)
add_test(NAME bee2_provider_contexts
    COMMAND bee2_provider_contexts $<TARGET_FILE_DIR:bee2_provider>)
set_tests_properties(bee2_provider_contexts PROPERTIES LABELS "regression;provider")

add_executable(bee2_bde_mode_metadata bde_mode_metadata.c)
target_link_libraries(bee2_bde_mode_metadata PRIVATE OpenSSL::Crypto)
add_test(NAME bee2_bde_mode_metadata
    COMMAND bee2_bde_mode_metadata $<TARGET_FILE_DIR:bee2_provider>)
set_tests_properties(bee2_bde_mode_metadata PROPERTIES LABELS "regression;evp;belt;bde")

add_executable(bee2_brng_contract brng_contract.c)
target_link_libraries(bee2_brng_contract PRIVATE OpenSSL::Crypto)
add_test(NAME bee2_brng_contract
    COMMAND bee2_brng_contract $<TARGET_FILE_DIR:bee2_provider>)
set_tests_properties(bee2_brng_contract PROPERTIES LABELS "regression;rand;brng")

add_executable(bee2_provider_isolation provider_isolation.c)
target_link_libraries(bee2_provider_isolation PRIVATE OpenSSL::Crypto)
add_test(NAME bee2_provider_isolation
    COMMAND bee2_provider_isolation $<TARGET_FILE_DIR:bee2_provider>)
set_tests_properties(bee2_provider_isolation PROPERTIES LABELS "regression;provider;libctx;bign")
# Appendix KATs for BELT and BASH are exercised by bee2_stb_kat above.

add_executable(bee2_belt_aead_stb belt_aead_stb.c)
target_link_libraries(bee2_belt_aead_stb PRIVATE OpenSSL::Crypto)
add_test(NAME bee2_belt_aead_stb
    COMMAND bee2_belt_aead_stb $<TARGET_FILE_DIR:bee2_provider>)
set_tests_properties(bee2_belt_aead_stb PROPERTIES LABELS "stb;known_answer;belt;aead;native")

add_executable(bee2_digest_oneshot digest_oneshot.c)
target_link_libraries(bee2_digest_oneshot PRIVATE OpenSSL::Crypto)
add_test(NAME bee2_digest_oneshot
    COMMAND bee2_digest_oneshot $<TARGET_FILE_DIR:bee2_provider>)
set_tests_properties(bee2_digest_oneshot PROPERTIES LABELS "regression;evp;digest;native")

add_executable(bee2_bash_prgae_stb bash_prgae_stb.c)
target_link_libraries(bee2_bash_prgae_stb PRIVATE OpenSSL::Crypto)
add_test(NAME bee2_bash_prgae_stb
    COMMAND bee2_bash_prgae_stb $<TARGET_FILE_DIR:bee2_provider>)
set_tests_properties(bee2_bash_prgae_stb PROPERTIES LABELS "stb;known_answer;bash;aead;native")

add_executable(bee2_bash_prgae_streaming bash_prgae_streaming.c)
target_link_libraries(bee2_bash_prgae_streaming PRIVATE OpenSSL::Crypto)
add_test(NAME bee2_bash_prgae_streaming
    COMMAND bee2_bash_prgae_streaming $<TARGET_FILE_DIR:bee2_provider>)
set_tests_properties(bee2_bash_prgae_streaming PROPERTIES LABELS "regression;bash;aead;evp;native")

add_executable(bee2_belt_reinit_padding belt_reinit_padding.c)
target_link_libraries(bee2_belt_reinit_padding PRIVATE OpenSSL::Crypto)
add_test(NAME bee2_belt_reinit_padding
    COMMAND bee2_belt_reinit_padding $<TARGET_FILE_DIR:bee2_provider>)
set_tests_properties(bee2_belt_reinit_padding PROPERTIES LABELS "regression;belt;evp;native")

add_executable(bee2_bign_stb_verify bign_stb_verify.c)
target_link_libraries(bee2_bign_stb_verify PRIVATE OpenSSL::Crypto)
add_test(NAME bee2_bign_stb_verify
    COMMAND bee2_bign_stb_verify $<TARGET_FILE_DIR:bee2_provider>)
set_tests_properties(bee2_bign_stb_verify PROPERTIES LABELS "stb;known_answer;bign;native")

add_executable(bee2_bign_transport_contract bign_transport_contract.c)
target_link_libraries(bee2_bign_transport_contract PRIVATE OpenSSL::Crypto)
add_test(NAME bee2_bign_transport_contract
    COMMAND bee2_bign_transport_contract $<TARGET_FILE_DIR:bee2_provider>)
set_tests_properties(bee2_bign_transport_contract PROPERTIES LABELS "regression;bign;transport;native")

add_executable(bee2_bign_params_contract bign_params_contract.c)
target_link_libraries(bee2_bign_params_contract PRIVATE OpenSSL::Crypto)
add_test(NAME bee2_bign_params_contract
    COMMAND bee2_bign_params_contract $<TARGET_FILE_DIR:bee2_provider>)
set_tests_properties(bee2_bign_params_contract PROPERTIES LABELS "regression;bign;params;native")

# The engine is built separately; keep these tests explicit and mandatory when
# BEE2_PROVIDER_ENABLE_INTEROP is enabled. The matrix checks both encryption
# directions for boundary values and deterministic pseudorandom inputs.
if(BEE2_PROVIDER_ENABLE_INTEROP)
    set(interop_prefix
        "${BEE2_INTEROP_PROVIDER_OPENSSL}|${BEE2_INTEROP_BEE2EVP_OPENSSL}|${BEE2_INTEROP_BEE2EVP_ENGINE}|${BEE2_INTEROP_BEE2EVP_LD_LIBRARY_PATH}|${BEE2_INTEROP_BEE2EVP_OPENSSL_CONF}|$<TARGET_FILE_DIR:bee2_provider>"
    )
    foreach(mode IN ITEMS ecb cbc cfb ctr)
        foreach(bits IN ITEMS 128 192 256)
            math(EXPR key_len "${bits} / 8")
            set(name "belt-${mode}${bits}")
            set(iv_len 16)
            if(mode STREQUAL "ecb")
                set(iv_len 0)
            endif()
            set(spec "cipher|${interop_prefix}|${name}|${name}|32|${key_len}|${iv_len}|-|-")
            set(test_name "bee2_interop_matrix_${name}")
            string(REPLACE "-" "_" test_name "${test_name}")
            add_test(NAME ${test_name}
                COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/openssl_bee2evp_matrix.py "${spec}")
            set_tests_properties(${test_name} PROPERTIES LABELS "interop;bee2evp;matrix")
        endforeach()
    endforeach()
    foreach(name IN ITEMS belt-hash bash256 bash384 bash512)
        set(spec "digest|${interop_prefix}|${name}|${name}|257|0|0|-|-")
        set(test_name "bee2_interop_matrix_${name}")
        string(REPLACE "-" "_" test_name "${test_name}")
        add_test(NAME ${test_name}
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/openssl_bee2evp_matrix.py "${spec}")
        set_tests_properties(${test_name} PROPERTIES LABELS "interop;bee2evp;matrix")
    endforeach()
    foreach(name IN ITEMS belt-mac256 belt-hmac)
        set(digest "-")
        if(name STREQUAL "belt-hmac")
            set(digest "belt-hash")
        endif()
        set(spec "mac|${interop_prefix}|${name}|${name}|257|32|0|${digest}|-")
        set(test_name "bee2_interop_matrix_${name}")
        string(REPLACE "-" "_" test_name "${test_name}")
        add_test(NAME ${test_name}
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/openssl_bee2evp_matrix.py "${spec}")
        set_tests_properties(${test_name} PROPERTIES LABELS "interop;bee2evp;matrix")
    endforeach()
endif()

# BIGN PKCS#8/SPKI cryptographic key serialization in PEM and DER.
add_executable(bee2_bign_legacy_pbkdf2_limit
    bign_legacy_pbkdf2_limit.c ${CMAKE_SOURCE_DIR}/src/bign_stb_pbes2.c)
target_include_directories(bee2_bign_legacy_pbkdf2_limit PRIVATE
    ${CMAKE_SOURCE_DIR}/src)
target_include_directories(bee2_bign_legacy_pbkdf2_limit SYSTEM PRIVATE
    ${CMAKE_SOURCE_DIR}/bee2/include)
target_link_libraries(bee2_bign_legacy_pbkdf2_limit PRIVATE
    bee2_static OpenSSL::Crypto)
add_test(NAME bee2_bign_legacy_pbkdf2_limit
    COMMAND bee2_bign_legacy_pbkdf2_limit)
set_tests_properties(bee2_bign_legacy_pbkdf2_limit
    PROPERTIES LABELS "regression;bign;pbkdf2;native")

add_executable(bee2_bign_codec_crypto bign_codec_crypto.c)
target_link_libraries(bee2_bign_codec_crypto PRIVATE OpenSSL::Crypto)
add_test(NAME bee2_bign_codec_crypto
    COMMAND bee2_bign_codec_crypto $<TARGET_FILE_DIR:bee2_provider>)
set_tests_properties(bee2_bign_codec_crypto PROPERTIES LABELS "bign;codec;crypto;native")
add_executable(bee2_hmac_bash_crypto hmac_bash_crypto.c)
target_link_libraries(bee2_hmac_bash_crypto PRIVATE OpenSSL::Crypto)
add_test(NAME bee2_hmac_bash_crypto
    COMMAND bee2_hmac_bash_crypto $<TARGET_FILE_DIR:bee2_provider>)
set_tests_properties(bee2_hmac_bash_crypto PROPERTIES LABELS "crypto;hmac;bash;native")

add_executable(bee2_bign_bake_crypto bign_bake_crypto.c)
target_include_directories(bee2_bign_bake_crypto SYSTEM PRIVATE ${CMAKE_SOURCE_DIR}/bee2/include)
target_link_libraries(bee2_bign_bake_crypto PRIVATE bee2_static OpenSSL::Crypto)
add_test(NAME bee2_bign_bake_crypto
    COMMAND bee2_bign_bake_crypto $<TARGET_FILE_DIR:bee2_provider>)
set_tests_properties(bee2_bign_bake_crypto PROPERTIES LABELS "crypto;interop;bign;bake;native")

add_executable(bee2_bign_digest_algorithms bign_digest_algorithms.c)
target_link_libraries(bee2_bign_digest_algorithms PRIVATE OpenSSL::Crypto)
add_test(NAME bee2_bign_digest_algorithms
    COMMAND bee2_bign_digest_algorithms $<TARGET_FILE_DIR:bee2_provider>)
set_tests_properties(bee2_bign_digest_algorithms PROPERTIES LABELS "crypto;bign;signature;native")

add_executable(bee2_bign_hspec_interop bign_hspec_interop.c)
target_include_directories(bee2_bign_hspec_interop SYSTEM PRIVATE ${CMAKE_SOURCE_DIR}/bee2/include)
target_link_libraries(bee2_bign_hspec_interop PRIVATE bee2_static OpenSSL::Crypto)
add_test(NAME bee2_bign_hspec_interop
    COMMAND bee2_bign_hspec_interop $<TARGET_FILE_DIR:bee2_provider>)
set_tests_properties(bee2_bign_hspec_interop PROPERTIES LABELS "interop;crypto;bign;hspec")

add_executable(bee2_bash_prgae_evp_stb bash_prgae_evp_stb.c)
target_link_libraries(bee2_bash_prgae_evp_stb PRIVATE OpenSSL::Crypto)
add_test(NAME bee2_bash_prgae_evp_stb
    COMMAND bee2_bash_prgae_evp_stb $<TARGET_FILE_DIR:bee2_provider>)
set_tests_properties(bee2_bash_prgae_evp_stb PROPERTIES LABELS "stb;known_answer;bash;aead;native")

