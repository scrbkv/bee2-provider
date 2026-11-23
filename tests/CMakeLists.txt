if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Werror)
endif()

find_program(BEE2_OPENSSL_EXECUTABLE NAMES openssl REQUIRED)

option(BEE2_PROVIDER_ENABLE_INTEROP "Register bee2evp engine interoperability tests" OFF)
if(BEE2_PROVIDER_ENABLE_INTEROP)
    find_package(Python3 COMPONENTS Interpreter REQUIRED)
endif()

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
# Test CLI encryption, decryption and exact STB PBES2 parameters.
add_executable(bee2_bign_cli_profile bign_cli_profile.c)
target_include_directories(bee2_bign_cli_profile PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(bee2_bign_cli_profile PRIVATE OpenSSL::Crypto)

foreach(bits 256 384 512)
    math(EXPR scalar_bytes "${bits} / 8")
    add_test(NAME bee2_bign_cli_pbes2_${bits}
        COMMAND ${CMAKE_COMMAND}
            "-DOPENSSL_EXECUTABLE=${BEE2_OPENSSL_EXECUTABLE}"
            "-DPROVIDER_PATH=$<TARGET_FILE_DIR:bee2_provider>"
            "-DPROFILE_CHECKER=$<TARGET_FILE:bee2_bign_cli_profile>"
            "-DWORK_DIRECTORY=${CMAKE_CURRENT_BINARY_DIR}/bign_cli_${bits}"
            "-DALGORITHM=bign-${bits}"
            "-DSCALAR_LENGTH=${scalar_bytes}"
            "-DOPENSSL_VERSION=${OPENSSL_VERSION}"
            -P ${CMAKE_CURRENT_SOURCE_DIR}/bign_cli_pbes2.cmake)
    set_tests_properties(bee2_bign_cli_pbes2_${bits}
        PROPERTIES LABELS "bign;codec;cli;stb;pbkdf2")
endforeach()

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

add_test(NAME bee2_bign_options
    COMMAND ${CMAKE_COMMAND}
        "-DOPENSSL_EXECUTABLE=${BEE2_OPENSSL_EXECUTABLE}"
        "-DPROVIDER_PATH=$<TARGET_FILE_DIR:bee2_provider>"
        "-DWORK_DIRECTORY=${CMAKE_CURRENT_BINARY_DIR}/bign-options"
        "-DCASE=options"
        -P "${CMAKE_SOURCE_DIR}/tests/bign_cli_contract.cmake")
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

add_executable(bee2_bign_asn1_negative bign_asn1_negative.c)
target_link_libraries(bee2_bign_asn1_negative PRIVATE OpenSSL::Crypto)
add_test(NAME bee2_bign_asn1_negative
    COMMAND bee2_bign_asn1_negative $<TARGET_FILE_DIR:bee2_provider>)
set_tests_properties(bee2_bign_asn1_negative PROPERTIES LABELS "regression;bign;asn1;native")

add_test(NAME bee2_bign_codec_roundtrip
    COMMAND ${CMAKE_COMMAND}
        "-DOPENSSL_EXECUTABLE=${BEE2_OPENSSL_EXECUTABLE}"
        "-DPROVIDER_PATH=$<TARGET_FILE_DIR:bee2_provider>"
        "-DWORK_DIRECTORY=${CMAKE_CURRENT_BINARY_DIR}/bign-codec-roundtrip"
        "-DCASE=roundtrip"
        -P "${CMAKE_SOURCE_DIR}/tests/bign_cli_contract.cmake")
set_tests_properties(bee2_bign_codec_roundtrip PROPERTIES LABELS "regression;bign;codec")

add_executable(bee2_bign_der_framing
    bign_der_framing.c
    ${CMAKE_SOURCE_DIR}/src/bign_asn1.c
    ${CMAKE_SOURCE_DIR}/src/bign_common.c
    ${CMAKE_SOURCE_DIR}/src/provider_util.c)
target_include_directories(bee2_bign_der_framing PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_include_directories(bee2_bign_der_framing SYSTEM PRIVATE ${CMAKE_SOURCE_DIR}/bee2/include)
target_link_libraries(bee2_bign_der_framing PRIVATE bee2_static OpenSSL::Crypto)
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
target_include_directories(bee2_bash_prgae_streaming SYSTEM PRIVATE ${CMAKE_SOURCE_DIR}/bee2/include)
target_link_libraries(bee2_bash_prgae_streaming PRIVATE bee2_static OpenSSL::Crypto)
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
    set(BEE2_INTEROP_LEGACY_TOOL "$ENV{BEE2EVP_LEGACY_TOOL}" CACHE FILEPATH
        "OpenSSL 1.1.1 helper for legacy engine AEAD and KWP")
    if(NOT EXISTS "${BEE2_INTEROP_LEGACY_TOOL}")
        message(FATAL_ERROR "BEE2_INTEROP_LEGACY_TOOL is required when enabling interop")
    endif()
    add_executable(bee2_interop_cipher_tool interop_cipher_tool.c)
    target_link_libraries(bee2_interop_cipher_tool PRIVATE OpenSSL::Crypto)
    # Each algorithm is an independent CTest. One long matrix used to
    # approach the per-test timeout even though individual cases passed.
    foreach(alg IN ITEMS
            belt-dwp128 belt-dwp192 belt-dwp256
            belt-che128 belt-che192 belt-che256
            belt-kwp128 belt-kwp192 belt-kwp256
            bash-prg-ae2561)
        string(REPLACE "-" "_" alg_id "${alg}")
        set(test_name "bee2_interop_${alg_id}")
        add_test(NAME ${test_name}
            COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_SOURCE_DIR}/tests/openssl_bee2evp_aead_interop.py
                --provider-tool $<TARGET_FILE:bee2_interop_cipher_tool>
                --engine-tool "${BEE2_INTEROP_LEGACY_TOOL}"
                --provider-path $<TARGET_FILE_DIR:bee2_provider>
                --algorithm "${alg}")
        set_tests_properties(${test_name}
            PROPERTIES LABELS "interop;bee2evp;cipher")
    endforeach()
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
    foreach(name IN ITEMS belt-mac128 belt-mac192 belt-mac256 belt-hmac)
        set(digest "-")
        if(name STREQUAL "belt-hmac")
            set(digest "belt-hash")
        endif()
        set(key_len 32)
        if(name STREQUAL "belt-mac128")
            set(key_len 16)
        elseif(name STREQUAL "belt-mac192")
            set(key_len 24)
        endif()
        set(spec "mac|${interop_prefix}|${name}|${name}|257|${key_len}|0|${digest}|-")
        set(test_name "bee2_interop_matrix_${name}")
        string(REPLACE "-" "_" test_name "${test_name}")
        add_test(NAME ${test_name}
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/openssl_bee2evp_matrix.py "${spec}")
        set_tests_properties(${test_name} PROPERTIES LABELS "interop;bee2evp;matrix")
    endforeach()
endif()

# BIGN PKCS#8/SPKI cryptographic key serialization in PEM and DER.
add_executable(bee2_bign_stb_pbes2_contract
    bign_stb_pbes2_contract.c
    ${CMAKE_SOURCE_DIR}/src/bign_asn1.c
    ${CMAKE_SOURCE_DIR}/src/bign_common.c
    ${CMAKE_SOURCE_DIR}/src/provider_util.c)
target_include_directories(bee2_bign_stb_pbes2_contract PRIVATE
    ${CMAKE_SOURCE_DIR}/src)
target_include_directories(bee2_bign_stb_pbes2_contract SYSTEM PRIVATE
    ${CMAKE_SOURCE_DIR}/bee2/include)
target_link_libraries(bee2_bign_stb_pbes2_contract PRIVATE
    bee2_static OpenSSL::Crypto)
add_test(NAME bee2_bign_stb_pbes2_contract
    COMMAND bee2_bign_stb_pbes2_contract $<TARGET_FILE_DIR:bee2_provider>)
set_tests_properties(bee2_bign_stb_pbes2_contract
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

# Provider state transitions that are reachable through public OpenSSL APIs.
foreach(test IN ITEMS brng_split_contract bign_private_selection
                      hmac_params_contract aead_phase_contract)
    add_executable(bee2_${test} ${test}.c)
    target_link_libraries(bee2_${test} PRIVATE OpenSSL::Crypto)
    add_test(NAME bee2_${test}
        COMMAND bee2_${test} $<TARGET_FILE_DIR:bee2_provider>)
endforeach()
set_tests_properties(bee2_brng_split_contract PROPERTIES
    LABELS "regression;rand;brng;native")
set_tests_properties(bee2_bign_private_selection PROPERTIES
    LABELS "regression;bign;keymgmt;native")
set_tests_properties(bee2_hmac_params_contract PROPERTIES
    LABELS "regression;mac;params;native")
set_tests_properties(bee2_aead_phase_contract PROPERTIES
    LABELS "regression;aead;evp;native")

# BIGN signing and verification with a digest properties-only update.
add_executable(bee2_bign_signature_properties bign_signature_properties.c)
target_link_libraries(bee2_bign_signature_properties PRIVATE OpenSSL::Crypto)
add_test(NAME bee2_bign_signature_properties
    COMMAND bee2_bign_signature_properties $<TARGET_FILE_DIR:bee2_provider>)
set_tests_properties(bee2_bign_signature_properties PROPERTIES
    LABELS "bign;signature;regression;native")

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

# Exercise independent EVP contexts from multiple threads using a shared
# OpenSSL library context, including context cloning and BIGN signatures.
if(UNIX)
    find_package(Threads REQUIRED)
    add_executable(bee2_provider_concurrent provider_concurrent.c)
    target_link_libraries(bee2_provider_concurrent PRIVATE
        OpenSSL::Crypto Threads::Threads)
    add_test(NAME bee2_provider_concurrent
        COMMAND bee2_provider_concurrent $<TARGET_FILE_DIR:bee2_provider>)
    set_tests_properties(bee2_provider_concurrent PROPERTIES
        LABELS "stress;concurrency;native;evp;bign")
endif()

# The ASN.1 implementation is intentionally linked into two unit tests.
# Instrument those copies as well so their exercised production paths
# are not omitted from the source coverage accounting.
if(BEE2_PROVIDER_ENABLE_COVERAGE)
    foreach(target IN ITEMS bee2_bign_der_framing bee2_bign_stb_pbes2_contract)
        target_compile_options(${target} PRIVATE --coverage -fprofile-update=atomic -O0 -g)
        target_link_options(${target} PRIVATE --coverage)
    endforeach()
endif()

# Direct provider cipher dispatch: one-shot callbacks and duplicated
# initialized contexts must agree with normal EVP streaming for every cipher.
add_executable(bee2_provider_cipher_dispatch provider_cipher_dispatch.c)
target_link_libraries(bee2_provider_cipher_dispatch PRIVATE OpenSSL::Crypto)
add_test(NAME bee2_provider_cipher_dispatch
    COMMAND bee2_provider_cipher_dispatch $<TARGET_FILE_DIR:bee2_provider>)
set_tests_properties(bee2_provider_cipher_dispatch PROPERTIES
    LABELS "crypto;evp;dispatch;context;native")

# The public decoder object-reference transfer path must preserve the full
# provider-native BIGN key and reject malformed references.
add_executable(bee2_bign_decoder_export bign_decoder_export.c)
target_link_libraries(bee2_bign_decoder_export PRIVATE OpenSSL::Crypto)
add_test(NAME bee2_bign_decoder_export
    COMMAND bee2_bign_decoder_export $<TARGET_FILE_DIR:bee2_provider>)
set_tests_properties(bee2_bign_decoder_export PROPERTIES
    LABELS "bign;codec;native;dispatch;negative")
# Internal secret-buffer replacement: aliasing, explicit clearing, empty keys.
add_executable(bee2_provider_util_contract
    provider_util_contract.c ${CMAKE_SOURCE_DIR}/src/provider_util.c)
target_include_directories(bee2_provider_util_contract PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(bee2_provider_util_contract PRIVATE OpenSSL::Crypto)
if(BEE2_PROVIDER_ENABLE_COVERAGE)
    target_compile_options(bee2_provider_util_contract PRIVATE
        --coverage -fprofile-update=atomic -O0 -g)
    target_link_options(bee2_provider_util_contract PRIVATE --coverage)
endif()
add_test(NAME bee2_provider_util_contract COMMAND bee2_provider_util_contract)
set_tests_properties(bee2_provider_util_contract PROPERTIES
    LABELS "regression;provider;native")

# Public EVP validation of provider-controlled OSSL_PARAM types, sizes
# and context reset behavior across all supported BELT key sizes.
add_executable(bee2_provider_params_validation provider_params_validation.c)
target_link_libraries(bee2_provider_params_validation PRIVATE OpenSSL::Crypto)
add_test(NAME bee2_provider_params_validation
    COMMAND bee2_provider_params_validation $<TARGET_FILE_DIR:bee2_provider>)
set_tests_properties(bee2_provider_params_validation PROPERTIES
    LABELS "regression;params;mac;cipher;kdf;native")

# Check implicit BIGN digest selection separately from explicit digest KATs.
add_executable(bee2_bign_default_digest bign_default_digest.c)
target_link_libraries(bee2_bign_default_digest PRIVATE OpenSSL::Crypto)
add_test(NAME bee2_bign_default_digest
    COMMAND bee2_bign_default_digest $<TARGET_FILE_DIR:bee2_provider>)
set_tests_properties(bee2_bign_default_digest PROPERTIES
    LABELS "regression;bign;signature;native")
# Exercise EVP BIGN signature parameter failures without modifying the key.
add_executable(bee2_bign_signature_edge_contract bign_signature_edge_contract.c)
target_link_libraries(bee2_bign_signature_edge_contract PRIVATE OpenSSL::Crypto)
add_test(NAME bee2_bign_signature_edge_contract
    COMMAND bee2_bign_signature_edge_contract $<TARGET_FILE_DIR:bee2_provider>)
set_tests_properties(bee2_bign_signature_edge_contract PROPERTIES
    LABELS "regression;bign;signature;params;native")

# Confirm implicit BRNG IVs match explicitly provided zero/empty IVs.
add_executable(bee2_brng_default_iv_contract brng_default_iv_contract.c)
target_link_libraries(bee2_brng_default_iv_contract PRIVATE OpenSSL::Crypto)
add_test(NAME bee2_brng_default_iv_contract
    COMMAND bee2_brng_default_iv_contract $<TARGET_FILE_DIR:bee2_provider>)
set_tests_properties(bee2_brng_default_iv_contract PROPERTIES
    LABELS "regression;brng;rand;params;native")
# The PEM reader handles CRLF and records lacking a final line ending.
add_executable(bee2_bign_pem_framing_contract bign_pem_framing_contract.c)
target_link_libraries(bee2_bign_pem_framing_contract PRIVATE OpenSSL::Crypto)
add_test(NAME bee2_bign_pem_framing_contract
    COMMAND bee2_bign_pem_framing_contract $<TARGET_FILE_DIR:bee2_provider>)
set_tests_properties(bee2_bign_pem_framing_contract PROPERTIES
    LABELS "regression;bign;codec;negative;native")

# A successful BIGN SPKI decode must not leave speculative ASN.1 errors.
add_executable(bee2_bign_decoder_error_queue bign_decoder_error_queue.c)
target_link_libraries(bee2_bign_decoder_error_queue PRIVATE OpenSSL::Crypto)
add_test(NAME bee2_bign_decoder_error_queue
    COMMAND bee2_bign_decoder_error_queue $<TARGET_FILE_DIR:bee2_provider>)
set_tests_properties(bee2_bign_decoder_error_queue PROPERTIES
    LABELS "regression;bign;codec;native")
