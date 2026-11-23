# BIGN command-line integration without a Python dependency.
foreach(required OPENSSL_EXECUTABLE PROVIDER_PATH WORK_DIRECTORY CASE)
    if(NOT DEFINED ${required})
        message(FATAL_ERROR "Missing ${required}")
    endif()
endforeach()
file(MAKE_DIRECTORY "${WORK_DIRECTORY}")

if(WIN32)
    set(null_conf "NUL")
else()
    set(null_conf "/dev/null")
endif()
set(prov -provider-path "${PROVIDER_PATH}" -provider default
    -provider bee2_provider)

function(openssl_ok)
    execute_process(
        COMMAND "${CMAKE_COMMAND}" -E env "OPENSSL_CONF=${null_conf}"
            "${OPENSSL_EXECUTABLE}" ${ARGN}
        RESULT_VARIABLE result OUTPUT_VARIABLE out ERROR_VARIABLE err)
    if(NOT "${result}" STREQUAL "0")
        message(FATAL_ERROR "openssl ${ARGN}: ${err}")
    endif()
    set(OPENSSL_STDOUT "${out}" PARENT_SCOPE)
endfunction()

function(openssl_fail)
    execute_process(
        COMMAND "${CMAKE_COMMAND}" -E env "OPENSSL_CONF=${null_conf}"
            "${OPENSSL_EXECUTABLE}" ${ARGN}
        RESULT_VARIABLE result OUTPUT_QUIET ERROR_QUIET)
    if("${result}" STREQUAL "0")
        message(FATAL_ERROR "Unexpected successful openssl ${ARGN}")
    endif()
endfunction()

function(identical a b)
    file(SHA256 "${a}" sha_a)
    file(SHA256 "${b}" sha_b)
    if(NOT sha_a STREQUAL sha_b)
        message(FATAL_ERROR "BIGN encoding changed between ${a} and ${b}")
    endif()
endfunction()

if(CASE STREQUAL "options")
    foreach(bits 256 384 512)
        openssl_ok(genpkey ${prov} -algorithm "bign-${bits}"
            -out "${WORK_DIRECTORY}/bign-${bits}.pem")
    endforeach()
    set(named "${WORK_DIRECTORY}/bign-256.pem")
    set(explicit "${WORK_DIRECTORY}/bign-256-explicit.pem")
    openssl_ok(genpkey ${prov} -algorithm bign-256
        -pkeyopt encoding:explicit -pkeyopt enc_params:cofactor
        -out "${explicit}")
    openssl_ok(asn1parse -in "${explicit}" -inform PEM -i)
    string(FIND "${OPENSSL_STDOUT}" "1.2.112.0.2.0.34.101.45.4.1" field_oid)
    string(FIND "${OPENSSL_STDOUT}" "INTEGER           :01" cofactor)
    if(field_oid EQUAL -1 OR cofactor EQUAL -1)
        message(FATAL_ERROR "Explicit BIGN field OID or cofactor missing")
    endif()
    file(SIZE "${explicit}" explicit_size)
    file(SIZE "${named}" named_size)
    if(NOT explicit_size GREATER named_size)
        message(FATAL_ERROR "Explicit curve parameters are not larger")
    endif()
    openssl_fail(genpkey ${prov} -algorithm bign)
    openssl_fail(genpkey ${prov} -algorithm bign-256
        -pkeyopt group:bign-384 -out "${WORK_DIRECTORY}/invalid.pem")
elseif(CASE STREQUAL "roundtrip")
    foreach(bits 256 384 512)
        set(prefix "${WORK_DIRECTORY}/bign-${bits}")
        set(key_pem "${prefix}.key.pem")
        set(key_der "${prefix}.key.der")
        set(key_reencoded "${prefix}.reencoded.pem")
        set(key_roundtrip "${prefix}.roundtrip.der")
        set(pub_der "${prefix}.pub.der")
        set(pub_pem "${prefix}.pub.pem")
        set(pub_roundtrip "${prefix}.pub.roundtrip.der")
        set(pub_again "${prefix}.pub.again.der")

        openssl_ok(genpkey ${prov} -algorithm "bign-${bits}" -out "${key_pem}")
        openssl_ok(pkey ${prov} -in "${key_pem}" -outform DER -out "${key_der}")
        openssl_ok(pkey ${prov} -inform DER -in "${key_der}"
            -outform PEM -out "${key_reencoded}")
        openssl_ok(pkey ${prov} -in "${key_reencoded}"
            -outform DER -out "${key_roundtrip}")
        identical("${key_der}" "${key_roundtrip}")

        openssl_ok(pkey ${prov} -in "${key_pem}" -pubout
            -outform DER -out "${pub_der}")
        openssl_ok(pkey ${prov} -pubin -inform DER -in "${pub_der}"
            -pubout -outform PEM -out "${pub_pem}")
        openssl_ok(pkey ${prov} -pubin -in "${pub_pem}"
            -pubout -outform DER -out "${pub_roundtrip}")
        openssl_ok(pkey ${prov} -in "${key_reencoded}" -pubout
            -outform DER -out "${pub_again}")
        identical("${pub_der}" "${pub_roundtrip}")
        identical("${pub_der}" "${pub_again}")

        set(explicit_pem "${prefix}.explicit.pem")
        set(explicit_der "${prefix}.explicit.der")
        set(explicit_roundtrip "${prefix}.explicit.roundtrip.pem")
        set(explicit_reencoded_der "${prefix}.explicit.reencoded.der")
        openssl_ok(genpkey ${prov} -algorithm "bign-${bits}"
            -pkeyopt encoding:explicit -pkeyopt enc_params:cofactor
            -out "${explicit_pem}")
        openssl_ok(pkey ${prov} -in "${explicit_pem}"
            -outform DER -out "${explicit_der}")
        openssl_ok(pkey ${prov} -inform DER -in "${explicit_der}"
            -out "${explicit_roundtrip}")
        openssl_ok(pkey ${prov} -in "${explicit_roundtrip}"
            -outform DER -out "${explicit_reencoded_der}")
        identical("${explicit_der}" "${explicit_reencoded_der}")

        foreach(key_path IN ITEMS "${key_pem}" "${key_der}" "${explicit_pem}"
                "${explicit_der}" "${pub_pem}" "${pub_der}")
            if(key_path STREQUAL pub_pem OR key_path STREQUAL pub_der)
                set(expected "-----BEGIN PUBLIC KEY-----")
            else()
                set(expected "-----BEGIN PRIVATE KEY-----")
            endif()
            foreach(uri IN ITEMS "file:${key_path}" "${key_path}")
                openssl_ok(storeutl ${prov} "${uri}")
                string(FIND "${OPENSSL_STDOUT}" "${expected}" marker)
                string(FIND "${OPENSSL_STDOUT}" "Total found: 1" count)
                if(marker EQUAL -1 OR count EQUAL -1)
                    message(FATAL_ERROR "OpenSSL STORE could not load ${uri}")
                endif()
            endforeach()
        endforeach()
    endforeach()
else()
    message(FATAL_ERROR "Unsupported BIGN test case: ${CASE}")
endif()
