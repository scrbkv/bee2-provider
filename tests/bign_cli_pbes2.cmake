# Run CLI commands and verify that their output is STB Annex E PBES2.
foreach(required OPENSSL_EXECUTABLE PROVIDER_PATH PROFILE_CHECKER WORK_DIRECTORY ALGORITHM SCALAR_LENGTH OPENSSL_VERSION)
    if(NOT DEFINED ${required})
        message(FATAL_ERROR "Missing ${required}")
    endif()
endforeach()
file(MAKE_DIRECTORY "${WORK_DIRECTORY}")
set(prov -provider-path "${PROVIDER_PATH}" -provider default -provider bee2_provider)
set(pass pass:bee2-test-password)
function(openssl_ok)
    execute_process(COMMAND "${OPENSSL_EXECUTABLE}" ${ARGN}
        RESULT_VARIABLE result ERROR_VARIABLE err OUTPUT_QUIET)
    if(NOT "${result}" STREQUAL "0")
        message(FATAL_ERROR "openssl ${ARGN}: ${err}")
    endif()
endfunction()
function(check_stb file count salt)
    file(READ "${file}" header LIMIT 80)
    if(NOT header MATCHES "-----BEGIN ENCRYPTED PRIVATE KEY-----")
        message(FATAL_ERROR "Not encrypted: ${file}")
    endif()
    execute_process(COMMAND "${PROFILE_CHECKER}" "${file}" "${count}"
        "${salt}" "${SCALAR_LENGTH}" RESULT_VARIABLE result ERROR_VARIABLE err)
    if(NOT "${result}" STREQUAL "0")
        message(FATAL_ERROR "STB PBES2 mismatch: ${err}")
    endif()
endfunction()
function(compare_pub a b)
    file(SHA256 "${a}" hash_a)
    file(SHA256 "${b}" hash_b)
    if(NOT hash_a STREQUAL hash_b)
        message(FATAL_ERROR "Different BIGN public keys: ${a} ${b}")
    endif()
endfunction()
set(plain "${WORK_DIRECTORY}/plain.pem")
set(original_pub "${WORK_DIRECTORY}/original.pub.pem")
set(gen "${WORK_DIRECTORY}/generated.enc.pem")
set(gen_clear "${WORK_DIRECTORY}/generated.clear.pem")
set(gen_pub "${WORK_DIRECTORY}/generated.pub.pem")
set(gen_clear_pub "${WORK_DIRECTORY}/generated.clear.pub.pem")
set(pkey_enc "${WORK_DIRECTORY}/pkey.enc.pem")
set(pkey_pub "${WORK_DIRECTORY}/pkey.pub.pem")

# A passphrase alone must not encrypt (OpenSSL's common contract).
openssl_ok(genpkey ${prov} -algorithm "${ALGORITHM}" -pass "${pass}" -out "${plain}")
file(READ "${plain}" header LIMIT 80)
if(NOT header MATCHES "-----BEGIN PRIVATE KEY-----")
    message(FATAL_ERROR "Password alone unexpectedly encrypted BIGN")
endif()
openssl_ok(pkey ${prov} -in "${plain}" -pubout -out "${original_pub}")

# genpkey and pkey must both use Annex E when belt-kwp256 is selected.
openssl_ok(genpkey ${prov} -algorithm "${ALGORITHM}" -belt-kwp256
    -pass "${pass}" -out "${gen}")
check_stb("${gen}" 10000 16)
openssl_ok(pkey ${prov} -in "${gen}" -passin "${pass}" -out "${gen_clear}")
openssl_ok(pkey ${prov} -in "${gen}" -passin "${pass}" -pubout -out "${gen_pub}")
openssl_ok(pkey ${prov} -in "${gen_clear}" -pubout -out "${gen_clear_pub}")
compare_pub("${gen_pub}" "${gen_clear_pub}")

execute_process(COMMAND "${OPENSSL_EXECUTABLE}" pkey ${prov}
    -in "${gen}" -passin pass:wrong-password -pubout
    RESULT_VARIABLE wrong_result OUTPUT_QUIET ERROR_QUIET)
if("${wrong_result}" STREQUAL "0")
    message(FATAL_ERROR "Wrong password was accepted")
endif()

openssl_ok(pkey ${prov} -in "${plain}" -belt-kwp256 -passout "${pass}"
    -out "${pkey_enc}")
check_stb("${pkey_enc}" 10000 16)
openssl_ok(pkey ${prov} -in "${pkey_enc}" -passin "${pass}"
    -pubout -out "${pkey_pub}")
compare_pub("${original_pub}" "${pkey_pub}")

# -encopt is only available in OpenSSL >= 4.0.
if(OPENSSL_VERSION VERSION_GREATER_EQUAL "4.0")
    set(opts -encopt stb-pbkdf2-iterations:12000 -encopt stb-pbkdf2-saltlen:24)
    set(custom_gen "${WORK_DIRECTORY}/custom.gen.pem")
    set(custom_pkey "${WORK_DIRECTORY}/custom.pkey.pem")
    set(custom_pub "${WORK_DIRECTORY}/custom.pub.pem")
    openssl_ok(genpkey ${prov} -algorithm "${ALGORITHM}" -belt-kwp256
        -pass "${pass}" ${opts} -out "${custom_gen}")
    check_stb("${custom_gen}" 12000 24)
    openssl_ok(pkey ${prov} -in "${custom_gen}" -passin "${pass}"
        -pubout -out "${WORK_DIRECTORY}/custom.gen.pub.pem")
    openssl_ok(pkey ${prov} -in "${plain}" -belt-kwp256 -passout "${pass}"
        ${opts} -out "${custom_pkey}")
    check_stb("${custom_pkey}" 12000 24)
    openssl_ok(pkey ${prov} -in "${custom_pkey}" -passin "${pass}"
        -pubout -out "${custom_pub}")
    compare_pub("${original_pub}" "${custom_pub}")
endif()
