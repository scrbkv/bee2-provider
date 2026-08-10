cmake_minimum_required(VERSION 3.20)
project(bee2_provider VERSION 0.1.0 LANGUAGES C)

include(GNUInstallDirs)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Find OpenSSL 3.x (required for provider API)
find_package(OpenSSL 3.0 REQUIRED)

# Build the upstream Bee2 backend supplied as a Git submodule.
if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/bee2/CMakeLists.txt")
    message(FATAL_ERROR
        "Bee2 submodule is missing. Run: git submodule update --init --recursive")
endif()

set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build shared Bee2 library" FORCE)
set(BUILD_CMD OFF CACHE BOOL "Build bee2cmd" FORCE)
set(BUILD_TESTS OFF CACHE BOOL "Build Bee2 tests" FORCE)
set(BUILD_DOC OFF CACHE BOOL "Build Bee2 documentation" FORCE)
set(INSTALL_HEADERS OFF CACHE BOOL "Install Bee2 headers" FORCE)
set(BUILD_PIC ON CACHE BOOL "Build position-independent Bee2" FORCE)
add_subdirectory(bee2 EXCLUDE_FROM_ALL)

# ---- Platform compatibility ----------------------------------------
# Provide symbols missing from the target toolchain (e.g. explicit_bzero
# on Windows/MinGW). We build them as a separate OBJECT library and
# attach them to the provider module.
if(WIN32)
    add_library(bee2_compat OBJECT src/compat.c)
endif()

# ---- OpenSSL provider shared module --------------------------------
add_library(bee2_provider MODULE
    src/provider.c
    src/provider_util.c
    src/belt_cipher.c
    src/belt_digest.c
    src/belt_mac.c
    src/belt_pbkdf.c
    src/hmac_mac.c
    src/bash_digest.c
    src/belt_aead.c
    src/belt_kwp.c
    src/belt_sde.c
    src/bash_prgae.c
    src/brng_rand.c
    src/bign_common.c
    src/bign_keymgmt.c
    src/bign_keyexchange.c
    src/bign_signature.c
    src/bign_keytransport.c
    src/bign_keycodec.c
)

target_include_directories(bee2_provider PRIVATE
    src
    ${OPENSSL_INCLUDE_DIR}
)
target_include_directories(bee2_provider SYSTEM PRIVATE bee2/include)

target_compile_definitions(bee2_provider PRIVATE
    BEE2_PROVIDER_VERSION="${PROJECT_VERSION}"
)

target_link_libraries(bee2_provider PRIVATE
    bee2_static
    $<$<BOOL:${WIN32}>:bee2_compat>
    # OpenSSL providers are loaded by libcrypto at runtime.
    # On Linux the OSSL_PARAM_* symbols resolve via the already-loaded
    # libcrypto; on Windows a DLL requires explicit linkage.
    OpenSSL::Crypto
)

# Do not re-export implementation symbols from the statically linked Bee2
# archive (including Bee2's own prngSTB* API).  The provider module exposes
# only its entry point and symbols compiled as part of the provider itself.
if(UNIX AND NOT APPLE)
    target_link_options(bee2_provider PRIVATE "-Wl,--exclude-libs,ALL")
endif()

# No "lib" prefix on any platform; keeps the filename predictable.
set_target_properties(bee2_provider PROPERTIES
    PREFIX ""
    C_STANDARD 11
    C_STANDARD_REQUIRED YES
    C_EXTENSIONS NO
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
)

# ---- Tests ----------------------------------------------------------

option(BEE2_PROVIDER_BUILD_TESTS "Build the provider test suite" OFF)

if(BEE2_PROVIDER_BUILD_TESTS)
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/CMakeLists.txt")
        message(FATAL_ERROR
            "The test suite is available only in the complete GitLab repository")
    endif()
    enable_testing()
    add_subdirectory(tests)
endif()

# ---- Install -------------------------------------------------------

set(BEE2_PROVIDER_INSTALL_DIR "${CMAKE_INSTALL_LIBDIR}/ossl-modules"
    CACHE STRING "Installation directory for the OpenSSL provider module")

install(TARGETS bee2_provider
    LIBRARY DESTINATION "${BEE2_PROVIDER_INSTALL_DIR}" COMPONENT Runtime
    RUNTIME DESTINATION "${BEE2_PROVIDER_INSTALL_DIR}" COMPONENT Runtime
)

install(FILES LICENSE README.md CHANGELOG.md SECURITY.md THIRD_PARTY_NOTICES.md
    DESTINATION "${CMAKE_INSTALL_DOCDIR}"
    COMPONENT Runtime
)

install(FILES bee2/LICENSE.txt
    DESTINATION "${CMAKE_INSTALL_DOCDIR}"
    RENAME LICENSE.bee2.txt
    COMPONENT Runtime
)

set(CPACK_PACKAGE_NAME "bee2-provider")
set(CPACK_PACKAGE_VENDOR "Bee2 provider contributors")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_CHECKSUM SHA256)
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_GENERATOR TGZ)
set(CPACK_ARCHIVE_COMPONENT_INSTALL ON)
set(CPACK_COMPONENTS_ALL Runtime)
include(CPack)
