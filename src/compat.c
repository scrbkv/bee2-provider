/*
 * compat.c — platform compatibility shims
 *
 * Provides functions missing from the target platform's standard library.
 */

#ifdef _WIN32
#include <stddef.h>
#include <windows.h>

/*
 * explicit_bzero — securely zero memory (not available in MinGW/MSVC).
 * Uses SecureZeroMemory which is guaranteed not to be optimised away.
 */
void explicit_bzero(void *s, size_t n) {
    SecureZeroMemory(s, n);
}
#endif /* _WIN32 */
