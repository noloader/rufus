/*
 * Rufus: The Reliable USB Formatting Utility
 * Device detection and enumeration
 * Copyright © 2014-2022 Pete Batard <pete@akeo.ie>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Four things must be in place to make a meaningful call to HasSHA1()
 * or HasSHA256(). First, the compiler must support the underlying
 * intrinsics. Second, the platform must provide a cpuid() function.
 * Third, the platform must support a static initializer. And fourth,
 * the cpu must actually support the SHA-1 and SHA-256 instructions.
 *
 * If any of the conditions are not met, then HasSHA1() and HasSHA256()
 * return FALSE. HasSHA512() always returns FALSE at the moment because
 * x86 processors do not currently provide instructions for the
 * algorithm. Other processors do provide SHA512 acceleration, so we
 * stubbed it out.
 *
 * The code does not use extraordinary means to accomplish the four
 * goals. For example, we could write our own cpuid() function and
 * extend support back to early Windows, but we don't. We rely on the
 * platform to provide it to keep things simple. It is easy to go into
 * the weeds with topics like cpu features, static initialization,
 * and emitting byte codes for mnemonics when the compiler does not
 * support an ISA like SHA.
 */

#include "cpu_features.h"

#if defined(RUFUS_MSC_VERSION) && (defined(RUFUS_X86_SHA1_AVAILABLE) || defined(RUFUS_X86_SHA256_AVAILABLE))
# include <intrin.h>
#endif

#if (defined(RUFUS_GCC_VERSION) || defined(RUFUS_LLVM_CLANG_VERSION)) && (defined(RUFUS_X86_SHA1_AVAILABLE) || defined(RUFUS_X86_SHA256_AVAILABLE))
# include <x86Intrin.h>
#endif

#if defined(RUFUS_INTEL_VERSION) && (defined(RUFUS_X86_SHA1_AVAILABLE) || defined(RUFUS_X86_SHA256_AVAILABLE))
# include <immintrin.h>
#endif

#ifdef RUFUS_X86_SHA1_AVAILABLE

#if defined(RUFUS_MSC_COMPILER)
static const BOOL s_sha1 = DetectSHA1();
#elif defined(RUFUS_GCC_COMPILER) || defined(RUFUS_INTEL_VERSION) || defined(RUFUS_LLVM_CLANG_VERSION)
static const BOOL s_sha1 __attribute__ ((init_priority (100))) = DetectSHA1();
#else
/* Catch all. We may say FALSE even if the cpu supports SHA acceleration. */
static const BOOL s_sha1 = FALSE;
#endif

/*
 * Detect if the processor supports SHA-1 acceleration. We only check for the
 * three ISAs we need - SSSE3, SSE4.1 and SHA. We don't check for XSAVE because
 * that's been enabled since Windows 2000. Rufus minimum Windows version is
 * currently Windows 7 (and soon to change), so it's a moot point nowadays.
 */
BOOL DetectSHA1(void)
{
#if defined(RUFUS_MSC_COMPILER)
	unint32_t regs0[4] = {0,0,0,0}, regs1[4] = {0,0,0,0}, regs7[4] = {0,0,0,0};
	const uint32_t SSSE3_BIT = 1u <<  9; /* Function 1, Bit  9 of ECX */
	const uint32_t SSE41_BIT = 1u << 19; /* Function 1, Bit 19 of ECX */
	const uint32_t SHA_BIT   = 1u << 29; /* Function 7, Bit 29 of EBX */

	__cpuid(regs0, 0);
	const uint32_t highest = regs0[0]; /*EAX*/

	if (highest >= 0x01) {
		__cpuidex(regs1, 1, 0);
	}
	if (highest >= 0x07) {
		__cpuidex(regs7, 7, 0);
	}

	return (regs1[2] /*ECX*/ & SSSE3_BIT) && (regs1[2] /*ECX*/ & SSE41_BIT) && (regs7[1] /*EBX*/ & SHA_BIT) ? TRUE : FALSE;
#elif defined(RUFUS_GCC_COMPILER) || defined(RUFUS_LLVM_CLANG_VERSION)
	/* __builtin_cpu_supports available in GCC 4.8.1 and above */
	return __builtin_cpu_supports("ssse3") && __builtin_cpu_supports("sse4.1") && __builtin_cpu_supports("sha") ? TRUE : FALSE;
#elif defined(RUFUS_INTEL_VERSION)
	/* https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html#text=_may_i_use_cpu_feature */
	return _may_i_use_cpu_feature(_FEATURE_SSSE3|_FEATURE_SSE4_1|_FEATURE_SHA) ? TRUE : FALSE;
#else
	return FALSE;
#endif
}
#endif  /* RUFUS_X86_SHA1_AVAILABLE */

#ifdef RUFUS_X86_SHA256_AVAILABLE

#if defined(RUFUS_MSC_COMPILER)
static const BOOL s_sha256 = DetectSHA256();
#elif defined(RUFUS_GCC_COMPILER) || defined(RUFUS_INTEL_VERSION) || defined(RUFUS_LLVM_CLANG_VERSION)
static const BOOL s_sha256 __attribute__ ((init_priority (100))) = DetectSHA256();
#else
/* Catch all. We may say FALSE even if the cpu supports SHA acceleration. */
static const BOOL s_sha256 = FALSE;
#endif

/*
 * Detect if the processor supports SHA-256 acceleration. We only check for the
 * three ISAs we need - SSSE3, SSE4.1 and SHA. We don't check for XSAVE because
 * that's been enabled since Windows 2000. Rufus minimum Windows version is
 * currently Windows 7 (and soon to change), so it's a moot point nowadays.
 */
BOOL DetectSHA256(void)
{
#if defined(RUFUS_MSC_COMPILER)
	unint32_t regs0[4] = {0,0,0,0}, regs1[4] = {0,0,0,0}, regs7[4] = {0,0,0,0};
	const uint32_t SSSE3_BIT = 1u <<  9; /* Function 1, Bit  9 of ECX */
	const uint32_t SSE41_BIT = 1u << 19; /* Function 1, Bit 19 of ECX */
	const uint32_t SHA_BIT   = 1u << 29; /* Function 7, Bit 29 of EBX */

	__cpuid(regs0, 0);
	const uint32_t highest = regs0[0]; /*EAX*/

	if (highest >= 0x01) {
		__cpuidex(regs1, 1, 0);
	}
	if (highest >= 0x07) {
		__cpuidex(regs7, 7, 0);
	}

	return (regs1[2] /*ECX*/ & SSSE3_BIT) && (regs1[2] /*ECX*/ & SSE41_BIT) && (regs7[1] /*EBX*/ & SHA_BIT) ? TRUE : FALSE;
#elif defined(RUFUS_GCC_COMPILER) || defined(RUFUS_LLVM_CLANG_VERSION)
	/* __builtin_cpu_supports available in GCC 4.8.1 and above */
	return __builtin_cpu_supports("ssse3") && __builtin_cpu_supports("sse4.1") && __builtin_cpu_supports("sha") ? TRUE : FALSE;
#elif defined(RUFUS_INTEL_VERSION)
	/* https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html#text=_may_i_use_cpu_feature */
	return _may_i_use_cpu_feature(_FEATURE_SSSE3|_FEATURE_SSE4_1|_FEATURE_SHA) ? TRUE : FALSE;
#else
	return FALSE;
#endif
}
#endif  /* RUFUS_X86_SHA256_AVAILABLE */

/*
 * Returns TRUE if the cpu supports SHA-1 acceleration, FALSE otherwise.
 * Note: this is a runtime check, not a compile time check. If the compiler
 * does not support SHA acceleration, then the function returns FALSE even
 * if the cpu supports the acceleration.
 */
BOOL HasSHA1(void)
{
#ifdef RUFUS_X86_SHA1_AVAILABLE
	return s_sha1;
#else
	return FALSE;
#endif
}

/*
 * Returns TRUE if the cpu supports SHA-256 acceleration, FALSE otherwise.
 * Note: this is a runtime check, not a compile time check. If the compiler
 * does not support SHA acceleration, then the function returns FALSE even
 * if the cpu supports the acceleration.
 */
BOOL HasSHA256(void)
{
#ifdef RUFUS_X86_SHA256_AVAILABLE
	return s_sha256;
#else
	return FALSE;
#endif
}

/*
 * Returns TRUE if the cpu supports SHA-256 acceleration, FALSE otherwise.
 * Note: this is a runtime check, not a compile time check. If the compiler
 * does not support SHA acceleration, then the function returns FALSE even
 * if the cpu supports the acceleration.
 */
BOOL HasSHA512(void)
{
	/* Not available yet on x86 */
	return FALSE;
}
