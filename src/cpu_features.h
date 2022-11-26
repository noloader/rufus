/*
 * Rufus: The Reliable USB Formatting Utility
 * Device detection and enumeration
 * Copyright © 2014-2022 Pete Batard <pete@akeo.ie>
 *                       Jeffrey Walton <noloader@gmail.com>
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

#ifndef RUFUS_CPU_FEATURES_INCLUDED
#define RUFUS_CPU_FEATURES_INCLUDED

#include "rufus.h"

#ifdef _MSC_VER
# define RUFUS_MSC_VERSION (_MSC_VER)
#endif

#if defined(__GNUC__)
# define RUFUS_GCC_VERSION (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
#endif

#ifdef __INTEL_COMPILER
# define RUFUS_INTEL_VERSION (__INTEL_COMPILER)
#endif

#if defined(__clang__) && defined(__apple_build_version__)
# define RUFUS_APPLE_CLANG_VERSION (__clang_major__ * 10000 + __clang_minor__ * 100 + __clang_patchlevel__)
#elif defined(__clang__)
# define RUFUS_LLVM_CLANG_VERSION  (__clang_major__ * 10000 + __clang_minor__ * 100 + __clang_patchlevel__)
#endif

/* Careful. Clang pretends to be other compilers but it can't always compile a program. */
#if defined(__clang__)
# undef RUFUS_MSC_VERSION
# undef RUFUS_GCC_VERSION
# undef RUFUS_INTEL_VERSION
#endif

/* Architecture defines */
#if (defined(__ILP32__) || defined(_ILP32)) && defined(__x86_64__)
# define RUFUS_ARCH_X32 1
#elif (defined(_M_X64) || defined(__x86_64__))
# define RUFUS_ARCH_X64 1
#elif (defined(_M_IX86) || defined(__i386__) || defined(__i386) || defined(_X86_) || defined(__I86__))
# define RUFUS_ARCH_X86 1
#elif defined(__arm64__) || defined(__aarch64__) || defined(_M_ARM64)
# define RUFUS_ARCH_ARM64 1
#elif defined(__arm__) || defined(_M_ARM)
# define RUFUS_ARCH_ARM32 1
#endif

/* Paydirt. These are the defines we ultimately want to see. */
#if defined(RUFUS_ARCH_X86) || defined(RUFUS_ARCH_X32) || defined(RUFUS_ARCH_X64)
# if (RUFUS_MSC_VERSION >= 1900) || (RUFUS_GCC_VERSION >= 40900) || (RUFUS_INTEL_VERSION >= 1600) || (RUFUS_LLVM_CLANG_VERSION >= 30400)
#  define RUFUS_X86_SHA1_AVAILABLE 1
#  define RUFUS_X86_SHA256_AVAILABLE 1
# endif
#endif

/*
 * Returns TRUE if the cpu supports SHA-1 acceleration, FALSE otherwise.
 * Note: this is a runtime check, not a compile time check. If the platform
 * and compiler do not support SHA acceleration, then the function returns
 * FALSE evenif the cpu supports the acceleration.
 */
extern BOOL HasSHA1(void);

/*
 * Returns TRUE if the cpu supports SHA-256 acceleration, FALSE otherwise.
 * Note: this is a runtime check, not a compile time check. If the platform
 * and compiler do not support SHA acceleration, then the function returns
 * FALSE evenif the cpu supports the acceleration.
 */
extern BOOL HasSHA256(void);

/*
 * Returns TRUE if the cpu supports SHA-512 acceleration, FALSE otherwise.
 * Note: this is a runtime check, not a compile time check. If the platform
 * and compiler do not support SHA acceleration, then the function returns
 * FALSE evenif the cpu supports the acceleration.
 */
extern BOOL HasSHA512(void);

#endif  /* RUFUS_CPU_FEATURES_INCLUDED */
