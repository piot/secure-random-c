/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Peter Bjorklund. All rights reserved.
 *  Licensed under the MIT License. See LICENSE in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
#if defined(_WIN32)
#include <Windows.h>
#endif

#include <secure-random/secure_random.h>

#if defined __APPLE__
#include <stdlib.h>

uint64_t secureRandomUInt64(void)
{
    uint32_t first = arc4random();
    uint32_t second = arc4random();

    return ((uint64_t) first << 32) | second;
}

int secureRandomOctets(uint8_t* target, size_t octetCount)
{
    arc4random_buf(target, octetCount);

    return 0;
}

#elif defined(_WIN32)
#include <bcrypt.h>
#include <ntstatus.h>

int secureRandomOctets(uint8_t* target, size_t octetCount)
{
    NTSTATUS status = BCryptGenRandom(NULL, target, (ULONG) octetCount, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status != STATUS_SUCCESS) {
        // CLOG_ERROR("failed secure random")
        return -1;
    }

    return 0;
}

uint64_t secureRandomUInt64(void)
{
    uint64_t target;

    int err = secureRandomOctets((uint8_t*) &target, sizeof(uint64_t));
    if (err < 0) {
        // CLOG_ERROR("error in random generator")
        return 0;
    }
    return target;
}

#elif defined __EMSCRIPTEN__
#include <stdlib.h>
#include <emscripten/em_math.h>

uint64_t secureRandomUInt64(void)
{
    // TODO: This is not a secure random number
    return (uint64_t) (emscripten_math_random() * (double)UINT64_MAX);
}

#elif defined __posix || defined __linux || defined __unix
#include <sys/random.h>

int secureRandomOctets(uint8_t* target, size_t octetCount)
{
    ssize_t err = getrandom(target, octetCount, 0);
    if (err != (ssize_t) octetCount) {
        // CLOG_ERROR("failed secure random")
        return -1;
    }

    return 0;
}

uint64_t secureRandomUInt64(void)
{
    uint64_t target;

    int err = secureRandomOctets((uint8_t*) &target, sizeof(uint64_t));
    if (err < 0) {
        // CLOG_ERROR("error in random generator")
        return 0;
    }
    return target;
}

#else
#error "secure random: unknown platform"
#endif
