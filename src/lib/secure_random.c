/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Peter Bjorklund. All rights reserved.
 *  Licensed under the MIT License. See LICENSE in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
#include <secure-random/secure_random.h>

#if __APPLE__
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

#elif __WIN32
#include <bcrypt.h>

int secureRandomOctets(uint8_t* target, size_t octetCount)
{
    NTSTATUS status = BCryptGenRandom(NULL, target, octeCount, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status != STATUS_SUCCESS) {
        CLOG_ERROR("failed secure random")
        return -1;
    }

    return 0;
}

uint64_t secureRandomUInt64(void)
{
    uint64_t target;

    int err = secureRandomOctets(&target, sizeof(uint64_t));
    if (err < 0) {
        CLOG_ERROR("error in random generator")
    }
    return target;
}

#elif __posix
#include <sys/random.h>

int secureRandomOctets(uint8_t* target, size_t octetCount)
{
    ssize_t err = getrandom(target, octeCount, 0);
    if (err != octetCount) {
        CLOG_ERROR("failed secure random")
        return -1;
    }

    return 0;
}

uint64_t secureRandomUInt64(void)
{
    uint64_t target;

    int err = secureRandomOctets(&target, sizeof(uint64_t));
    if (err < 0) {
        CLOG_ERROR("error in random generator")
    }
    return target;
}

GRND_RANDOM

#else
#error "secure random: unknown platform"
#endif
