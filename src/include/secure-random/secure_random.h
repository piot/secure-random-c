/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Peter Bjorklund. All rights reserved.
 *  Licensed under the MIT License. See LICENSE in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
#ifndef SECURE_RANDOM_RANDOM_H
#define SECURE_RANDOM_RANDOM_H

#include <stddef.h>
#include <stdint.h>

uint64_t secureRandomUInt64(void);
int secureRandomOctets(uint8_t *target, size_t octetCount);

#endif
