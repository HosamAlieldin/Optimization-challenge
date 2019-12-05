/*
 *
 * Chinese Academy of Sciences
 * State Key Laboratory of Information Security
 * Institute of Information Engineering
 *
 * Copyright (C) 2016 Chinese Academy of Sciences
 *
 * LuoPeng, luopeng@iie.ac.cn
 * Updated in Oct 2016
 * Updated in Jan 2017, update muliple function on GF(2^8).
 *
 */
#include <stdint.h>


#include "aes_schedule.h"
#include "aes_encrypt.h"
/*
 * round constants
 */
static uint8_t RC[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

void aes_key_schedule_128( register uint8_t *roundkeys)
{

    register uint8_t temp[4];
    register uint8_t *last4bytes; // point to the last 4 bytes of one round
    register uint8_t *lastround;
    register uint8_t i;

    /*
	for (i = 0; i < 16; ++i) {
        *roundkeys++ = key[i];
    }
	*/
	*roundkeys++ = key[0];
	*roundkeys++ = key[1];
	*roundkeys++ = key[2];
	*roundkeys++ = key[3];
	*roundkeys++ = key[4];
	*roundkeys++ = key[5];
	*roundkeys++ = key[6];
	*roundkeys++ = key[7];
	*roundkeys++ = key[8];
	*roundkeys++ = key[9];
	*roundkeys++ = key[10];
	*roundkeys++ = key[11];
	*roundkeys++ = key[12];
	*roundkeys++ = key[13];
	*roundkeys++ = key[14];
	*roundkeys++ = key[15];

    last4bytes = roundkeys-4;
    
	for (i = AES_ROUNDS ; i != 0; --i) {
        // k0-k3 for next round
        temp[3] = SBOX[*last4bytes++];
        temp[0] = SBOX[*last4bytes++];
        temp[1] = SBOX[*last4bytes++];
        temp[2] = SBOX[*last4bytes++];
        temp[0] ^= RC[i];
        lastround = roundkeys-16;
        *roundkeys++ = temp[0] ^ *lastround++;
        *roundkeys++ = temp[1] ^ *lastround++;
        *roundkeys++ = temp[2] ^ *lastround++;
        *roundkeys++ = temp[3] ^ *lastround++;
        // k4-k7 for next round        
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        // k8-k11 for next round
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        // k12-k15 for next round
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
    }
}
