/*
 *
 * Chinese Academy of Sciences
 * State Key Laboratory of Information Security
 * Institute of Information Engineering
 *
 * Copyright (C) 2016 Chinese Academy of Sciences
 *
 * LuoPeng, luopeng@iie.ac.cn
 * Updated in May 2016
 *
 */

/*#include <stdio.h>*/

/*#include <avr/io.h>*/
#include "std_types.h"
#include "aes_decrypt.h"
#include "aes_encrypt.h"
#include "aes_schedule.h"

uint32_t main(uint32_t argc, const uint8_t * const argv[]);
uint32_t main(uint32_t argc, const uint8_t * const argv[]) {

    uint8_t i;
    uint8_t CypherText[AES_BLOCK_SIZE]={0};
    /* 128 bit key */
    const uint8_t key1[] = {
        /*0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59,
		0x0c, 0xb7, 0xad, 0xd6, 0xaf, 0x7f, 0x67, 0x98,*/
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,

    };

    uint8_t plaintext1[] = {
      /*0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,*/
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };


    uint8_t ciphertext1[AES_BLOCK_SIZE]={0};
    const uint8_t const_cipher[AES_BLOCK_SIZE] = {
        /*0xff, 0x0b, 0x84, 0x4a, 0x08, 0x53, 0xbf, 0x7c,
		0x69, 0x34, 0xab, 0x43, 0x64, 0x14, 0x8f, 0xb9,*/
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
        0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
    };

    uint8_t roundkeys1[AES_ROUND_KEY_SIZE]={0};

    /* key schedule*/
    aes_key_schedule_128(key1, roundkeys1);

    /* encryption*/
    aes_encrypt_128(roundkeys1, plaintext1, ciphertext1);

    for (i = 0U; i < AES_BLOCK_SIZE; i++) {
        if ( ciphertext1[i] != const_cipher[i] ) { break; }
    }


    /* decryption*/
    aes_decrypt_128(roundkeys1, ciphertext1, CypherText);
    for (i = 0U; i < AES_BLOCK_SIZE; i++) {
        if ( CypherText[i] != plaintext1[i] ) { break; }
    }

    return 0U;
}


