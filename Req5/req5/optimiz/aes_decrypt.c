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

#include "aes_decrypt.h"


static uint8_t INV_SBOX[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

/**
 * https://en.wikipedia.org/wiki/Finite_field_arithmetic
 * Multiply two numbers in the GF(2^8) finite field defined
 * by the polynomial x^8 + x^4 + x^3 + x + 1 = 0
 * We do use mul2(int8_t a) but not mul(uint8_t a, uint8_t b)
 * just in order to get a higher speed.
 */
__attribute__((always_inline)) static inline uint8_t mul2(register uint8_t a)
{
    return (a&0x80) ? ((a<<1)^0x1b) : (a<<1);
}
/**
 * @purpose:    Inverse ShiftRows
 * @description
 *  Row0: s0  s4  s8  s12   >>> 0 byte
 *  Row1: s1  s5  s9  s13   >>> 1 byte
 *  Row2: s2  s6  s10 s14   >>> 2 bytes
 *  Row3: s3  s7  s11 s15   >>> 3 bytes
 */
static void inv_shift_rows(register uint8_t *state)
{
    register uint8_t temp;
    // row1
    temp        = *(state+13);
    *(state+13) = *(state+9);
    *(state+9)  = *(state+5);
    *(state+5)  = *(state+1);
    *(state+1)  = temp;
    // row2
    temp        = *(state+14);
    *(state+14) = *(state+6);
    *(state+6)  = temp;
    temp        = *(state+10);
    *(state+10) = *(state+2);
    *(state+2)  = temp;
    // row3
    temp        = *(state+3);
    *(state+3)  = *(state+7);
    *(state+7)  = *(state+11);
    *(state+11) = *(state+15);
    *(state+15) = temp;
}
void aes_decrypt_128( register uint8_t *roundkeys, register uint8_t *ciphertext, register uint8_t *plaintext)
{

    uint8_t tmp[16];
    register uint8_t t, u, v;
    //register uint8_t i;
	register uint8_t j;

    roundkeys += 160;

    // first round
    /*
	for ( i = (AES_BLOCK_SIZE-1); i != 0; --i ) {
        *(plaintext+i) = *(ciphertext+i) ^ *(roundkeys+i);
    }
	*(plaintext+i) = *(ciphertext+i) ^ *(roundkeys+i);
	*/
	*(plaintext+0) = *(ciphertext+0) ^ *(roundkeys+0);
	*(plaintext+1) = *(ciphertext+1) ^ *(roundkeys+1);
	*(plaintext+2) = *(ciphertext+2) ^ *(roundkeys+2);
	*(plaintext+3) = *(ciphertext+3) ^ *(roundkeys+3);
	*(plaintext+4) = *(ciphertext+4) ^ *(roundkeys+4);
	*(plaintext+5) = *(ciphertext+5) ^ *(roundkeys+5);
	*(plaintext+6) = *(ciphertext+6) ^ *(roundkeys+6);
	*(plaintext+7) = *(ciphertext+7) ^ *(roundkeys+7);
	*(plaintext+8) = *(ciphertext+8) ^ *(roundkeys+8);
	*(plaintext+9) = *(ciphertext+9) ^ *(roundkeys+9);
	*(plaintext+10) = *(ciphertext+10) ^ *(roundkeys+10);
	*(plaintext+11) = *(ciphertext+11) ^ *(roundkeys+11);
	*(plaintext+12) = *(ciphertext+12) ^ *(roundkeys+12);
	*(plaintext+13) = *(ciphertext+13) ^ *(roundkeys+13);
	*(plaintext+14) = *(ciphertext+14) ^ *(roundkeys+14);
	*(plaintext+15) = *(ciphertext+15) ^ *(roundkeys+15);
	
    roundkeys -= 16;
    inv_shift_rows(plaintext);
    /*
	for (i = (AES_BLOCK_SIZE-1); i != 0; --i) {
        *(plaintext+i) = INV_SBOX[*(plaintext+i)];
    }
	*(plaintext+i) = INV_SBOX[*(plaintext+i)];
	*/
	*(plaintext+0) = INV_SBOX[*(plaintext+0)];
	*(plaintext+1) = INV_SBOX[*(plaintext+1)];
	*(plaintext+2) = INV_SBOX[*(plaintext+2)];
	*(plaintext+3) = INV_SBOX[*(plaintext+3)];
	*(plaintext+4) = INV_SBOX[*(plaintext+4)];
	*(plaintext+5) = INV_SBOX[*(plaintext+5)];
	*(plaintext+6) = INV_SBOX[*(plaintext+6)];
	*(plaintext+7) = INV_SBOX[*(plaintext+7)];
	*(plaintext+8) = INV_SBOX[*(plaintext+8)];
	*(plaintext+9) = INV_SBOX[*(plaintext+9)];
	*(plaintext+10) = INV_SBOX[*(plaintext+10)];
	*(plaintext+11) = INV_SBOX[*(plaintext+11)];
	*(plaintext+12) = INV_SBOX[*(plaintext+12)];
	*(plaintext+13) = INV_SBOX[*(plaintext+13)];
	*(plaintext+14) = INV_SBOX[*(plaintext+14)];
	*(plaintext+15) = INV_SBOX[*(plaintext+15)];

    for (j = (AES_ROUNDS-1); j != 0; --j) {
        
        // Inverse AddRoundKey
        /*
		for ( i = AES_BLOCK_SIZE-1 ; i != 0; --i ) {
            *(tmp+i) = *(plaintext+i) ^ *(roundkeys+i);
        }
		*(tmp+i) = *(plaintext+i) ^ *(roundkeys+i);
		*/
		*(tmp+0) = *(plaintext+0) ^ *(roundkeys+0);
		*(tmp+1) = *(plaintext+1) ^ *(roundkeys+1);
		*(tmp+2) = *(plaintext+2) ^ *(roundkeys+2);
		*(tmp+3) = *(plaintext+3) ^ *(roundkeys+3);
		*(tmp+4) = *(plaintext+4) ^ *(roundkeys+4);
		*(tmp+5) = *(plaintext+5) ^ *(roundkeys+5);
		*(tmp+6) = *(plaintext+6) ^ *(roundkeys+6);
		*(tmp+7) = *(plaintext+7) ^ *(roundkeys+7);
		*(tmp+8) = *(plaintext+8) ^ *(roundkeys+8);
		*(tmp+9) = *(plaintext+9) ^ *(roundkeys+9);
		*(tmp+10) = *(plaintext+10) ^ *(roundkeys+10);
		*(tmp+11) = *(plaintext+11) ^ *(roundkeys+11);
		*(tmp+12) = *(plaintext+12) ^ *(roundkeys+12);
		*(tmp+13) = *(plaintext+13) ^ *(roundkeys+13);
		*(tmp+14) = *(plaintext+14) ^ *(roundkeys+14);
		*(tmp+15) = *(plaintext+15) ^ *(roundkeys+15);
        
        /*
         * Inverse MixColumns
         * [0e 0b 0d 09]   [s0  s4  s8  s12]
         * [09 0e 0b 0d] . [s1  s5  s9  s13]
         * [0d 09 0e 0b]   [s2  s6  s10 s14]
         * [0b 0d 09 0e]   [s3  s7  s11 s15]
         */
        /*
		for (i = 0; i < AES_BLOCK_SIZE; i+=4) {
            t = tmp[i] ^ tmp[i+1] ^ tmp[i+2] ^ tmp[i+3];
            plaintext[i]   = t ^ tmp[i]   ^ mul2(tmp[i]   ^ tmp[i+1]);
            plaintext[i+1] = t ^ tmp[i+1] ^ mul2(tmp[i+1] ^ tmp[i+2]);
            plaintext[i+2] = t ^ tmp[i+2] ^ mul2(tmp[i+2] ^ tmp[i+3]);
            plaintext[i+3] = t ^ tmp[i+3] ^ mul2(tmp[i+3] ^ tmp[i]);
            u = mul2(mul2(tmp[i]   ^ tmp[i+2]));
            v = mul2(mul2(tmp[i+1] ^ tmp[i+3]));
            t = mul2(u ^ v);
            plaintext[i]   ^= t ^ u;
            plaintext[i+1] ^= t ^ v;
            plaintext[i+2] ^= t ^ u;
            plaintext[i+3] ^= t ^ v;
        }
		*/
		//i=0;
		t = tmp[0] ^ tmp[1] ^ tmp[2] ^ tmp[3];
		plaintext[0]   = t ^ tmp[0]   ^ mul2(tmp[0]   ^ tmp[1]);
		plaintext[1] = t ^ tmp[1] ^ mul2(tmp[1] ^ tmp[2]);
		plaintext[2] = t ^ tmp[2] ^ mul2(tmp[2] ^ tmp[3]);
		plaintext[3] = t ^ tmp[3] ^ mul2(tmp[3] ^ tmp[0]);
		u = mul2(mul2(tmp[0]   ^ tmp[2]));
		v = mul2(mul2(tmp[1] ^ tmp[3]));
		t = mul2(u ^ v);
		plaintext[0]   ^= t ^ u;
		plaintext[1] ^= t ^ v;
		plaintext[2] ^= t ^ u;
		plaintext[3] ^= t ^ v;
		
		//i+=4;
		t = tmp[4] ^ tmp[5] ^ tmp[6] ^ tmp[7];
		plaintext[4]   = t ^ tmp[4]   ^ mul2(tmp[4]   ^ tmp[5]);
		plaintext[5] = t ^ tmp[5] ^ mul2(tmp[5] ^ tmp[6]);
		plaintext[6] = t ^ tmp[6] ^ mul2(tmp[6] ^ tmp[7]);
		plaintext[7] = t ^ tmp[7] ^ mul2(tmp[7] ^ tmp[4]);
		u = mul2(mul2(tmp[4]   ^ tmp[6]));
		v = mul2(mul2(tmp[5] ^ tmp[7]));
		t = mul2(u ^ v);
		plaintext[4]   ^= t ^ u;
		plaintext[5] ^= t ^ v;
		plaintext[6] ^= t ^ u;
		plaintext[7] ^= t ^ v;
		
		//i+=4;
		t = tmp[8] ^ tmp[9] ^ tmp[10] ^ tmp[11];
		plaintext[8]   = t ^ tmp[8]   ^ mul2(tmp[8]   ^ tmp[9]);
		plaintext[9] = t ^ tmp[9] ^ mul2(tmp[9] ^ tmp[10]);
		plaintext[10] = t ^ tmp[10] ^ mul2(tmp[10] ^ tmp[11]);
		plaintext[11] = t ^ tmp[11] ^ mul2(tmp[11] ^ tmp[8]);
		u = mul2(mul2(tmp[8]   ^ tmp[10]));
		v = mul2(mul2(tmp[9] ^ tmp[11]));
		t = mul2(u ^ v);
		plaintext[8]   ^= t ^ u;
		plaintext[9] ^= t ^ v;
		plaintext[10] ^= t ^ u;
		plaintext[11] ^= t ^ v;
		
		//i+=4;
		t = tmp[12] ^ tmp[13] ^ tmp[14] ^ tmp[15];
		plaintext[12]   = t ^ tmp[12]   ^ mul2(tmp[12]   ^ tmp[13]);
		plaintext[13] = t ^ tmp[13] ^ mul2(tmp[13] ^ tmp[14]);
		plaintext[14] = t ^ tmp[14] ^ mul2(tmp[14] ^ tmp[15]);
		plaintext[15] = t ^ tmp[15] ^ mul2(tmp[15] ^ tmp[12]);
		u = mul2(mul2(tmp[12]   ^ tmp[14]));
		v = mul2(mul2(tmp[13] ^ tmp[15]));
		t = mul2(u ^ v);
		plaintext[12]   ^= t ^ u;
		plaintext[13] ^= t ^ v;
		plaintext[14] ^= t ^ u;
		plaintext[15] ^= t ^ v;
		
        
        // Inverse ShiftRows
        inv_shift_rows(plaintext);
        
        // Inverse SubBytes
        
		/*for (i = (AES_BLOCK_SIZE-1); i != 0; --i) {
            *(plaintext+i) = INV_SBOX[*(plaintext+i)];
        }
		*(plaintext+i) = INV_SBOX[*(plaintext+i)];
		*/
		*(plaintext+0) = INV_SBOX[*(plaintext+0)];
		*(plaintext+1) = INV_SBOX[*(plaintext+1)];
		*(plaintext+2) = INV_SBOX[*(plaintext+2)];
		*(plaintext+3) = INV_SBOX[*(plaintext+3)];
		*(plaintext+4) = INV_SBOX[*(plaintext+4)];
		*(plaintext+5) = INV_SBOX[*(plaintext+5)];
		*(plaintext+6) = INV_SBOX[*(plaintext+6)];
		*(plaintext+7) = INV_SBOX[*(plaintext+7)];
		*(plaintext+8) = INV_SBOX[*(plaintext+8)];
		*(plaintext+9) = INV_SBOX[*(plaintext+9)];
		*(plaintext+10) = INV_SBOX[*(plaintext+10)];
		*(plaintext+11) = INV_SBOX[*(plaintext+11)];
		*(plaintext+12) = INV_SBOX[*(plaintext+12)];
		*(plaintext+13) = INV_SBOX[*(plaintext+13)];
		*(plaintext+14) = INV_SBOX[*(plaintext+14)];
		*(plaintext+15) = INV_SBOX[*(plaintext+15)];

        roundkeys -= 16;

    }

    // last AddRoundKey
    /*
	for ( i = 0; i < AES_BLOCK_SIZE; ++i ) {
        *(plaintext+i) ^= *(roundkeys+i);
    }
	*/
	*(plaintext+0) ^= *(roundkeys+0);
	*(plaintext+1) ^= *(roundkeys+1);
	*(plaintext+2) ^= *(roundkeys+2);
	*(plaintext+3) ^= *(roundkeys+3);
	*(plaintext+4) ^= *(roundkeys+4);
	*(plaintext+5) ^= *(roundkeys+5);
	*(plaintext+6) ^= *(roundkeys+6);
	*(plaintext+7) ^= *(roundkeys+7);
	*(plaintext+8) ^= *(roundkeys+8);
	*(plaintext+9) ^= *(roundkeys+9);
	*(plaintext+10) ^= *(roundkeys+10);
	*(plaintext+11) ^= *(roundkeys+11);
	*(plaintext+12) ^= *(roundkeys+12);
	*(plaintext+13) ^= *(roundkeys+13);
	*(plaintext+14) ^= *(roundkeys+14);
	*(plaintext+15) ^= *(roundkeys+15);

}
