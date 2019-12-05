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

#include "aes_encrypt.h"
/*
 * Sbox
 */
uint8_t SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};


/**
 * https://en.wikipedia.org/wiki/Finite_field_arithmetic
 * Multiply two numbers in the GF(2^8) finite field defined
 * by the polynomial x^8 + x^4 + x^3 + x + 1 = 0
 * We do use mul2(int8_t a) but not mul(uint8_t a, uint8_t b)
 * just in order to get a higher speed.
 */
static inline uint8_t mul2(register uint8_t a)
{
    return (a&0x80) ? ((a<<1)^0x1b) : (a<<1);
}
/**
 * @purpose:    ShiftRows
 * @descrption:
 *  Row0: s0  s4  s8  s12   <<< 0 byte
 *  Row1: s1  s5  s9  s13   <<< 1 byte
 *  Row2: s2  s6  s10 s14   <<< 2 bytes
 *  Row3: s3  s7  s11 s15   <<< 3 bytes
 */
static void shift_rows(register uint8_t *state)
{
    register uint8_t temp;
    // row1
    temp        = *(state+1);
    *(state+1)  = *(state+5);
    *(state+5)  = *(state+9);
    *(state+9)  = *(state+13);
    *(state+13) = temp;
    // row2
    temp        = *(state+2);
    *(state+2)  = *(state+10);
    *(state+10) = temp;
    temp        = *(state+6);
    *(state+6)  = *(state+14);
    *(state+14) = temp;
    // row3
    temp        = *(state+15);
    *(state+15) = *(state+11);
    *(state+11) = *(state+7);
    *(state+7)  = *(state+3);
    *(state+3)  = temp;
}

void aes_encrypt_128( register uint8_t *roundkeys, register uint8_t *ciphertext)
{

    uint8_t tmp[16], t;
    //uint8_t i;
	//uint8_t j;

    // first AddRoundKey
    /*
	for ( i = AES_BLOCK_SIZE; i != 0; --i )
    {
        *(ciphertext+i) = plaintext[i] ^ *roundkeys++;
    }
	*(ciphertext+i) = plaintext[i] ^ *roundkeys++;
	*/
	*(ciphertext+0) = plaintext[0] ^ *roundkeys++;
	*(ciphertext+1) = plaintext[1] ^ *roundkeys++;
	*(ciphertext+2) = plaintext[2] ^ *roundkeys++;
	*(ciphertext+3) = plaintext[3] ^ *roundkeys++;
	*(ciphertext+4) = plaintext[4] ^ *roundkeys++;
	*(ciphertext+5) = plaintext[5] ^ *roundkeys++;
	*(ciphertext+6) = plaintext[6] ^ *roundkeys++;
	*(ciphertext+7) = plaintext[7] ^ *roundkeys++;
	*(ciphertext+8) = plaintext[8] ^ *roundkeys++;
	*(ciphertext+9) = plaintext[9] ^ *roundkeys++;
	*(ciphertext+10) = plaintext[10] ^ *roundkeys++;
	*(ciphertext+11) = plaintext[11] ^ *roundkeys++;
	*(ciphertext+12) = plaintext[12] ^ *roundkeys++;
	*(ciphertext+13) = plaintext[13] ^ *roundkeys++;
	*(ciphertext+14) = plaintext[14] ^ *roundkeys++;
	*(ciphertext+15) = plaintext[15] ^ *roundkeys++;

    // 9 rounds
    /*
	for (j = (AES_ROUNDS - 1); j != 0; --j)
    {
		*/

        // SubBytes
        /*
		for (i = (AES_BLOCK_SIZE-1); i != 0; --i)
        {
            *(tmp+i) = SBOX[*(ciphertext+i)];
        }
		*(tmp+i) = SBOX[*(ciphertext+i)];
		*/
		/*
		*(tmp+0) = SBOX[*(ciphertext+0)];
		*(tmp+1) = SBOX[*(ciphertext+1)];
		*(tmp+2) = SBOX[*(ciphertext+2)];
		*(tmp+3) = SBOX[*(ciphertext+3)];
		*(tmp+4) = SBOX[*(ciphertext+4)];
		*(tmp+5) = SBOX[*(ciphertext+5)];
		*(tmp+6) = SBOX[*(ciphertext+6)];
		*(tmp+7) = SBOX[*(ciphertext+7)];
		*(tmp+8) = SBOX[*(ciphertext+8)];
		*(tmp+9) = SBOX[*(ciphertext+9)];
		*(tmp+10) = SBOX[*(ciphertext+10)];
		*(tmp+11) = SBOX[*(ciphertext+11)];
		*(tmp+12) = SBOX[*(ciphertext+12)];
		*(tmp+13) = SBOX[*(ciphertext+13)];
		*(tmp+14) = SBOX[*(ciphertext+14)];
		*(tmp+15) = SBOX[*(ciphertext+15)];
        shift_rows(tmp);
		*/
        /*
         * MixColumns 
         * [02 03 01 01]   [s0  s4  s8  s12]
         * [01 02 03 01] . [s1  s5  s9  s13]
         * [01 01 02 03]   [s2  s6  s10 s14]
         * [03 01 01 02]   [s3  s7  s11 s15]
         */
        /*
		for (i = 0; i < AES_BLOCK_SIZE; i+=4)
        {
            t = tmp[i] ^ tmp[i+1] ^ tmp[i+2] ^ tmp[i+3];
            ciphertext[i]   = mul2(tmp[i]   ^ tmp[i+1]) ^ tmp[i]   ^ t;
            ciphertext[i+1] = mul2(tmp[i+1] ^ tmp[i+2]) ^ tmp[i+1] ^ t;
            ciphertext[i+2] = mul2(tmp[i+2] ^ tmp[i+3]) ^ tmp[i+2] ^ t;
            ciphertext[i+3] = mul2(tmp[i+3] ^ tmp[i]  ) ^ tmp[i+3] ^ t;
        }
		*/			
			/*
			t = tmp[0] ^ tmp[1] ^ tmp[2] ^ tmp[3];
            ciphertext[0]   = mul2(tmp[0]   ^ tmp[1]) ^ tmp[0]   ^ t;
            ciphertext[1] = mul2(tmp[1] ^ tmp[2]) ^ tmp[1] ^ t;
            ciphertext[2] = mul2(tmp[2] ^ tmp[3]) ^ tmp[2] ^ t;
            ciphertext[3] = mul2(tmp[3] ^ tmp[0]  ) ^ tmp[3] ^ t;
			
			t = tmp[4] ^ tmp[5] ^ tmp[6] ^ tmp[7];
            ciphertext[4]   = mul2(tmp[4]   ^ tmp[5]) ^ tmp[4]   ^ t;
            ciphertext[5] = mul2(tmp[5] ^ tmp[6]) ^ tmp[5] ^ t;
            ciphertext[6] = mul2(tmp[6] ^ tmp[7]) ^ tmp[6] ^ t;
            ciphertext[7] = mul2(tmp[7] ^ tmp[4]  ) ^ tmp[7] ^ t;
			
			t = tmp[8] ^ tmp[9] ^ tmp[10] ^ tmp[11];
            ciphertext[8]   = mul2(tmp[8]   ^ tmp[9]) ^ tmp[8]   ^ t;
            ciphertext[9] = mul2(tmp[9] ^ tmp[10]) ^ tmp[9] ^ t;
            ciphertext[10] = mul2(tmp[10] ^ tmp[11]) ^ tmp[10] ^ t;
            ciphertext[11] = mul2(tmp[11] ^ tmp[8]  ) ^ tmp[11] ^ t;
			
			t = tmp[12] ^ tmp[13] ^ tmp[14] ^ tmp[15];
            ciphertext[12]   = mul2(tmp[12]   ^ tmp[13]) ^ tmp[12]   ^ t;
            ciphertext[13] = mul2(tmp[13] ^ tmp[14]) ^ tmp[13] ^ t;
            ciphertext[14] = mul2(tmp[14] ^ tmp[15]) ^ tmp[14] ^ t;
            ciphertext[15] = mul2(tmp[15] ^ tmp[12]  ) ^ tmp[15] ^ t;
			*/
			

        // AddRoundKey
        /*
		for ( i = AES_BLOCK_SIZE-1; i != 0; --i )
        {
            *(ciphertext+i) ^= *roundkeys++;
        }
		*(ciphertext+i) ^= *roundkeys++;
		*/
		/*
		*(ciphertext+0) ^= *roundkeys++;
		*(ciphertext+1) ^= *roundkeys++;
		*(ciphertext+2) ^= *roundkeys++;
		*(ciphertext+3) ^= *roundkeys++;
		*(ciphertext+4) ^= *roundkeys++;
		*(ciphertext+5) ^= *roundkeys++;
		*(ciphertext+6) ^= *roundkeys++;
		*(ciphertext+7) ^= *roundkeys++;
		*(ciphertext+8) ^= *roundkeys++;
		*(ciphertext+9) ^= *roundkeys++;
		*(ciphertext+10) ^= *roundkeys++;
		*(ciphertext+11) ^= *roundkeys++;
		*(ciphertext+12) ^= *roundkeys++;
		*(ciphertext+13) ^= *roundkeys++;
		*(ciphertext+14) ^= *roundkeys++;
		*(ciphertext+15) ^= *roundkeys++;
		*/
/*
    }
	*/

		*(tmp+0) = SBOX[*(ciphertext+0)];
		*(tmp+1) = SBOX[*(ciphertext+1)];
		*(tmp+2) = SBOX[*(ciphertext+2)];
		*(tmp+3) = SBOX[*(ciphertext+3)];
		*(tmp+4) = SBOX[*(ciphertext+4)];
		*(tmp+5) = SBOX[*(ciphertext+5)];
		*(tmp+6) = SBOX[*(ciphertext+6)];
		*(tmp+7) = SBOX[*(ciphertext+7)];
		*(tmp+8) = SBOX[*(ciphertext+8)];
		*(tmp+9) = SBOX[*(ciphertext+9)];
		*(tmp+10) = SBOX[*(ciphertext+10)];
		*(tmp+11) = SBOX[*(ciphertext+11)];
		*(tmp+12) = SBOX[*(ciphertext+12)];
		*(tmp+13) = SBOX[*(ciphertext+13)];
		*(tmp+14) = SBOX[*(ciphertext+14)];
		*(tmp+15) = SBOX[*(ciphertext+15)];
        shift_rows(tmp);
		
		t = tmp[0] ^ tmp[1] ^ tmp[2] ^ tmp[3];
        ciphertext[0]   = mul2(tmp[0]   ^ tmp[1]) ^ tmp[0]   ^ t;
        ciphertext[1] = mul2(tmp[1] ^ tmp[2]) ^ tmp[1] ^ t;
        ciphertext[2] = mul2(tmp[2] ^ tmp[3]) ^ tmp[2] ^ t;
        ciphertext[3] = mul2(tmp[3] ^ tmp[0]  ) ^ tmp[3] ^ t;
			
		t = tmp[4] ^ tmp[5] ^ tmp[6] ^ tmp[7];
        ciphertext[4]   = mul2(tmp[4]   ^ tmp[5]) ^ tmp[4]   ^ t;
        ciphertext[5] = mul2(tmp[5] ^ tmp[6]) ^ tmp[5] ^ t;
        ciphertext[6] = mul2(tmp[6] ^ tmp[7]) ^ tmp[6] ^ t;
        ciphertext[7] = mul2(tmp[7] ^ tmp[4]  ) ^ tmp[7] ^ t;
			
		t = tmp[8] ^ tmp[9] ^ tmp[10] ^ tmp[11];
        ciphertext[8]   = mul2(tmp[8]   ^ tmp[9]) ^ tmp[8]   ^ t;
        ciphertext[9] = mul2(tmp[9] ^ tmp[10]) ^ tmp[9] ^ t;
        ciphertext[10] = mul2(tmp[10] ^ tmp[11]) ^ tmp[10] ^ t;
        ciphertext[11] = mul2(tmp[11] ^ tmp[8]  ) ^ tmp[11] ^ t;
			
		t = tmp[12] ^ tmp[13] ^ tmp[14] ^ tmp[15];
        ciphertext[12]   = mul2(tmp[12]   ^ tmp[13]) ^ tmp[12]   ^ t;
        ciphertext[13] = mul2(tmp[13] ^ tmp[14]) ^ tmp[13] ^ t;
        ciphertext[14] = mul2(tmp[14] ^ tmp[15]) ^ tmp[14] ^ t;
        ciphertext[15] = mul2(tmp[15] ^ tmp[12]  ) ^ tmp[15] ^ t;
		
		*(ciphertext+0) ^= *roundkeys++;
		*(ciphertext+1) ^= *roundkeys++;
		*(ciphertext+2) ^= *roundkeys++;
		*(ciphertext+3) ^= *roundkeys++;
		*(ciphertext+4) ^= *roundkeys++;
		*(ciphertext+5) ^= *roundkeys++;
		*(ciphertext+6) ^= *roundkeys++;
		*(ciphertext+7) ^= *roundkeys++;
		*(ciphertext+8) ^= *roundkeys++;
		*(ciphertext+9) ^= *roundkeys++;
		*(ciphertext+10) ^= *roundkeys++;
		*(ciphertext+11) ^= *roundkeys++;
		*(ciphertext+12) ^= *roundkeys++;
		*(ciphertext+13) ^= *roundkeys++;
		*(ciphertext+14) ^= *roundkeys++;
		*(ciphertext+15) ^= *roundkeys++;
		
		*(tmp+0) = SBOX[*(ciphertext+0)];
		*(tmp+1) = SBOX[*(ciphertext+1)];
		*(tmp+2) = SBOX[*(ciphertext+2)];
		*(tmp+3) = SBOX[*(ciphertext+3)];
		*(tmp+4) = SBOX[*(ciphertext+4)];
		*(tmp+5) = SBOX[*(ciphertext+5)];
		*(tmp+6) = SBOX[*(ciphertext+6)];
		*(tmp+7) = SBOX[*(ciphertext+7)];
		*(tmp+8) = SBOX[*(ciphertext+8)];
		*(tmp+9) = SBOX[*(ciphertext+9)];
		*(tmp+10) = SBOX[*(ciphertext+10)];
		*(tmp+11) = SBOX[*(ciphertext+11)];
		*(tmp+12) = SBOX[*(ciphertext+12)];
		*(tmp+13) = SBOX[*(ciphertext+13)];
		*(tmp+14) = SBOX[*(ciphertext+14)];
		*(tmp+15) = SBOX[*(ciphertext+15)];
        shift_rows(tmp);
		
		t = tmp[0] ^ tmp[1] ^ tmp[2] ^ tmp[3];
        ciphertext[0]   = mul2(tmp[0]   ^ tmp[1]) ^ tmp[0]   ^ t;
        ciphertext[1] = mul2(tmp[1] ^ tmp[2]) ^ tmp[1] ^ t;
        ciphertext[2] = mul2(tmp[2] ^ tmp[3]) ^ tmp[2] ^ t;
        ciphertext[3] = mul2(tmp[3] ^ tmp[0]  ) ^ tmp[3] ^ t;
			
		t = tmp[4] ^ tmp[5] ^ tmp[6] ^ tmp[7];
        ciphertext[4]   = mul2(tmp[4]   ^ tmp[5]) ^ tmp[4]   ^ t;
        ciphertext[5] = mul2(tmp[5] ^ tmp[6]) ^ tmp[5] ^ t;
        ciphertext[6] = mul2(tmp[6] ^ tmp[7]) ^ tmp[6] ^ t;
        ciphertext[7] = mul2(tmp[7] ^ tmp[4]  ) ^ tmp[7] ^ t;
			
		t = tmp[8] ^ tmp[9] ^ tmp[10] ^ tmp[11];
        ciphertext[8]   = mul2(tmp[8]   ^ tmp[9]) ^ tmp[8]   ^ t;
        ciphertext[9] = mul2(tmp[9] ^ tmp[10]) ^ tmp[9] ^ t;
        ciphertext[10] = mul2(tmp[10] ^ tmp[11]) ^ tmp[10] ^ t;
        ciphertext[11] = mul2(tmp[11] ^ tmp[8]  ) ^ tmp[11] ^ t;
			
		t = tmp[12] ^ tmp[13] ^ tmp[14] ^ tmp[15];
        ciphertext[12]   = mul2(tmp[12]   ^ tmp[13]) ^ tmp[12]   ^ t;
        ciphertext[13] = mul2(tmp[13] ^ tmp[14]) ^ tmp[13] ^ t;
        ciphertext[14] = mul2(tmp[14] ^ tmp[15]) ^ tmp[14] ^ t;
        ciphertext[15] = mul2(tmp[15] ^ tmp[12]  ) ^ tmp[15] ^ t;
		
		*(ciphertext+0) ^= *roundkeys++;
		*(ciphertext+1) ^= *roundkeys++;
		*(ciphertext+2) ^= *roundkeys++;
		*(ciphertext+3) ^= *roundkeys++;
		*(ciphertext+4) ^= *roundkeys++;
		*(ciphertext+5) ^= *roundkeys++;
		*(ciphertext+6) ^= *roundkeys++;
		*(ciphertext+7) ^= *roundkeys++;
		*(ciphertext+8) ^= *roundkeys++;
		*(ciphertext+9) ^= *roundkeys++;
		*(ciphertext+10) ^= *roundkeys++;
		*(ciphertext+11) ^= *roundkeys++;
		*(ciphertext+12) ^= *roundkeys++;
		*(ciphertext+13) ^= *roundkeys++;
		*(ciphertext+14) ^= *roundkeys++;
		*(ciphertext+15) ^= *roundkeys++;
		
		*(tmp+0) = SBOX[*(ciphertext+0)];
		*(tmp+1) = SBOX[*(ciphertext+1)];
		*(tmp+2) = SBOX[*(ciphertext+2)];
		*(tmp+3) = SBOX[*(ciphertext+3)];
		*(tmp+4) = SBOX[*(ciphertext+4)];
		*(tmp+5) = SBOX[*(ciphertext+5)];
		*(tmp+6) = SBOX[*(ciphertext+6)];
		*(tmp+7) = SBOX[*(ciphertext+7)];
		*(tmp+8) = SBOX[*(ciphertext+8)];
		*(tmp+9) = SBOX[*(ciphertext+9)];
		*(tmp+10) = SBOX[*(ciphertext+10)];
		*(tmp+11) = SBOX[*(ciphertext+11)];
		*(tmp+12) = SBOX[*(ciphertext+12)];
		*(tmp+13) = SBOX[*(ciphertext+13)];
		*(tmp+14) = SBOX[*(ciphertext+14)];
		*(tmp+15) = SBOX[*(ciphertext+15)];
        shift_rows(tmp);
		
		t = tmp[0] ^ tmp[1] ^ tmp[2] ^ tmp[3];
        ciphertext[0]   = mul2(tmp[0]   ^ tmp[1]) ^ tmp[0]   ^ t;
        ciphertext[1] = mul2(tmp[1] ^ tmp[2]) ^ tmp[1] ^ t;
        ciphertext[2] = mul2(tmp[2] ^ tmp[3]) ^ tmp[2] ^ t;
        ciphertext[3] = mul2(tmp[3] ^ tmp[0]  ) ^ tmp[3] ^ t;
			
		t = tmp[4] ^ tmp[5] ^ tmp[6] ^ tmp[7];
        ciphertext[4]   = mul2(tmp[4]   ^ tmp[5]) ^ tmp[4]   ^ t;
        ciphertext[5] = mul2(tmp[5] ^ tmp[6]) ^ tmp[5] ^ t;
        ciphertext[6] = mul2(tmp[6] ^ tmp[7]) ^ tmp[6] ^ t;
        ciphertext[7] = mul2(tmp[7] ^ tmp[4]  ) ^ tmp[7] ^ t;
			
		t = tmp[8] ^ tmp[9] ^ tmp[10] ^ tmp[11];
        ciphertext[8]   = mul2(tmp[8]   ^ tmp[9]) ^ tmp[8]   ^ t;
        ciphertext[9] = mul2(tmp[9] ^ tmp[10]) ^ tmp[9] ^ t;
        ciphertext[10] = mul2(tmp[10] ^ tmp[11]) ^ tmp[10] ^ t;
        ciphertext[11] = mul2(tmp[11] ^ tmp[8]  ) ^ tmp[11] ^ t;
			
		t = tmp[12] ^ tmp[13] ^ tmp[14] ^ tmp[15];
        ciphertext[12]   = mul2(tmp[12]   ^ tmp[13]) ^ tmp[12]   ^ t;
        ciphertext[13] = mul2(tmp[13] ^ tmp[14]) ^ tmp[13] ^ t;
        ciphertext[14] = mul2(tmp[14] ^ tmp[15]) ^ tmp[14] ^ t;
        ciphertext[15] = mul2(tmp[15] ^ tmp[12]  ) ^ tmp[15] ^ t;
		
		*(ciphertext+0) ^= *roundkeys++;
		*(ciphertext+1) ^= *roundkeys++;
		*(ciphertext+2) ^= *roundkeys++;
		*(ciphertext+3) ^= *roundkeys++;
		*(ciphertext+4) ^= *roundkeys++;
		*(ciphertext+5) ^= *roundkeys++;
		*(ciphertext+6) ^= *roundkeys++;
		*(ciphertext+7) ^= *roundkeys++;
		*(ciphertext+8) ^= *roundkeys++;
		*(ciphertext+9) ^= *roundkeys++;
		*(ciphertext+10) ^= *roundkeys++;
		*(ciphertext+11) ^= *roundkeys++;
		*(ciphertext+12) ^= *roundkeys++;
		*(ciphertext+13) ^= *roundkeys++;
		*(ciphertext+14) ^= *roundkeys++;
		*(ciphertext+15) ^= *roundkeys++;
		
		*(tmp+0) = SBOX[*(ciphertext+0)];
		*(tmp+1) = SBOX[*(ciphertext+1)];
		*(tmp+2) = SBOX[*(ciphertext+2)];
		*(tmp+3) = SBOX[*(ciphertext+3)];
		*(tmp+4) = SBOX[*(ciphertext+4)];
		*(tmp+5) = SBOX[*(ciphertext+5)];
		*(tmp+6) = SBOX[*(ciphertext+6)];
		*(tmp+7) = SBOX[*(ciphertext+7)];
		*(tmp+8) = SBOX[*(ciphertext+8)];
		*(tmp+9) = SBOX[*(ciphertext+9)];
		*(tmp+10) = SBOX[*(ciphertext+10)];
		*(tmp+11) = SBOX[*(ciphertext+11)];
		*(tmp+12) = SBOX[*(ciphertext+12)];
		*(tmp+13) = SBOX[*(ciphertext+13)];
		*(tmp+14) = SBOX[*(ciphertext+14)];
		*(tmp+15) = SBOX[*(ciphertext+15)];
        shift_rows(tmp);
		
		t = tmp[0] ^ tmp[1] ^ tmp[2] ^ tmp[3];
        ciphertext[0] = mul2(tmp[0]   ^ tmp[1]) ^ tmp[0]   ^ t;
        ciphertext[1] = mul2(tmp[1] ^ tmp[2]) ^ tmp[1] ^ t;
        ciphertext[2] = mul2(tmp[2] ^ tmp[3]) ^ tmp[2] ^ t;
        ciphertext[3] = mul2(tmp[3] ^ tmp[0]  ) ^ tmp[3] ^ t;
			
		t = tmp[4] ^ tmp[5] ^ tmp[6] ^ tmp[7];
        ciphertext[4] = mul2(tmp[4]   ^ tmp[5]) ^ tmp[4]   ^ t;
        ciphertext[5] = mul2(tmp[5] ^ tmp[6]) ^ tmp[5] ^ t;
        ciphertext[6] = mul2(tmp[6] ^ tmp[7]) ^ tmp[6] ^ t;
        ciphertext[7] = mul2(tmp[7] ^ tmp[4]  ) ^ tmp[7] ^ t;
			
		t = tmp[8] ^ tmp[9] ^ tmp[10] ^ tmp[11];
        ciphertext[8]  = mul2(tmp[8]   ^ tmp[9]) ^ tmp[8]   ^ t;
        ciphertext[9]  = mul2(tmp[9] ^ tmp[10]) ^ tmp[9] ^ t;
        ciphertext[10] = mul2(tmp[10] ^ tmp[11]) ^ tmp[10] ^ t;
        ciphertext[11] = mul2(tmp[11] ^ tmp[8]  ) ^ tmp[11] ^ t;
			
		t = tmp[12] ^ tmp[13] ^ tmp[14] ^ tmp[15];
        ciphertext[12] = mul2(tmp[12]   ^ tmp[13]) ^ tmp[12]   ^ t;
        ciphertext[13] = mul2(tmp[13] ^ tmp[14]) ^ tmp[13] ^ t;
        ciphertext[14] = mul2(tmp[14] ^ tmp[15]) ^ tmp[14] ^ t;
        ciphertext[15] = mul2(tmp[15] ^ tmp[12]  ) ^ tmp[15] ^ t;
		
		*(ciphertext+0) ^= *roundkeys++;
		*(ciphertext+1) ^= *roundkeys++;
		*(ciphertext+2) ^= *roundkeys++;
		*(ciphertext+3) ^= *roundkeys++;
		*(ciphertext+4) ^= *roundkeys++;
		*(ciphertext+5) ^= *roundkeys++;
		*(ciphertext+6) ^= *roundkeys++;
		*(ciphertext+7) ^= *roundkeys++;
		*(ciphertext+8) ^= *roundkeys++;
		*(ciphertext+9) ^= *roundkeys++;
		*(ciphertext+10) ^= *roundkeys++;
		*(ciphertext+11) ^= *roundkeys++;
		*(ciphertext+12) ^= *roundkeys++;
		*(ciphertext+13) ^= *roundkeys++;
		*(ciphertext+14) ^= *roundkeys++;
		*(ciphertext+15) ^= *roundkeys++;
		
		*(tmp+0) = SBOX[*(ciphertext+0)];
		*(tmp+1) = SBOX[*(ciphertext+1)];
		*(tmp+2) = SBOX[*(ciphertext+2)];
		*(tmp+3) = SBOX[*(ciphertext+3)];
		*(tmp+4) = SBOX[*(ciphertext+4)];
		*(tmp+5) = SBOX[*(ciphertext+5)];
		*(tmp+6) = SBOX[*(ciphertext+6)];
		*(tmp+7) = SBOX[*(ciphertext+7)];
		*(tmp+8) = SBOX[*(ciphertext+8)];
		*(tmp+9) = SBOX[*(ciphertext+9)];
		*(tmp+10) = SBOX[*(ciphertext+10)];
		*(tmp+11) = SBOX[*(ciphertext+11)];
		*(tmp+12) = SBOX[*(ciphertext+12)];
		*(tmp+13) = SBOX[*(ciphertext+13)];
		*(tmp+14) = SBOX[*(ciphertext+14)];
		*(tmp+15) = SBOX[*(ciphertext+15)];
        shift_rows(tmp);
		
		t = tmp[0] ^ tmp[1] ^ tmp[2] ^ tmp[3];
        ciphertext[0] = mul2(tmp[0]   ^ tmp[1]) ^ tmp[0]   ^ t;
        ciphertext[1] = mul2(tmp[1] ^ tmp[2]) ^ tmp[1] ^ t;
        ciphertext[2] = mul2(tmp[2] ^ tmp[3]) ^ tmp[2] ^ t;
        ciphertext[3] = mul2(tmp[3] ^ tmp[0]  ) ^ tmp[3] ^ t;
			
		t = tmp[4] ^ tmp[5] ^ tmp[6] ^ tmp[7];
        ciphertext[4]   = mul2(tmp[4]   ^ tmp[5]) ^ tmp[4]   ^ t;
        ciphertext[5] = mul2(tmp[5] ^ tmp[6]) ^ tmp[5] ^ t;
        ciphertext[6] = mul2(tmp[6] ^ tmp[7]) ^ tmp[6] ^ t;
        ciphertext[7] = mul2(tmp[7] ^ tmp[4]  ) ^ tmp[7] ^ t;
			
		t = tmp[8] ^ tmp[9] ^ tmp[10] ^ tmp[11];
        ciphertext[8]  = mul2(tmp[8]   ^ tmp[9]) ^ tmp[8]   ^ t;
        ciphertext[9]  = mul2(tmp[9] ^ tmp[10]) ^ tmp[9] ^ t;
        ciphertext[10] = mul2(tmp[10] ^ tmp[11]) ^ tmp[10] ^ t;
        ciphertext[11] = mul2(tmp[11] ^ tmp[8]  ) ^ tmp[11] ^ t;
			
		t = tmp[12] ^ tmp[13] ^ tmp[14] ^ tmp[15];
        ciphertext[12] = mul2(tmp[12]   ^ tmp[13]) ^ tmp[12]   ^ t;
        ciphertext[13] = mul2(tmp[13] ^ tmp[14]) ^ tmp[13] ^ t;
        ciphertext[14] = mul2(tmp[14] ^ tmp[15]) ^ tmp[14] ^ t;
        ciphertext[15] = mul2(tmp[15] ^ tmp[12]  ) ^ tmp[15] ^ t;
		
		*(ciphertext+0) ^= *roundkeys++;
		*(ciphertext+1) ^= *roundkeys++;
		*(ciphertext+2) ^= *roundkeys++;
		*(ciphertext+3) ^= *roundkeys++;
		*(ciphertext+4) ^= *roundkeys++;
		*(ciphertext+5) ^= *roundkeys++;
		*(ciphertext+6) ^= *roundkeys++;
		*(ciphertext+7) ^= *roundkeys++;
		*(ciphertext+8) ^= *roundkeys++;
		*(ciphertext+9) ^= *roundkeys++;
		*(ciphertext+10) ^= *roundkeys++;
		*(ciphertext+11) ^= *roundkeys++;
		*(ciphertext+12) ^= *roundkeys++;
		*(ciphertext+13) ^= *roundkeys++;
		*(ciphertext+14) ^= *roundkeys++;
		*(ciphertext+15) ^= *roundkeys++;
		
		*(tmp+0) = SBOX[*(ciphertext+0)];
		*(tmp+1) = SBOX[*(ciphertext+1)];
		*(tmp+2) = SBOX[*(ciphertext+2)];
		*(tmp+3) = SBOX[*(ciphertext+3)];
		*(tmp+4) = SBOX[*(ciphertext+4)];
		*(tmp+5) = SBOX[*(ciphertext+5)];
		*(tmp+6) = SBOX[*(ciphertext+6)];
		*(tmp+7) = SBOX[*(ciphertext+7)];
		*(tmp+8) = SBOX[*(ciphertext+8)];
		*(tmp+9) = SBOX[*(ciphertext+9)];
		*(tmp+10) = SBOX[*(ciphertext+10)];
		*(tmp+11) = SBOX[*(ciphertext+11)];
		*(tmp+12) = SBOX[*(ciphertext+12)];
		*(tmp+13) = SBOX[*(ciphertext+13)];
		*(tmp+14) = SBOX[*(ciphertext+14)];
		*(tmp+15) = SBOX[*(ciphertext+15)];
        shift_rows(tmp);
		
		t = tmp[0] ^ tmp[1] ^ tmp[2] ^ tmp[3];
        ciphertext[0] = mul2(tmp[0]   ^ tmp[1]) ^ tmp[0]   ^ t;
        ciphertext[1] = mul2(tmp[1] ^ tmp[2]) ^ tmp[1] ^ t;
        ciphertext[2] = mul2(tmp[2] ^ tmp[3]) ^ tmp[2] ^ t;
        ciphertext[3] = mul2(tmp[3] ^ tmp[0]  ) ^ tmp[3] ^ t;
			
		t = tmp[4] ^ tmp[5] ^ tmp[6] ^ tmp[7];
        ciphertext[4] = mul2(tmp[4]   ^ tmp[5]) ^ tmp[4]   ^ t;
        ciphertext[5] = mul2(tmp[5] ^ tmp[6]) ^ tmp[5] ^ t;
        ciphertext[6] = mul2(tmp[6] ^ tmp[7]) ^ tmp[6] ^ t;
        ciphertext[7] = mul2(tmp[7] ^ tmp[4]  ) ^ tmp[7] ^ t;
			
		t = tmp[8] ^ tmp[9] ^ tmp[10] ^ tmp[11];
        ciphertext[8]  = mul2(tmp[8]   ^ tmp[9]) ^ tmp[8]   ^ t;
        ciphertext[9]  = mul2(tmp[9] ^ tmp[10]) ^ tmp[9] ^ t;
        ciphertext[10] = mul2(tmp[10] ^ tmp[11]) ^ tmp[10] ^ t;
        ciphertext[11] = mul2(tmp[11] ^ tmp[8]  ) ^ tmp[11] ^ t;
			
		t = tmp[12] ^ tmp[13] ^ tmp[14] ^ tmp[15];
        ciphertext[12] = mul2(tmp[12]   ^ tmp[13]) ^ tmp[12]   ^ t;
        ciphertext[13] = mul2(tmp[13] ^ tmp[14]) ^ tmp[13] ^ t;
        ciphertext[14] = mul2(tmp[14] ^ tmp[15]) ^ tmp[14] ^ t;
        ciphertext[15] = mul2(tmp[15] ^ tmp[12]  ) ^ tmp[15] ^ t;
		
		*(ciphertext+0) ^= *roundkeys++;
		*(ciphertext+1) ^= *roundkeys++;
		*(ciphertext+2) ^= *roundkeys++;
		*(ciphertext+3) ^= *roundkeys++;
		*(ciphertext+4) ^= *roundkeys++;
		*(ciphertext+5) ^= *roundkeys++;
		*(ciphertext+6) ^= *roundkeys++;
		*(ciphertext+7) ^= *roundkeys++;
		*(ciphertext+8) ^= *roundkeys++;
		*(ciphertext+9) ^= *roundkeys++;
		*(ciphertext+10) ^= *roundkeys++;
		*(ciphertext+11) ^= *roundkeys++;
		*(ciphertext+12) ^= *roundkeys++;
		*(ciphertext+13) ^= *roundkeys++;
		*(ciphertext+14) ^= *roundkeys++;
		*(ciphertext+15) ^= *roundkeys++;
		
		*(tmp+0) = SBOX[*(ciphertext+0)];
		*(tmp+1) = SBOX[*(ciphertext+1)];
		*(tmp+2) = SBOX[*(ciphertext+2)];
		*(tmp+3) = SBOX[*(ciphertext+3)];
		*(tmp+4) = SBOX[*(ciphertext+4)];
		*(tmp+5) = SBOX[*(ciphertext+5)];
		*(tmp+6) = SBOX[*(ciphertext+6)];
		*(tmp+7) = SBOX[*(ciphertext+7)];
		*(tmp+8) = SBOX[*(ciphertext+8)];
		*(tmp+9) = SBOX[*(ciphertext+9)];
		*(tmp+10) = SBOX[*(ciphertext+10)];
		*(tmp+11) = SBOX[*(ciphertext+11)];
		*(tmp+12) = SBOX[*(ciphertext+12)];
		*(tmp+13) = SBOX[*(ciphertext+13)];
		*(tmp+14) = SBOX[*(ciphertext+14)];
		*(tmp+15) = SBOX[*(ciphertext+15)];
        shift_rows(tmp);
		
		t = tmp[0] ^ tmp[1] ^ tmp[2] ^ tmp[3];
        ciphertext[0] = mul2(tmp[0]   ^ tmp[1]) ^ tmp[0]   ^ t;
        ciphertext[1] = mul2(tmp[1] ^ tmp[2]) ^ tmp[1] ^ t;
        ciphertext[2] = mul2(tmp[2] ^ tmp[3]) ^ tmp[2] ^ t;
        ciphertext[3] = mul2(tmp[3] ^ tmp[0]  ) ^ tmp[3] ^ t;
			
		t = tmp[4] ^ tmp[5] ^ tmp[6] ^ tmp[7];
        ciphertext[4] = mul2(tmp[4]   ^ tmp[5]) ^ tmp[4]   ^ t;
        ciphertext[5] = mul2(tmp[5] ^ tmp[6]) ^ tmp[5] ^ t;
        ciphertext[6] = mul2(tmp[6] ^ tmp[7]) ^ tmp[6] ^ t;
        ciphertext[7] = mul2(tmp[7] ^ tmp[4]  ) ^ tmp[7] ^ t;
			
		t = tmp[8] ^ tmp[9] ^ tmp[10] ^ tmp[11];
        ciphertext[8]  = mul2(tmp[8]   ^ tmp[9]) ^ tmp[8]   ^ t;
        ciphertext[9]  = mul2(tmp[9] ^ tmp[10]) ^ tmp[9] ^ t;
        ciphertext[10] = mul2(tmp[10] ^ tmp[11]) ^ tmp[10] ^ t;
        ciphertext[11] = mul2(tmp[11] ^ tmp[8]  ) ^ tmp[11] ^ t;
			
		t = tmp[12] ^ tmp[13] ^ tmp[14] ^ tmp[15];
        ciphertext[12] = mul2(tmp[12]   ^ tmp[13]) ^ tmp[12]   ^ t;
        ciphertext[13] = mul2(tmp[13] ^ tmp[14]) ^ tmp[13] ^ t;
        ciphertext[14] = mul2(tmp[14] ^ tmp[15]) ^ tmp[14] ^ t;
        ciphertext[15] = mul2(tmp[15] ^ tmp[12]  ) ^ tmp[15] ^ t;
		
		*(ciphertext+0) ^= *roundkeys++;
		*(ciphertext+1) ^= *roundkeys++;
		*(ciphertext+2) ^= *roundkeys++;
		*(ciphertext+3) ^= *roundkeys++;
		*(ciphertext+4) ^= *roundkeys++;
		*(ciphertext+5) ^= *roundkeys++;
		*(ciphertext+6) ^= *roundkeys++;
		*(ciphertext+7) ^= *roundkeys++;
		*(ciphertext+8) ^= *roundkeys++;
		*(ciphertext+9) ^= *roundkeys++;
		*(ciphertext+10) ^= *roundkeys++;
		*(ciphertext+11) ^= *roundkeys++;
		*(ciphertext+12) ^= *roundkeys++;
		*(ciphertext+13) ^= *roundkeys++;
		*(ciphertext+14) ^= *roundkeys++;
		*(ciphertext+15) ^= *roundkeys++;
		
		*(tmp+0) = SBOX[*(ciphertext+0)];
		*(tmp+1) = SBOX[*(ciphertext+1)];
		*(tmp+2) = SBOX[*(ciphertext+2)];
		*(tmp+3) = SBOX[*(ciphertext+3)];
		*(tmp+4) = SBOX[*(ciphertext+4)];
		*(tmp+5) = SBOX[*(ciphertext+5)];
		*(tmp+6) = SBOX[*(ciphertext+6)];
		*(tmp+7) = SBOX[*(ciphertext+7)];
		*(tmp+8) = SBOX[*(ciphertext+8)];
		*(tmp+9) = SBOX[*(ciphertext+9)];
		*(tmp+10) = SBOX[*(ciphertext+10)];
		*(tmp+11) = SBOX[*(ciphertext+11)];
		*(tmp+12) = SBOX[*(ciphertext+12)];
		*(tmp+13) = SBOX[*(ciphertext+13)];
		*(tmp+14) = SBOX[*(ciphertext+14)];
		*(tmp+15) = SBOX[*(ciphertext+15)];
        shift_rows(tmp);
		
		t = tmp[0] ^ tmp[1] ^ tmp[2] ^ tmp[3];
        ciphertext[0] = mul2(tmp[0]   ^ tmp[1]) ^ tmp[0]   ^ t;
        ciphertext[1] = mul2(tmp[1] ^ tmp[2]) ^ tmp[1] ^ t;
        ciphertext[2] = mul2(tmp[2] ^ tmp[3]) ^ tmp[2] ^ t;
        ciphertext[3] = mul2(tmp[3] ^ tmp[0]  ) ^ tmp[3] ^ t;
			
		t = tmp[4] ^ tmp[5] ^ tmp[6] ^ tmp[7];
        ciphertext[4]   = mul2(tmp[4]   ^ tmp[5]) ^ tmp[4]   ^ t;
        ciphertext[5] = mul2(tmp[5] ^ tmp[6]) ^ tmp[5] ^ t;
        ciphertext[6] = mul2(tmp[6] ^ tmp[7]) ^ tmp[6] ^ t;
        ciphertext[7] = mul2(tmp[7] ^ tmp[4]  ) ^ tmp[7] ^ t;
			
		t = tmp[8] ^ tmp[9] ^ tmp[10] ^ tmp[11];
        ciphertext[8]   = mul2(tmp[8]   ^ tmp[9]) ^ tmp[8]   ^ t;
        ciphertext[9] = mul2(tmp[9] ^ tmp[10]) ^ tmp[9] ^ t;
        ciphertext[10] = mul2(tmp[10] ^ tmp[11]) ^ tmp[10] ^ t;
        ciphertext[11] = mul2(tmp[11] ^ tmp[8]  ) ^ tmp[11] ^ t;
			
		t = tmp[12] ^ tmp[13] ^ tmp[14] ^ tmp[15];
        ciphertext[12] = mul2(tmp[12]   ^ tmp[13]) ^ tmp[12]   ^ t;
        ciphertext[13] = mul2(tmp[13] ^ tmp[14]) ^ tmp[13] ^ t;
        ciphertext[14] = mul2(tmp[14] ^ tmp[15]) ^ tmp[14] ^ t;
        ciphertext[15] = mul2(tmp[15] ^ tmp[12]  ) ^ tmp[15] ^ t;
		
		*(ciphertext+0) ^= *roundkeys++;
		*(ciphertext+1) ^= *roundkeys++;
		*(ciphertext+2) ^= *roundkeys++;
		*(ciphertext+3) ^= *roundkeys++;
		*(ciphertext+4) ^= *roundkeys++;
		*(ciphertext+5) ^= *roundkeys++;
		*(ciphertext+6) ^= *roundkeys++;
		*(ciphertext+7) ^= *roundkeys++;
		*(ciphertext+8) ^= *roundkeys++;
		*(ciphertext+9) ^= *roundkeys++;
		*(ciphertext+10) ^= *roundkeys++;
		*(ciphertext+11) ^= *roundkeys++;
		*(ciphertext+12) ^= *roundkeys++;
		*(ciphertext+13) ^= *roundkeys++;
		*(ciphertext+14) ^= *roundkeys++;
		*(ciphertext+15) ^= *roundkeys++;
		
		*(tmp+0) = SBOX[*(ciphertext+0)];
		*(tmp+1) = SBOX[*(ciphertext+1)];
		*(tmp+2) = SBOX[*(ciphertext+2)];
		*(tmp+3) = SBOX[*(ciphertext+3)];
		*(tmp+4) = SBOX[*(ciphertext+4)];
		*(tmp+5) = SBOX[*(ciphertext+5)];
		*(tmp+6) = SBOX[*(ciphertext+6)];
		*(tmp+7) = SBOX[*(ciphertext+7)];
		*(tmp+8) = SBOX[*(ciphertext+8)];
		*(tmp+9) = SBOX[*(ciphertext+9)];
		*(tmp+10) = SBOX[*(ciphertext+10)];
		*(tmp+11) = SBOX[*(ciphertext+11)];
		*(tmp+12) = SBOX[*(ciphertext+12)];
		*(tmp+13) = SBOX[*(ciphertext+13)];
		*(tmp+14) = SBOX[*(ciphertext+14)];
		*(tmp+15) = SBOX[*(ciphertext+15)];
        shift_rows(tmp);
		
		t = tmp[0] ^ tmp[1] ^ tmp[2] ^ tmp[3];
        ciphertext[0] = mul2(tmp[0]   ^ tmp[1]) ^ tmp[0]   ^ t;
        ciphertext[1] = mul2(tmp[1] ^ tmp[2]) ^ tmp[1] ^ t;
        ciphertext[2] = mul2(tmp[2] ^ tmp[3]) ^ tmp[2] ^ t;
        ciphertext[3] = mul2(tmp[3] ^ tmp[0]  ) ^ tmp[3] ^ t;
			
		t = tmp[4] ^ tmp[5] ^ tmp[6] ^ tmp[7];
        ciphertext[4] = mul2(tmp[4]   ^ tmp[5]) ^ tmp[4]   ^ t;
        ciphertext[5] = mul2(tmp[5] ^ tmp[6]) ^ tmp[5] ^ t;
        ciphertext[6] = mul2(tmp[6] ^ tmp[7]) ^ tmp[6] ^ t;
        ciphertext[7] = mul2(tmp[7] ^ tmp[4]  ) ^ tmp[7] ^ t;
			
		t = tmp[8] ^ tmp[9] ^ tmp[10] ^ tmp[11];
        ciphertext[8]  = mul2(tmp[8]   ^ tmp[9]) ^ tmp[8]   ^ t;
        ciphertext[9]  = mul2(tmp[9] ^ tmp[10]) ^ tmp[9] ^ t;
        ciphertext[10] = mul2(tmp[10] ^ tmp[11]) ^ tmp[10] ^ t;
        ciphertext[11] = mul2(tmp[11] ^ tmp[8]  ) ^ tmp[11] ^ t;
			
		t = tmp[12] ^ tmp[13] ^ tmp[14] ^ tmp[15];
        ciphertext[12] = mul2(tmp[12]   ^ tmp[13]) ^ tmp[12]   ^ t;
        ciphertext[13] = mul2(tmp[13] ^ tmp[14]) ^ tmp[13] ^ t;
        ciphertext[14] = mul2(tmp[14] ^ tmp[15]) ^ tmp[14] ^ t;
        ciphertext[15] = mul2(tmp[15] ^ tmp[12]  ) ^ tmp[15] ^ t;
		
		*(ciphertext+0) ^= *roundkeys++;
		*(ciphertext+1) ^= *roundkeys++;
		*(ciphertext+2) ^= *roundkeys++;
		*(ciphertext+3) ^= *roundkeys++;
		*(ciphertext+4) ^= *roundkeys++;
		*(ciphertext+5) ^= *roundkeys++;
		*(ciphertext+6) ^= *roundkeys++;
		*(ciphertext+7) ^= *roundkeys++;
		*(ciphertext+8) ^= *roundkeys++;
		*(ciphertext+9) ^= *roundkeys++;
		*(ciphertext+10) ^= *roundkeys++;
		*(ciphertext+11) ^= *roundkeys++;
		*(ciphertext+12) ^= *roundkeys++;
		*(ciphertext+13) ^= *roundkeys++;
		*(ciphertext+14) ^= *roundkeys++;
		*(ciphertext+15) ^= *roundkeys++;
		
    
    // last round
    /*
	for (i = AES_BLOCK_SIZE-1; i != 0; --i)
    {
        *(ciphertext+i) = SBOX[*(ciphertext+i)];
    }
	*(ciphertext+i) = SBOX[*(ciphertext+i)];
	*/
	*(ciphertext+0) = SBOX[*(ciphertext+0)];
	*(ciphertext+1) = SBOX[*(ciphertext+1)];
	*(ciphertext+2) = SBOX[*(ciphertext+2)];
	*(ciphertext+3) = SBOX[*(ciphertext+3)];
	*(ciphertext+4) = SBOX[*(ciphertext+4)];
	*(ciphertext+5) = SBOX[*(ciphertext+5)];
	*(ciphertext+6) = SBOX[*(ciphertext+6)];
	*(ciphertext+7) = SBOX[*(ciphertext+7)];
	*(ciphertext+8) = SBOX[*(ciphertext+8)];
	*(ciphertext+9) = SBOX[*(ciphertext+9)];
	*(ciphertext+10) = SBOX[*(ciphertext+10)];
	*(ciphertext+11) = SBOX[*(ciphertext+11)];
	*(ciphertext+12) = SBOX[*(ciphertext+12)];
	*(ciphertext+13) = SBOX[*(ciphertext+13)];
	*(ciphertext+14) = SBOX[*(ciphertext+14)];
	*(ciphertext+15) = SBOX[*(ciphertext+15)];
	
    shift_rows(ciphertext);
    /*
	for ( i = AES_BLOCK_SIZE-1; i != 0; --i )
    {
        *(ciphertext+i) ^= *roundkeys++;
    }
	*(ciphertext+i) ^= *roundkeys++;
	*/
	*(ciphertext+0) ^= *roundkeys++;
	*(ciphertext+1) ^= *roundkeys++;
	*(ciphertext+2) ^= *roundkeys++;
	*(ciphertext+3) ^= *roundkeys++;
	*(ciphertext+4) ^= *roundkeys++;
	*(ciphertext+5) ^= *roundkeys++;
	*(ciphertext+6) ^= *roundkeys++;
	*(ciphertext+7) ^= *roundkeys++;
	*(ciphertext+8) ^= *roundkeys++;
	*(ciphertext+9) ^= *roundkeys++;
	*(ciphertext+10) ^= *roundkeys++;
	*(ciphertext+11) ^= *roundkeys++;
	*(ciphertext+12) ^= *roundkeys++;
	*(ciphertext+13) ^= *roundkeys++;
	*(ciphertext+14) ^= *roundkeys++;
	*(ciphertext+15) ^= *roundkeys++;
}
