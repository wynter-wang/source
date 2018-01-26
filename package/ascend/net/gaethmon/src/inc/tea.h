#ifndef _TEA_H
#define _TEA_H

#include <stdint.h>


extern const uint32_t TEAKey[4];

void tea_encrypt(uint32_t * v, const uint32_t * k);
void tea_decrypt(uint32_t * v, const uint32_t * k);


#endif