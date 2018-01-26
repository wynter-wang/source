/******************************************************************************
**			TEA加密算法是由英国剑桥大学计算机实验室提出的一种对称分组加密算法。
**		它采用扩散和混乱方法，对64位的明文数据块，用128位密钥分组进行加密，产生
**		64位的密文数据块，其循环轮数可根据加密强度需要设定。
**			文件加密过程中，加法运算和减法运算用作可逆的操作。算法轮流使用异或运
**		算和加法运算提供非线性特性，双移位操作使密钥和数据的所有比特重复地混合，
**		最多16轮循环就能使数据或密钥的单个比特的变化扩展到接近32比特。因此，当循
**		环轮数达到16轮以上时，该算法具有很强的抗差分攻击能力，128比特密钥长度可以
**		抗击穷举搜索攻击，该算法设计者推荐算法迭代次数为32轮。
*****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdint.h>                    //32位和64位兼容移植

const uint32_t TEAKey[4] = { 0xec7620bd, 0xabd10359, 0x23901e58, 0x98f08a4c };
             
             
void tea_encrypt(uint32_t * v, const uint32_t * k);
void tea_decrypt(uint32_t * v, const uint32_t * k);

/* encrypt
 *   Encrypt 64 bits with a 128 bit key using TEA
 *   From http://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm
 * Arguments:
 *   v - array of two 32 bit uints to be encoded in place
 *   k - array of four 32 bit uints to act as key
 * Returns:
 *   v - encrypted result
 * Side effects:
 *   None
 */
/*
 *  加密函数，输入为64bit的数据，两个32bit的无符号整型，密钥是128bit的数据，四个无符号整型
 */
void tea_encrypt(uint32_t * v, const uint32_t * k)
{
    uint32_t v0 = v[0], v1 = v[1], sum = 0, i;  /* set up */

    uint32_t delta = 0x9e3779b9;       /* a key schedule constant */
    uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];    /* cache key */



    for(i = 0; i < 32; i++)
    {                                  /* basic cycle start */
        sum += delta;
        v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
    }                                  /* end cycle */
    
    v[0] = v0;
    v[1] = v1;

}

/* decrypt
 *   Decrypt 64 bits with a 128 bit key using TEA
 *   From http://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm
 * Arguments:
 *   v - array of two 32 bit uints to be decoded in place
 *   k - array of four 32 bit uints to act as key
 * Returns:
 *   v - decrypted result
 * Side effects:
 *   None
 */
void tea_decrypt(uint32_t * v, const uint32_t * k)
{
    uint32_t v0 = v[0], v1 = v[1], sum = 0xC6EF3720, i; /* set up */
    uint32_t delta = 0x9e3779b9;       /* a key schedule constant */
    uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];    /* cache key */
 
    for(i = 0; i < 32; i++)
    {                                  /* basic cycle start */
        v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
        v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        sum -= delta;
    }                                  /* end cycle */
   
    v[0] = v0;
    v[1] = v1;
}
