/******************************************************************************
**			TEA�����㷨����Ӣ�����Ŵ�ѧ�����ʵ���������һ�ֶԳƷ�������㷨��
**		��������ɢ�ͻ��ҷ�������64λ���������ݿ飬��128λ��Կ������м��ܣ�����
**		64λ���������ݿ飬��ѭ�������ɸ��ݼ���ǿ����Ҫ�趨��
**			�ļ����ܹ����У��ӷ�����ͼ���������������Ĳ������㷨����ʹ�������
**		��ͼӷ������ṩ���������ԣ�˫��λ����ʹ��Կ�����ݵ����б����ظ��ػ�ϣ�
**		���16��ѭ������ʹ���ݻ���Կ�ĵ������صı仯��չ���ӽ�32���ء���ˣ���ѭ
**		�������ﵽ16������ʱ�����㷨���к�ǿ�Ŀ���ֹ���������128������Կ���ȿ���
**		��������������������㷨������Ƽ��㷨��������Ϊ32�֡�
*****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdint.h>                    //32λ��64λ������ֲ

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
 *  ���ܺ���������Ϊ64bit�����ݣ�����32bit���޷������ͣ���Կ��128bit�����ݣ��ĸ��޷�������
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
