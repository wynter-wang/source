#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdio.h>
#include <endian.h>                    //大端小端
#include <byteswap.h>                  //字节置换

/*
#if BYTE_ORDER == LITTLE_ENDIAN
#define le64toh(x) (x)
#define le32toh(x) (x)
#define le16toh(x) (x)
#define htole64(x) (x)
#define htole32(x) (x)
#define htole16(x) (x)
#else
#define le64toh(x) bswap_64(x)
#define le32toh(x) bswap_32(x)
#define le16toh(x) bswap_16(x)
#define htole64(x) bswap_64(x)
#define htole32(x) bswap_32(x)
#define htole16(x) bswap_16(x)
#endif
*/

 

const char *ether_sprintf(const unsigned char *mac);

const char *ether_sprintf_short(const unsigned char *mac);

const char *ip_sprintf(const unsigned int ip);

const char *ip_sprintf_short(const unsigned int ip);

void convert_string_to_mac(const char *string, unsigned char *mac);

//int normalize(float val, int max_val, int max);
//static inline int normalize_db(int val, int max);

char get_packet_type_char(int type);

const char *get_packet_type_name(int type);

const char *kilo_mega_ize(unsigned int val);

#define MAC_NOT_EMPTY(_mac) (_mac[0] || _mac[1] || _mac[2] || _mac[3] || _mac[4] || _mac[5])
#define MAC_EMPTY(_mac) (!_mac[0] && !_mac[1] && !_mac[2] && !_mac[3] && !_mac[4] && !_mac[5])

#define MAC_EQUAL(_mac1,_mac2) ((_mac1[0]==_mac2[0])&&\
  (_mac1[1]==_mac2[1])&&(_mac1[2]==_mac2[2])&&\
  (_mac1[3]==_mac2[3])&&(_mac1[4]==_mac2[4])&&(_mac1[5]==_mac2[5]))

//判断扫描得到的mac地址为单播，非组播或者是广播
#define MAC_IS_UNICAST(_mac) (!(_mac[0] & 0x01))

#define TOGGLE_BIT(_x, _m) (_x) ^= (_m)

#define max(_x, _y) ((_x) > (_y) ? (_x) : (_y))
#define min(_x, _y) ((_x) < (_y) ? (_x) : (_y))

#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))

//static inline __attribute__((const))

int is_power_of_2(unsigned long n);

int ilog2(int x);

int is_digital_str(char *instr);


#endif
