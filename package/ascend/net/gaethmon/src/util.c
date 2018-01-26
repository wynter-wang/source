/*


*/
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "util.h"
//#include "ieee80211.h"

//int normalize(float oval, int max_val, int max)
//{
//    int val;
//    val = (oval / max_val) * max;
//    if (val > max)              /* cap if still bigger */
//        val = max;
//    if (val == 0 && oval > 0)
//        val = 1;
//    if (val < 0)
//        val = 0;
//    return val;
//}
//
//static inline int normalize_db(int val, int max)
//{
//    if (val <= 30)
//        return 0;
//    else if (val >= 100)
//        return max;
//    else
//        return normalize(val - 30, 70, max);
//}
//

int is_power_of_2(unsigned long n)
{
    return (n != 0 && ((n & (n - 1)) == 0));
}

const char *ether_sprintf(const unsigned char *mac)
{
    static char etherbuf[18];
    snprintf(etherbuf, sizeof(etherbuf), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return etherbuf;
}

const char *ether_sprintf_short(const unsigned char *mac)
{
    static char etherbuf[5];
    snprintf(etherbuf, sizeof(etherbuf), "%02x%02x", mac[4], mac[5]);
    return etherbuf;
}

const char *ip_sprintf(const unsigned int ip)
{
    static char ipbuf[18];
    unsigned char *cip = (unsigned char *)&ip;
    snprintf(ipbuf, sizeof(ipbuf), "%d.%d.%d.%d", cip[0], cip[1], cip[2], cip[3]);
    return ipbuf;
}

const char *ip_sprintf_short(const unsigned int ip)
{
    static char ipbuf[5];
    unsigned char *cip = (unsigned char *)&ip;
    snprintf(ipbuf, sizeof(ipbuf), ".%d", cip[3]);
    return ipbuf;
}

void convert_string_to_mac(const char *string, unsigned char *mac)
{
    int c;
    for(c = 0; c < 6 && string; c++)
    {
        int x = 0;
        if(string)
            sscanf(string, "%x", &x);
        mac[c] = x;
        string = strchr(string, ':');
        if(string)
            string++;
    }
}

const char *kilo_mega_ize(unsigned int val)
{
    static char buf[20];
    char c = 0;
    int rest;
    if(val >= 1024)
    {                                  /* kilo */
        rest = (val & 1023) / 102.4;   /* only one digit */
        val = val >> 10;
        c = 'k';
    }
    if(val >= 1024)
    {                                  /* mega */
        rest = (val & 1023) / 102.4;   /* only one digit */
        val = val >> 10;
        c = 'M';
    }
    if(c)
        snprintf(buf, sizeof(buf), "%d.%d%c", val, rest, c);
    else
        snprintf(buf, sizeof(buf), "%d", val);
    return buf;
}

/* simple ilog2 implementation */
int ilog2(int x)
{
    int n;
    for(n = 0; !(x & 1); n++)
        x = x >> 1;
    return n;
}

int is_digital_str(char *instr)
{
    int ret;

    ret = 1;

    while (*(instr) != 0x00)
    {
        //printf("%c[%d]\n", *instr, *instr);
        if(!isdigit(*instr))
        {
            ret = 0;
            break;
        }

        instr++;
    }

    return ret;
}
