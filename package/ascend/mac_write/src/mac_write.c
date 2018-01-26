/*
   
用法
write_wtp_mac 001f6f0f0a01
其中
/dev/mtdblock5 不能改，必须是这个值
001f6f0f0a01 是12位的MAC地址，可以改。


*/

/*################################ include ###################################*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

/*################################# MACRO ####################################*/

#define MAX_FILE_BUF_LEN 0x10000
#define MAX_READ_BUF_LEN 0x400
#define MAC_LOCAL_OPENWRT 0x100


#define MTDBLOCK5 "/dev/mtdblock5"

typedef struct boardconfig {
    unsigned char mac[6];              // 6位MAC Address
} BOARDCONFIG;
/*########################### Globle variable ################################*/

int readFile(const char *_fileName, unsigned char *_buf, int _bufLen)
{
    FILE *fp = NULL;
    unsigned long n_file_len = 0;

    if(!_buf || _bufLen <= 0)
    {
        printf("%s param error\n", __func__);
        return (-1);
    }

    fp = fopen(_fileName, "rb");       // 必须确保是以 二进制读取的形式打开 

    if(!fp)
    {
        printf("%s handler error\n", __func__);
        return (-1);
    }
    while (n_file_len < MAX_FILE_BUF_LEN)
    {
        fread((void *)&_buf[n_file_len], _bufLen, 1, fp);   // 二进制读
        n_file_len += _bufLen;
    }

    fclose(fp);
    return 0;
}

int writeFile(const char *_fileName, unsigned char *_buf, int _bufLen)
{
    FILE *fp = NULL;
    unsigned long n_file_len = 0;
    if(!_buf || _bufLen <= 0)
    {
        printf("%s param error\n", __func__);
        return (-1);
    }

    fp = fopen(_fileName, "wb");       // 必须确保是以 二进制写入的形式打开

    if(!fp)
    {
        printf("%s handler error\n", __func__);
        return (-1);
    }

    while (n_file_len < MAX_FILE_BUF_LEN)
    {
        fwrite((void *)&_buf[n_file_len], _bufLen, 1, fp);  //二进制写
        n_file_len += _bufLen;
    }

    fclose(fp);
    fp = NULL;

    return 0;
}

unsigned char ascii_to_bin(char *pmac)
{
    unsigned char tmp1 = 0, tmp2 = 0;
    if(!pmac)
        return 0;
    if(*pmac >= 'A' && *pmac <= 'F')
    {
        tmp1 = *pmac - 'A' + 10;
    } else if(*pmac >= 'a' && *pmac <= 'f')
    {
        tmp1 = *pmac - 'a' + 10;
    } else if(*pmac >= '0' && *pmac <= '9')
    {
        tmp1 = *pmac - '0';
    }
    pmac++;
    if(*pmac >= 'A' && *pmac <= 'F')
    {
        tmp2 = *pmac - 'A' + 10;
    } else if(*pmac >= 'a' && *pmac <= 'f')
    {
        tmp2 = *pmac - 'a' + 10;
    } else if(*pmac >= '0' && *pmac <= '9')
    {
        tmp2 = *pmac - '0';
    }

    return (((tmp1 << 4) & 0xF0) | tmp2);
}

int main(int argc, char *argv[])
{
    unsigned char m_acBuf[MAX_FILE_BUF_LEN + 4] = { 0x0 };
    char s_mac[18] = {0x0}, s_cmd[128] = {0x0};
    
    int n_macaddr_len = 0, i = 0, j = 0;
    unsigned char mac_addr_val[6] = { 0x0, 0x1F, 0x6F, 0x01, 0xA0, 0x55 };
    

    if(argc != 2)
    {
        printf("Usage:%s cal_data_sector_name macaddress\n\t %s /dev/mtdblock4 0015EBBA0201\n",
               argv[0], argv[1]);
        return -1;
    }
    
    n_macaddr_len = strlen(argv[1]);
    if(n_macaddr_len != 12 && (n_macaddr_len != 17))
    {
        printf("\n!Macaddress Error\n");
        return -1;
    }
    strcpy(s_mac, argv[1]);
    j = 0;
    i = 0;
    if(12 == n_macaddr_len)
    {
        while (i < 12)
        {
            mac_addr_val[j] = ascii_to_bin((char *)&s_mac[i]);
            j++;
            i += 2;
        }
    } 
	else
    {
        while (i < 17)
        {
            mac_addr_val[j] = ascii_to_bin((char *)&s_mac[i]);
            j++;
            i += 3;
        }
    }

    if(readFile(MTDBLOCK5, m_acBuf, MAX_READ_BUF_LEN))
    {
        printf("\n!Error 1\n");
        return -1;
    }

    //eth0 
    memcpy(m_acBuf, mac_addr_val, 6);
    
	//eth1
	mac_addr_val[5] += 1;
    if(mac_addr_val[5] < 1)
    {
       /*有进位 */
       mac_addr_val[4] += 1;
       if(mac_addr_val[4] < 1)
       {
           /*有进位 */
           mac_addr_val[3] += 1;
       }
    }
    memcpy((void *)&m_acBuf[6], mac_addr_val, 6);

	//wlan0
	mac_addr_val[5] += 1;
	if(mac_addr_val[5] < 1)
	{
		mac_addr_val[4] += 1;
		if(mac_addr_val[4] < 1)
		{
			mac_addr_val[3] += 1;
		}
	}
	memcpy((void*)&m_acBuf[4098], mac_addr_val, 6);
	
    
    if(writeFile("/tmp/new_mac_data", m_acBuf, MAX_READ_BUF_LEN))
    {
        printf("\n!Error 2\n");
        return -1;
    }
    if(argc = 2)
    {
        snprintf(s_cmd, sizeof(s_cmd) - 1, "cat /tmp/new_mac_data > %s", MTDBLOCK5);
        printf("%s\n", s_cmd);
        system(s_cmd);
    }

    printf("\n!!!Write Mac Success!!!\n");
	
	sleep(2);
	system("reboot");
    return 0;
}
