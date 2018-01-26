#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 引用uci库(为openwrt类库)，仅读取，不涉及修改，不涉及commit提交 */
#include <uci.h>

/* 配置参数，extern在头文件，作为全局变量 */
int device_idx;                        /* 根据lan口地址判断 */
int channel;
int enable_switch;
int switch_interval;
int report_interval;
char cfg_mac_addr[16];                 /* cfg配置的mac地址 */
char device_id[16];                    /* 配置的设备编号 */
char ftp_ip[16];                       /*tcp上传地址*/

int is_pro;

char wpa_essid[36];                    /* 指定wpa加密AP的名称 */
char wpa_passwd[65];                   /* 指定wpa加密AP的密码 */
char dev_wan_ip[16];

/* 根据eth0的mac地址包含版本 */
extern unsigned char eth0_mac[6];

//-----------------------------------------------------------------------------
//读取配置项接口
//-----------------------------------------------------------------------------
static int read_item(char *cfg_path, char *value)
{
    struct uci_ptr ptr;
    struct uci_context *ctx = NULL;
    char path[64];

    /* !!!字符串常量传入有问题，赋值给变量，然后指针传入 */
    /* uci库接口设计的缺陷 */
    memset(path, 0x00, 64);
    strcat(path, cfg_path);

    ctx = uci_alloc_context();

    if(!ctx)
        return 0;

    if((uci_lookup_ptr(ctx, &ptr, path, true) != UCI_OK) ||
       (ptr.o == NULL || ptr.o->v.string == NULL))
    {
        //fprintf(stderr, "read_item_error: %s\n", path);
        uci_free_context(ctx);
        return 0;
    }

    if(ptr.flags & UCI_LOOKUP_COMPLETE)
        strcpy(value, ptr.o->v.string);

    uci_free_context(ctx);

    return 1;
}

void read_ispro(void)
{
    int ret;
    char value[32];

    /* 读取基本型或增强型配置 */
    memset(value, 0x00, 32);
    ret = read_item("iwmoncfg.bbb.ispro", value);
    if(ret == 1)
    {
        is_pro = atoi(value);
    } else
        is_pro = 0;
}

/* 读取iwmon的配置项 */
void read_cfg(void)
{
    int ret;
    char value[32];

    /* device_idx默认值为0，然后根据network.lan.ipaddr读取 
     * !!!device_idx!!! 非常关键，用来确定模块的主/从工作模式
     * 同事确定读取wpa_essid和wpa_pwd的值
     */

    device_idx = 0;
    memset(value, 0x00, 32);
    read_item("network.lan.ipaddr", value);
    printf("ipaddr = %s\n", value);

    if((strcmp(value, "192.168.111.11") == 0) || (strcmp(value, "192.168.1.1") == 0))
    {
        device_idx = 1;
    } else if((strcmp(value, "192.168.111.22") == 0) || (strcmp(value, "192.168.1.2") == 0))
    {
        device_idx = 2;
    } else if((strcmp(value, "192.168.111.33") == 0) || (strcmp(value, "192.168.1.3") == 0))
    {
        device_idx = 3;
    } else if((strcmp(value, "192.168.111.44") == 0) || (strcmp(value, "192.168.1.4") == 0))
    {
        device_idx = 4;
    } else if(strcmp(value, "192.168.222.11") == 0)
    {
        device_idx = 4;
    } else if(strcmp(value, "192.168.222.22") == 0)
    {
        device_idx = 5;
    } else if(strcmp(value, "192.168.222.33") == 0)
    {
        device_idx = 6;
    }

    printf("*********************\n");
    printf("device_idx = %d\n", device_idx);
    printf("*********************\n");

    /* 读取配置的设备编号 */
    memset(device_id, 0x00, 16);

    memset(value, 0x00, 32);
    ret = read_item("iwmoncfg.bbb.device_id", value);
    if(ret == 1)
    {
        strcat(device_id, value);
    } else
    {
        strcpy(device_id, "ASD00001");
    }
    printf("device_id = %s\n", device_id);

    /* 读取配置的mac地址 */
    memset(cfg_mac_addr, 0x00, 16);

    memset(value, 0x00, 32);
    ret = read_item("iwmoncfg.bbb.mac_addr", value);
    if(ret == 1)
    {
        strcat(cfg_mac_addr, value);
    } else
    {
        //如果iwmoncfg文件内没有该配置项，则以硬件mac为主
        sprintf(cfg_mac_addr, "%02x%02x%02x%02x%02x%02x", eth0_mac[0], eth0_mac[1], eth0_mac[2],
                eth0_mac[3], eth0_mac[4], eth0_mac[5]);
    }
    printf("cfg_mac_addr = %s\n", cfg_mac_addr);

    /* 初始信道 */
    memset(value, 0x00, 32);
    ret = read_item("iwmoncfg.bbb.channel", value);
    if(ret == 1)
    {
        channel = atoi(value);

/*  协同切换，默认配置为1,6,11，避免设置wpa模式后，协同切换失效
        if(device_idx == 1)
        	channel = 1;
        if(device_idx == 2)
        	channel = 6;
        if(device_idx == 3)
        	channel = 11;
*/

    } else
        channel = 1;
    printf("channel = %d\n", channel);

    /* 切换使能 */
    memset(value, 0x00, 32);
    ret = read_item("iwmoncfg.bbb.enable_switch", value);
    if(ret == 1)
    {
        enable_switch = atoi(value);
    } else
        enable_switch = 1;
    printf("enable_switch = %d\n", enable_switch);

    /* 切换周期 */
    memset(value, 0x00, 32);
    ret = read_item("iwmoncfg.bbb.switch_interval", value);
    if(ret == 1)
    {
        switch_interval = atoi(value);
    } else
        switch_interval = 3000;
    printf("switch_interval = %d\n", switch_interval);

    /* 上报周期 */
    memset(value, 0x00, 32);
    ret = read_item("iwmoncfg.bbb.report_interval", value);
    if(ret == 1)
    {
        report_interval = atoi(value);
    } else
        report_interval = 300;
    printf("report_interval = %d\n", report_interval);
	
	/* ftp地址 */
	memset(ftp_ip, 0x00, 16);
    memset(value, 0x00, 32);
    ret = read_item("iwmoncfg.bbb.ftp_ip", value);
    if(ret == 1)
    {
        strcat(ftp_ip, value);
    } else
        strcat(ftp_ip, "123.57.175.155");
    printf("ftp_ip = %s\n", ftp_ip);

    /* wan口地址 */
    memset(dev_wan_ip, 0x00, 16);
    memset(value, 0x00, 32);
    ret = read_item("network.wan.ipaddr", value);
    if(ret == 1)
    {
        strcat(dev_wan_ip, value);
    }

    printf("dev_wan_ip = %s\n", dev_wan_ip);

//-----------------------------------------------------------------------------
//  根据device_idx读取WPA的相关配置
//-----------------------------------------------------------------------------
    memset(wpa_essid, 0, sizeof(wpa_essid));
    memset(wpa_passwd, 0, sizeof(wpa_passwd));

    if((device_idx == 1) || (device_idx == 0))
    {
        memset(value, 0x00, 32);
        ret = read_item("iwmoncfg.bbb.wpa_essid", value);
        if(ret == 1)
        {
            printf("wpa_essid = %s\n", value);
            strncpy(wpa_essid, value, sizeof(wpa_essid) - 1);
        }

        memset(value, 0x00, 32);
        ret = read_item("iwmoncfg.bbb.wpa_passwd", value);
        if(ret == 1)
        {
            printf("wpa_passwd = %s\n", value);
            strncpy(wpa_passwd, value, sizeof(wpa_passwd) - 1);
        }

        printf("wpa_essid:wpa_passwd = %s:%s\n", wpa_essid, wpa_passwd);
    } else if(device_idx == 2)
    {
        memset(value, 0x00, 32);
        ret = read_item("iwmoncfg.bbb.wpa_essid2", value);
        if(ret == 1)
        {
            printf("wpa_essid2 = %s\n", value);
            strncpy(wpa_essid, value, sizeof(wpa_essid) - 1);
        }

        memset(value, 0x00, 32);
        ret = read_item("iwmoncfg.bbb.wpa_passwd2", value);
        if(ret == 1)
        {
            printf("wpa_passwd2 = %s\n", value);
            strncpy(wpa_passwd, value, sizeof(wpa_passwd) - 1);
        }

        printf("wpa_essid:wpa_passwd = %s:%s\n", wpa_essid, wpa_passwd);
    } else if(device_idx == 3)
    {
        memset(value, 0x00, 32);
        ret = read_item("iwmoncfg.bbb.wpa_essid3", value);
        if(ret == 1)
        {
            printf("wpa_essid3 = %s\n", value);
            strncpy(wpa_essid, value, sizeof(wpa_essid) - 1);
        }

        memset(value, 0x00, 32);
        ret = read_item("iwmoncfg.bbb.wpa_passwd3", value);
        if(ret == 1)
        {
            printf("wpa_passwd3 = %s\n", value);
            strncpy(wpa_passwd, value, sizeof(wpa_passwd) - 1);
        }

        printf("wpa_essid:wpa_passwd = %s:%s\n", wpa_essid, wpa_passwd);
    } else if(device_idx == 4)
    {
        memset(value, 0x00, 32);
        ret = read_item("iwmoncfg.bbb.wpa_essid4", value);
        if(ret == 1)
        {
            printf("wpa_essid4 = %s\n", value);
            strncpy(wpa_essid, value, sizeof(wpa_essid) - 1);
        }

        memset(value, 0x00, 32);
        ret = read_item("iwmoncfg.bbb.wpa_passwd4", value);
        if(ret == 1)
        {
            printf("wpa_passwd4 = %s\n", value);
            strncpy(wpa_passwd, value, sizeof(wpa_passwd) - 1);
        }

        printf("wpa_essid:wpa_passwd = %s:%s\n", wpa_essid, wpa_passwd);
    }
}
