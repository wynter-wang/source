#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ����uci��(Ϊopenwrt���)������ȡ�����漰�޸ģ����漰commit�ύ */
#include <uci.h>

/* ���ò�����extern��ͷ�ļ�����Ϊȫ�ֱ��� */
int device_idx;                        /* ����lan�ڵ�ַ�ж� */
int channel;
int enable_switch;
int switch_interval;
int report_interval;
char cfg_mac_addr[16];                 /* cfg���õ�mac��ַ */
char device_id[16];                    /* ���õ��豸��� */
char ftp_ip[16];                       /*tcp�ϴ���ַ*/

int is_pro;

char wpa_essid[36];                    /* ָ��wpa����AP������ */
char wpa_passwd[65];                   /* ָ��wpa����AP������ */
char dev_wan_ip[16];

/* ����eth0��mac��ַ�����汾 */
extern unsigned char eth0_mac[6];

//-----------------------------------------------------------------------------
//��ȡ������ӿ�
//-----------------------------------------------------------------------------
static int read_item(char *cfg_path, char *value)
{
    struct uci_ptr ptr;
    struct uci_context *ctx = NULL;
    char path[64];

    /* !!!�ַ����������������⣬��ֵ��������Ȼ��ָ�봫�� */
    /* uci��ӿ���Ƶ�ȱ�� */
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

    /* ��ȡ�����ͻ���ǿ������ */
    memset(value, 0x00, 32);
    ret = read_item("iwmoncfg.bbb.ispro", value);
    if(ret == 1)
    {
        is_pro = atoi(value);
    } else
        is_pro = 0;
}

/* ��ȡiwmon�������� */
void read_cfg(void)
{
    int ret;
    char value[32];

    /* device_idxĬ��ֵΪ0��Ȼ�����network.lan.ipaddr��ȡ 
     * !!!device_idx!!! �ǳ��ؼ�������ȷ��ģ�����/�ӹ���ģʽ
     * ͬ��ȷ����ȡwpa_essid��wpa_pwd��ֵ
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

    /* ��ȡ���õ��豸��� */
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

    /* ��ȡ���õ�mac��ַ */
    memset(cfg_mac_addr, 0x00, 16);

    memset(value, 0x00, 32);
    ret = read_item("iwmoncfg.bbb.mac_addr", value);
    if(ret == 1)
    {
        strcat(cfg_mac_addr, value);
    } else
    {
        //���iwmoncfg�ļ���û�и����������Ӳ��macΪ��
        sprintf(cfg_mac_addr, "%02x%02x%02x%02x%02x%02x", eth0_mac[0], eth0_mac[1], eth0_mac[2],
                eth0_mac[3], eth0_mac[4], eth0_mac[5]);
    }
    printf("cfg_mac_addr = %s\n", cfg_mac_addr);

    /* ��ʼ�ŵ� */
    memset(value, 0x00, 32);
    ret = read_item("iwmoncfg.bbb.channel", value);
    if(ret == 1)
    {
        channel = atoi(value);

/*  Эͬ�л���Ĭ������Ϊ1,6,11����������wpaģʽ��Эͬ�л�ʧЧ
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

    /* �л�ʹ�� */
    memset(value, 0x00, 32);
    ret = read_item("iwmoncfg.bbb.enable_switch", value);
    if(ret == 1)
    {
        enable_switch = atoi(value);
    } else
        enable_switch = 1;
    printf("enable_switch = %d\n", enable_switch);

    /* �л����� */
    memset(value, 0x00, 32);
    ret = read_item("iwmoncfg.bbb.switch_interval", value);
    if(ret == 1)
    {
        switch_interval = atoi(value);
    } else
        switch_interval = 3000;
    printf("switch_interval = %d\n", switch_interval);

    /* �ϱ����� */
    memset(value, 0x00, 32);
    ret = read_item("iwmoncfg.bbb.report_interval", value);
    if(ret == 1)
    {
        report_interval = atoi(value);
    } else
        report_interval = 300;
    printf("report_interval = %d\n", report_interval);
	
	/* ftp��ַ */
	memset(ftp_ip, 0x00, 16);
    memset(value, 0x00, 32);
    ret = read_item("iwmoncfg.bbb.ftp_ip", value);
    if(ret == 1)
    {
        strcat(ftp_ip, value);
    } else
        strcat(ftp_ip, "123.57.175.155");
    printf("ftp_ip = %s\n", ftp_ip);

    /* wan�ڵ�ַ */
    memset(dev_wan_ip, 0x00, 16);
    memset(value, 0x00, 32);
    ret = read_item("network.wan.ipaddr", value);
    if(ret == 1)
    {
        strcat(dev_wan_ip, value);
    }

    printf("dev_wan_ip = %s\n", dev_wan_ip);

//-----------------------------------------------------------------------------
//  ����device_idx��ȡWPA���������
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
