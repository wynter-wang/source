#ifndef _READCFG_H
#define _READCFG_H


extern int device_idx;			/* 设备编号，主设备为0/1，从设备为2,3,4 */
extern int channel;
extern int enable_switch;
extern int switch_interval;
extern int report_interval;
extern char cfg_mac_addr[16];		/* cfg配置的mac地址 */
extern char device_id[16];			/* 配置的设备编号 */

extern char wpa_essid[36];                    /* 指定wpa加密AP的名称 */
extern char wpa_passwd[65];                   /* 指定wpa加密AP的密码 */

extern char dev_wan_ip[16];

extern int is_pro;

void read_cfg(void);
void read_ispro(void);

#endif /* _WPA_H */