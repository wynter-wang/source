#ifndef _READCFG_H
#define _READCFG_H


extern int device_idx;			/* �豸��ţ����豸Ϊ0/1�����豸Ϊ2,3,4 */
extern int channel;
extern int enable_switch;
extern int switch_interval;
extern int report_interval;
extern char cfg_mac_addr[16];		/* cfg���õ�mac��ַ */
extern char device_id[16];			/* ���õ��豸��� */

extern char wpa_essid[36];                    /* ָ��wpa����AP������ */
extern char wpa_passwd[65];                   /* ָ��wpa����AP������ */

extern char dev_wan_ip[16];

extern int is_pro;

void read_cfg(void);
void read_ispro(void);

#endif /* _WPA_H */