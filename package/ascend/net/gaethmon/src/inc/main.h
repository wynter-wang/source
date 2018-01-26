/*
*/

#ifndef _MAIN_H_
#define _MAIN_H_

#define MAC_LEN 6
#define MAX_ESSID_LEN 32

#define EYPT_WEP		0x01
#define EYPT_WPA		0x02
#define EYPT_WPA2		0x04
#define EYPT_WPS		0x08


extern int DevIdx;

void sys_reboot(void);
int read_item(char *cfg_path, char *value);

#endif
