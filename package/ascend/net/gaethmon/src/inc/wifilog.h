#ifndef _WIFILOG_H_
#define _WIFILOG_H_

#include <sys/types.h>
#include "main.h"
#include "asdwifi.h"

#define MAX_AP_LIST_NUM 256

//一个小时内，有可能驻留的用户超过1024，仅在办公室窗外测试的结果
#define MAX_USR_VISIT_NUM 1024

#define MAX_USR_PNL_NUM 1024
#define MAX_USR_HTTP_NUM 64

#define MAX_USR_VID_NUM 256

#define MAX_KICK_LIST_NUM 32

/* 将指定用户从指定ap上kick下来的时间周期，以防止频繁kick用户 */
#define KICK_INTERVAL 30  /* 单位秒 */


// aplist中的list项定义
struct _ap_list {
    unsigned char ap_bssid[MAC_LEN];   //bssid
    char ap_essid[MAX_ESSID_LEN];      //essid
    unsigned char ap_channel;          //工作信道
    int ap_beacon_count;               //扫描到的信标帧次数
    unsigned char ap_ecypt;            //加密方式
    int sum_signal;
    int sum_snr;
    unsigned int first_time;	//第一次被扫描到的时间	
    unsigned int last_time;		//最后一次被扫描到的时间
};

struct _usr_visitlist {
	unsigned char usr_mac[6];	//用户的MAC地址
	unsigned char ap_mac[6];
	int usr_signal;
	unsigned int pk_type;  
	unsigned int src_ip;
	unsigned int dst_ip;
	unsigned int src_port;
	unsigned int dst_port;
	unsigned int times;			//被扫描到的次数
	unsigned int first_time;	//第一次被扫描到的时间	
	unsigned int last_time;		//最后一次被扫描到的时间
};

struct _usr_pnllist {
	unsigned char usr_mac[6];	//用户的MAC地址
	unsigned char ap_mac[6];
	char ap_essid[MAX_ESSID_LEN];      //essid	
	unsigned int times;			//被扫描到的次数
	unsigned int qry_time;	//第一次被扫描到的时间	
};


struct _usr_http {
	unsigned char usr_mac[6];	//用户的MAC地址
	char usr_agent[128];
	char usr_host[32];
	char usr_qq[16];
	unsigned int times;			//被扫描到的次数
	unsigned int usr_http_time;	//第一次被扫描到的时间
};

struct _usr_vid_list {
	unsigned char usr_mac[6];	//用户的MAC地址
	unsigned int usr_vid_type;
	char usr_vid[64];
	unsigned int times;			//被扫描到的次数
	unsigned int get_vid_time;	//第一次被扫描到的时间
};


struct _kick_list{
	unsigned char usr_mac[6];	//kick_sta_mac
	unsigned int kick_time;			//kick_time
};




void update_wifilog(struct packet_info *p);


void init_mac_list(void);

void visitlog2file(void);  //周期性（一个小时）将目前不活动的终端写入log文件，功能被注释
void print_visitlist(void);
void fprint_logfile(char *mac_addr, char *logfilename);

//for debug
void test_sort_time(void);

void init_ap_list(void);
void fprint_aplfile(char *mac_addr, char *logfilename);
void get_wpa_bssid(char * wpa_essid);

void init_pnl_list(void);
void print_pnllist(void);
void fprint_pnlfile(char *mac_addr, char *logfilename);

void init_agl_list(void);
int update_agent_list(unsigned char* new_usr_mac, char* new_usr_http_agent, char * new_usr_http_host);
void print_usrhttplist(void);
void fprint_aglfile(char *mac_addr, char *logfilename);

void init_kick_list(void);
void kick_sta(unsigned char *ap_mac, unsigned char *sta_mac);

void init_vid_list(void);
int update_vid_list(unsigned char *new_usr_mac, char *new_usr_vid, unsigned int new_usr_vid_type);
void snd_vidfile(void);


int update_mac_list(unsigned char *new_usr_mac, unsigned char *new_usr_apmac, int new_usr_signal,
                unsigned int new_usr_pktype, unsigned int src_ip, unsigned int dst_ip,
                unsigned int src_port, unsigned int dst_port);

int update_pnl_list(unsigned char *new_usr_mac, unsigned char *new_qry_apmac, char *new_qry_apname);

void update_ap_list(unsigned char *new_ap_bssid, char *new_ap_essid, unsigned int new_ap_signal,
	unsigned int new_ap_snr, unsigned char new_ap_channel, unsigned char new_ap_ecypt);



#endif
