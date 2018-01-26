#ifndef _WIFILOG_H_
#define _WIFILOG_H_

#include <sys/types.h>
#include "main.h"
#include "asdwifi.h"

#define MAX_AP_LIST_NUM 256

//һ��Сʱ�ڣ��п���פ�����û�����1024�����ڰ칫�Ҵ�����ԵĽ��
#define MAX_USR_VISIT_NUM 1024

#define MAX_USR_PNL_NUM 1024
#define MAX_USR_HTTP_NUM 64

#define MAX_USR_VID_NUM 256

#define MAX_KICK_LIST_NUM 32

/* ��ָ���û���ָ��ap��kick������ʱ�����ڣ��Է�ֹƵ��kick�û� */
#define KICK_INTERVAL 30  /* ��λ�� */


// aplist�е�list���
struct _ap_list {
    unsigned char ap_bssid[MAC_LEN];   //bssid
    char ap_essid[MAX_ESSID_LEN];      //essid
    unsigned char ap_channel;          //�����ŵ�
    int ap_beacon_count;               //ɨ�赽���ű�֡����
    unsigned char ap_ecypt;            //���ܷ�ʽ
    int sum_signal;
    int sum_snr;
    unsigned int first_time;	//��һ�α�ɨ�赽��ʱ��	
    unsigned int last_time;		//���һ�α�ɨ�赽��ʱ��
};

struct _usr_visitlist {
	unsigned char usr_mac[6];	//�û���MAC��ַ
	unsigned char ap_mac[6];
	int usr_signal;
	unsigned int pk_type;  
	unsigned int src_ip;
	unsigned int dst_ip;
	unsigned int src_port;
	unsigned int dst_port;
	unsigned int times;			//��ɨ�赽�Ĵ���
	unsigned int first_time;	//��һ�α�ɨ�赽��ʱ��	
	unsigned int last_time;		//���һ�α�ɨ�赽��ʱ��
};

struct _usr_pnllist {
	unsigned char usr_mac[6];	//�û���MAC��ַ
	unsigned char ap_mac[6];
	char ap_essid[MAX_ESSID_LEN];      //essid	
	unsigned int times;			//��ɨ�赽�Ĵ���
	unsigned int qry_time;	//��һ�α�ɨ�赽��ʱ��	
};


struct _usr_http {
	unsigned char usr_mac[6];	//�û���MAC��ַ
	char usr_agent[128];
	char usr_host[32];
	char usr_qq[16];
	unsigned int times;			//��ɨ�赽�Ĵ���
	unsigned int usr_http_time;	//��һ�α�ɨ�赽��ʱ��
};

struct _usr_vid_list {
	unsigned char usr_mac[6];	//�û���MAC��ַ
	unsigned int usr_vid_type;
	char usr_vid[64];
	unsigned int times;			//��ɨ�赽�Ĵ���
	unsigned int get_vid_time;	//��һ�α�ɨ�赽��ʱ��
};


struct _kick_list{
	unsigned char usr_mac[6];	//kick_sta_mac
	unsigned int kick_time;			//kick_time
};




void update_wifilog(struct packet_info *p);


void init_mac_list(void);

void visitlog2file(void);  //�����ԣ�һ��Сʱ����Ŀǰ������ն�д��log�ļ������ܱ�ע��
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
