/*
	帧解析后的数据记录与统计模块

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <err.h>
#include <sys/time.h>

#include "wifilog.h"
//#include "ieee80211.h"
#include "util.h"
#include "main.h"
#include "asdwifi.h"
#include "readcfg.h"
#include "net.h"
extern char cfg_mac_addr[16];                 /* cfg配置的mac地址 */
extern char device_id[16];                    /* 配置的设备编号 */
extern char ftp_ip[16]; 
extern int cli_nodify_fd;
const unsigned char NULL_MAC[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
const unsigned char FFFF_MAC[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

/* get_wpa_bssid() */
extern unsigned char wpa_bssid[6];     /* 指定wpa的AP的MAC：从信令帧里获取（根据配置的essid查询获得） */
extern unsigned char wpa_channel;      /* 指定wap的AP的工作信道，解密时需要锁定该信道不切换 */

/* 当前扫描到的记录，即时更新，并定期移除已成事实的访问记录，保持到文件
   MAX_USR_VISIT_NUM 暂时定为1024，该数值与排序时间有关 */
struct _usr_visitlist visitlist[MAX_USR_VISIT_NUM];

//当前列表的最大更新位置，在加入和移除是需要及时更新
unsigned int cur_pos;

/* 以下队列通过依次遍历查找 */
struct _ap_list aplist[MAX_AP_LIST_NUM];
struct _usr_pnllist pnl_list[MAX_USR_PNL_NUM];
struct _usr_http usr_http_list[MAX_USR_HTTP_NUM];
struct _usr_vid_list usr_vid_list[MAX_USR_VID_NUM];

#ifdef _KICK
struct _kick_list kick_list[MAX_KICK_LIST_NUM];
#endif

/*
[0000]  ASOCRQ	30
[0004]  UNKNOW	1
[0008]    DATA	7230
[000c]  UNKNOW	1
[0010]  ASOCRP	40
[0014]  UNKNOW	1
[0018]  DCFACK	2
[001c]  UNKNOW	2
[0020]  REASRQ	2
[0028]  DCFPLL	2
[0030]  REASRP	15
[0038]  DCFKPL	3
[003c]  UNKNOW	1
[0040]  PROBRQ	7316
[0044]  UNKNOW	3
[0048]    NULL	10390
[004c]  UNKNOW	1
[0050]  PROBRP	15550
[0058]   CFACK	1
[005c]  UNKNOW	1
[0060]  UNKNOW	3
[0064]  UNKNOW	1
[0068]  CFPOLL	2
[006c]  UNKNOW	1
[0070]  UNKNOW	1
[0074]  UNKNOW	1
[0080]  BEACON	51680
[0084]  UNKNOW	464
[0088]   QDATA	27620
[008c]  UNKNOW	1
[0090]    ATIM	3
[0094]  UNKNOW	7899
[0098]  QDCFCK	1
[00a0]  DISASC	22
[00a4]  PSPOLL	521
[00a8]  QDCFPL	7
[00b0]    AUTH	162
[00b4]     RTS	12347
[00b8]  QDCFKP	3
[00bc]  UNKNOW	2
[00c0]  DEAUTH	53
[00c4]     CTS	11866
[00c8]  QDNULL	225
[00cc]  UNKNOW	2
[00d0]  ACTION	254
[00d4]     ACK	34532
[00d8]  QCFACK	1
[00e4]   CFEND	26
[00f4]  CFENDK	1
[00f8]  QCFKPL	3
[00fc]  UNKNOW	1
*/
//-----------------------------------------------------------------------------
// 打印扫描到的ap列表
// 根据信号强度分析用户位置，信号强度分两个方向，从AP发出的可推测与AP的距离，暂时不用
// 重点记录终端发出的信号，暂时仅统计PROBRQ，和数据帧中wlan_mode == WLAN_MODE_STA的信号
// 其他情况，信号强度设置为0，不纳入统计
//-----------------------------------------------------------------------------
void update_wifilog(struct packet_info *p)
{
    //switch (p->wlan_type & IEEE80211_FCTL_FTYPE)
    //{
    //case IEEE80211_FTYPE_MGMT:        /* 0x0000 管理帧 */
    //    switch (p->wlan_type & IEEE80211_FCTL_STYPE)
    //    {
    //    case IEEE80211_STYPE_ASSOC_REQ:
    //        update_mac_list(p->wlan_src, p->wlan_bssid, p->phy_signal, p->wlan_type, p->ip_src,
    //                        p->ip_dst, p->port_src, p->port_dst);
    //        break;
    //    case IEEE80211_STYPE_ASSOC_RESP:
    //        update_mac_list(p->wlan_dst, p->wlan_bssid, 0, p->wlan_type, p->ip_src, p->ip_dst,
    //                        p->port_src, p->port_dst);
    //        break;
    //    case IEEE80211_STYPE_REASSOC_REQ:
    //        update_mac_list(p->wlan_src, p->wlan_bssid, p->phy_signal, p->wlan_type, p->ip_src,
    //                        p->ip_dst, p->port_src, p->port_dst);
    //        break;
    //    case IEEE80211_STYPE_REASSOC_RESP:
    //        update_mac_list(p->wlan_dst, p->wlan_bssid, 0, p->wlan_type, p->ip_src, p->ip_dst,
    //                        p->port_src, p->port_dst);
    //        break;
    //    case IEEE80211_STYPE_PROBE_REQ:

    //        update_mac_list(p->wlan_src, p->wlan_bssid, p->phy_signal, p->wlan_type, p->ip_src,
    //                        p->ip_dst, p->port_src, p->port_dst);

    //        if(p->wlan_essid[0] != 0x00)
    //            update_pnl_list(p->wlan_src, p->wlan_bssid, p->wlan_essid);

    //        break;
    //    case IEEE80211_STYPE_PROBE_RESP:
    //        update_mac_list(p->wlan_dst, p->wlan_bssid, 0, p->wlan_type, p->ip_src, p->ip_dst,
    //                        p->port_src, p->port_dst);

    //        break;
    //    case IEEE80211_STYPE_BEACON:

    //        if(p->wlan_channel != 0)
    //            update_ap_list(p->wlan_bssid, p->wlan_essid, p->phy_signal, p->phy_snr,
    //                           p->wlan_channel, p->ap_ecypt);
    //        break;
    //    case IEEE80211_STYPE_ATIM:
    //        break;
    //    case IEEE80211_STYPE_DISASSOC:
    //        break;
    //    case IEEE80211_STYPE_AUTH:
    //        break;
    //    case IEEE80211_STYPE_DEAUTH:
    //        break;
    //    case IEEE80211_STYPE_ACTION:
    //        break;
    //    }
    //    break;

    //case IEEE80211_FTYPE_CTL:         /* 0x0004 控制帧 */
    //    switch (p->wlan_type & IEEE80211_FCTL_STYPE)
    //    {
    //    case IEEE80211_STYPE_CTL_EXT:
    //        break;
    //    case IEEE80211_STYPE_BACK_REQ:
    //        break;
    //    case IEEE80211_STYPE_BLOCKACK:
    //        break;
    //    case IEEE80211_STYPE_PSPOLL:

    //        update_mac_list(p->wlan_src, p->wlan_bssid, p->phy_signal, p->wlan_type, p->ip_src,
    //                        p->ip_dst, p->port_src, p->port_dst);

    //        break;
    //    case IEEE80211_STYPE_RTS:
    //        break;
    //    case IEEE80211_STYPE_CTS:
    //        break;
    //    case IEEE80211_STYPE_ACK:
    //        break;
    //    case IEEE80211_STYPE_CFEND:
    //        break;
    //    case IEEE80211_STYPE_CFENDACK:
    //        break;
    //    }
    //    break;

    //case IEEE80211_FTYPE_DATA:        /* 0x0008 数据帧 */
    //    //根据子类解析
    //    switch (p->wlan_type & IEEE80211_FCTL_STYPE)
    //    {
    //    case IEEE80211_STYPE_DATA:
    //        if(p->wlan_mode == WLAN_MODE_AP)
    //        {                          //过滤广播和组播
    //            if(MAC_IS_UNICAST(p->wlan_dst))
    //                update_mac_list(p->wlan_dst, p->wlan_bssid, 0, p->wlan_type, p->ip_src,
    //                                p->ip_dst, p->port_src, p->port_dst);
    //        } else if(p->wlan_mode == WLAN_MODE_STA)
    //        {                          //过滤广播和组播
    //            if(MAC_IS_UNICAST(p->wlan_src))
    //                update_mac_list(p->wlan_src, p->wlan_bssid, p->phy_signal, p->wlan_type,
    //                                p->ip_src, p->ip_dst, p->port_src, p->port_dst);
    //        }
    //        break;
    //    case IEEE80211_STYPE_DATA_CFACK:
    //        break;
    //    case IEEE80211_STYPE_DATA_CFPOLL:
    //        break;
    //    case IEEE80211_STYPE_DATA_CFACKPOLL:
    //        break;
    //    case IEEE80211_STYPE_NULLFUNC:

    //        /* NULL  始终24个字节，不存在组播和广播的情况 */
    //        if(p->wlan_mode == WLAN_MODE_AP)
    //        {                          //过滤广播和组播
    //            if(MAC_IS_UNICAST(p->wlan_dst))
    //                update_mac_list(p->wlan_dst, p->wlan_bssid, 0, p->wlan_type, p->ip_src,
    //                                p->ip_dst, p->port_src, p->port_dst);
    //        } else if(p->wlan_mode == WLAN_MODE_STA)
    //        {                          //过滤广播和组播
    //            if(MAC_IS_UNICAST(p->wlan_src))
    //                update_mac_list(p->wlan_src, p->wlan_bssid, p->phy_signal, p->wlan_type,
    //                                p->ip_src, p->ip_dst, p->port_src, p->port_dst);
    //        }

    //        break;
    //    case IEEE80211_STYPE_CFACK:
    //        break;
    //    case IEEE80211_STYPE_CFPOLL:
    //        break;
    //    case IEEE80211_STYPE_CFACKPOLL:
    //        break;
    //    case IEEE80211_STYPE_QOS_DATA:

    //        if(p->wlan_mode == WLAN_MODE_AP)
    //        {                          //过滤广播和组播
    //            if(MAC_IS_UNICAST(p->wlan_dst))
    //                update_mac_list(p->wlan_dst, p->wlan_bssid, 0, p->wlan_type, p->ip_src,
    //                                p->ip_dst, p->port_src, p->port_dst);
    //        } else if(p->wlan_mode == WLAN_MODE_STA)
    //        {                          //过滤广播和组播
    //            if(MAC_IS_UNICAST(p->wlan_src))
    //                update_mac_list(p->wlan_src, p->wlan_bssid, p->phy_signal, p->wlan_type,
    //                                p->ip_src, p->ip_dst, p->port_src, p->port_dst);
    //        }

    //        break;
    //    case IEEE80211_STYPE_QOS_DATA_CFACK:
    //        break;
    //    case IEEE80211_STYPE_QOS_DATA_CFPOLL:
    //        break;
    //    case IEEE80211_STYPE_QOS_DATA_CFACKPOLL:
    //        break;
    //    case IEEE80211_STYPE_QOS_NULLFUNC:
    //        break;
    //    case IEEE80211_STYPE_QOS_CFACK:
    //        break;
    //    case IEEE80211_STYPE_QOS_CFPOLL:
    //        break;
    //    case IEEE80211_STYPE_QOS_CFACKPOLL:
    //        break;

    //    }
    //    break;

    //default:
    //    break;
    //}
}

//---------------------------------------------------------
//初始化记录模块
//---------------------------------------------------------
void init_mac_list(void)
{
    //初始化记录
    cur_pos = 0;
    memset(&visitlist, 0, sizeof(visitlist));
}

/*
	排序插入
	通过二分法查找当前MAC是否已经在列表里
	如果找到，返回对应的位置，如果没找到则插入
*/

//---------------------------------------------------------
// 打印队列
//---------------------------------------------------------
void print_visitlist(void)
{
    struct tm *local;
    time_t t;
    int diff_time;

    int i, j;
    int all;
    all = 0;

    printf("----------------------------------------------------------------------\n");
    printf(" *User Visit Log\n");
    printf("----------------------------------------------------------------------\n");
    printf
        ("nnnn,           usr_mac,            ap_mac,            essid, sig,nnnnn,  times,      firsttime,       lasttime,   stay  \n");
    for(i = 0; i < cur_pos; i++)
    {
        all = all + visitlist[i].times;
        printf("%4d, ", i + 1);
        printf("%02x:%02x:%02x:%02x:%02x:%02x, ",
               visitlist[i].usr_mac[0], visitlist[i].usr_mac[1],
               visitlist[i].usr_mac[2], visitlist[i].usr_mac[3],
               visitlist[i].usr_mac[4], visitlist[i].usr_mac[5]);

        printf("%02x:%02x:%02x:%02x:%02x:%02x, ",
               visitlist[i].ap_mac[0], visitlist[i].ap_mac[1],
               visitlist[i].ap_mac[2], visitlist[i].ap_mac[3],
               visitlist[i].ap_mac[4], visitlist[i].ap_mac[5]);

        for(j = 0; j < MAX_AP_LIST_NUM; j++)
        {
            if(MAC_NOT_EMPTY(aplist[j].ap_bssid))
            {
                if(MAC_EQUAL(visitlist[i].ap_mac, aplist[j].ap_bssid))
                {
                    printf("%16s, ", aplist[j].ap_essid);
                    break;
                }
            } else
            {
                printf("                , ");
                break;
            }
        }

        printf("%3d, %04x, %6d, ", visitlist[i].usr_signal,
               visitlist[i].pk_type, visitlist[i].times);

        t = visitlist[i].first_time;
        local = localtime(&t);

        printf("%02d-%02d %02d:%02d:%02d, ", local->tm_mon + 1,
               local->tm_mday, local->tm_hour, local->tm_min, local->tm_sec);

        t = visitlist[i].last_time;
        local = localtime(&t);

        printf("%02d-%02d %02d:%02d:%02d, ", local->tm_mon + 1,
               local->tm_mday, local->tm_hour, local->tm_min, local->tm_sec);

        diff_time = visitlist[i].last_time - visitlist[i].first_time;

        printf(" %2d.%02d, ", diff_time / 60, diff_time % 60);

        printf("%16s, ", ip_sprintf(visitlist[i].src_ip));
        printf("%16s, ", ip_sprintf(visitlist[i].dst_ip));
        printf("%d, %d", visitlist[i].src_port, visitlist[i].dst_port);

        printf("\n");
    }
    //printf("all = %d\n",all);
}

//-----------------------------------------------------------------------------
// 把当前列表保存到指定文件：正常结束退出时调用
//-----------------------------------------------------------------------------
void fprint_logfile(char *mac_addr, char *logfilename)
{
    struct tm *local;
    time_t t;
    int diff_time;
    int i, j;
    //char visitfilename[64];

    FILE *VISIT_LIST_LOG = NULL;       // 测试结果汇总文件句柄

    if(cur_pos == 0)
        return;

/*
	//获取当前时间	
	t = time(NULL);
	local = localtime(&t);
	

	//根据时间戳自动生成日志文件
	sprintf(summaryfilename, "/tmp/%04d_%02d_%02d_%02d_%02d_%02d.vit",
        local->tm_year+1900,local->tm_mon+1,local->tm_mday,local->tm_hour, local->tm_min, local->tm_sec);

    sprintf(summaryfilename, "/tmp/%s_%s.log", device_id, timestamp);
    sprintf(uploadfilename, "%s_%s.log", device_id, timestamp);

*/

    //打开日志文件,追加的方式读写
    VISIT_LIST_LOG = fopen(logfilename, "a+");
    if(VISIT_LIST_LOG == NULL)
        err(1, "couldn't open packetlog file: %s", logfilename);

    for(i = 0; i < cur_pos; i++)
    {
/*		
		fprintf(VISIT_LIST_LOG, "%02x%02x%02x%02x%02x%02x, ",
		eth0_mac[0],eth0_mac[1],eth0_mac[2],eth0_mac[3],eth0_mac[4],eth0_mac[5]);
*/
        fprintf(VISIT_LIST_LOG, "%s, ", mac_addr);

        fprintf(VISIT_LIST_LOG, "%02x:%02x:%02x:%02x:%02x:%02x, ",
                visitlist[i].usr_mac[0], visitlist[i].usr_mac[1],
                visitlist[i].usr_mac[2], visitlist[i].usr_mac[3],
                visitlist[i].usr_mac[4], visitlist[i].usr_mac[5]);

        fprintf(VISIT_LIST_LOG, "%02x:%02x:%02x:%02x:%02x:%02x, ",
                visitlist[i].ap_mac[0], visitlist[i].ap_mac[1],
                visitlist[i].ap_mac[2], visitlist[i].ap_mac[3],
                visitlist[i].ap_mac[4], visitlist[i].ap_mac[5]);

        for(j = 0; j < MAX_AP_LIST_NUM; j++)
        {
            if(MAC_NOT_EMPTY(aplist[j].ap_bssid))
            {
                if(MAC_EQUAL(visitlist[i].ap_mac, aplist[j].ap_bssid))
                {
                    fprintf(VISIT_LIST_LOG, "%16s, ", aplist[j].ap_essid);
                    break;
                }
            } else
            {
                fprintf(VISIT_LIST_LOG, "                , ");
                break;
            }
        }

        fprintf(VISIT_LIST_LOG, "%3d, %04x, %6d, ", visitlist[i].usr_signal,
                visitlist[i].pk_type, visitlist[i].times);

        t = visitlist[i].first_time;
        local = localtime(&t);

        fprintf(VISIT_LIST_LOG, " %04d-%02d-%02d %02d:%02d:%02d, ", local->tm_year + 1900,
                local->tm_mon + 1, local->tm_mday, local->tm_hour, local->tm_min, local->tm_sec);

        t = visitlist[i].last_time;
        local = localtime(&t);

        fprintf(VISIT_LIST_LOG, " %04d-%02d-%02d %02d:%02d:%02d, ", local->tm_year + 1900,
                local->tm_mon + 1, local->tm_mday, local->tm_hour, local->tm_min, local->tm_sec);

        diff_time = visitlist[i].last_time - visitlist[i].first_time;

        if(diff_time < 0)
        {
            fprintf(VISIT_LIST_LOG, " %2d.%02d, ", 0, 0);
        } else
        {
            fprintf(VISIT_LIST_LOG, " %2d.%02d, ", diff_time / 60, diff_time % 60);
        }

        fprintf(VISIT_LIST_LOG, "%16s, ", ip_sprintf(visitlist[i].src_ip));
        fprintf(VISIT_LIST_LOG, "%16s, ", ip_sprintf(visitlist[i].dst_ip));
        fprintf(VISIT_LIST_LOG, "%d, %d", visitlist[i].src_port, visitlist[i].dst_port);

        fprintf(VISIT_LIST_LOG, "\n");
    }

    fclose(VISIT_LIST_LOG);

}

void init_ap_list(void)
{
    memset(&aplist, 0, sizeof(aplist));
}

//---------------------------------------------------------
//初始化记录模块
//---------------------------------------------------------
void init_pnl_list(void)
{
    memset(&pnl_list, 0, sizeof(pnl_list));
}

int update_pnl_list(unsigned char *new_usr_mac, unsigned char *new_qry_apmac, char *new_qry_apname)
{
    int i;
    time_t t_now;

    //获取当前时间
    t_now = time(NULL);

    for(i = 0; i < MAX_USR_PNL_NUM; i++)
    {
        if((MAC_EQUAL(new_usr_mac, pnl_list[i].usr_mac))
           && (strcmp(new_qry_apname, pnl_list[i].ap_essid) == 0))
        {
            pnl_list[i].times++;
            pnl_list[i].qry_time = t_now;
            if(!MAC_EQUAL(new_qry_apmac, FFFF_MAC))
                memcpy(pnl_list[i].ap_mac, new_qry_apmac, MAC_LEN);
            break;
        } else
        {
            if(MAC_EMPTY(pnl_list[i].usr_mac))
            {
                pnl_list[i].times = 1;
                memcpy(pnl_list[i].usr_mac, new_usr_mac, MAC_LEN);
                memcpy(pnl_list[i].ap_mac, new_qry_apmac, MAC_LEN);
                memcpy(pnl_list[i].ap_essid, new_qry_apname, MAX_ESSID_LEN);
                pnl_list[i].qry_time = t_now;
                break;
            }
        }
    }
    return 0;
}

void print_pnllist(void)
{
    int i;
    struct tm *local;
    time_t t;

    printf("----------------------------------------------------------------------\n");
    printf(" *User PNL Log\n");
    printf("----------------------------------------------------------------------\n");
    printf("nnnn,           usr_mac,            ap_mac,            essid,  times  \n");

    for(i = 0; i < MAX_USR_PNL_NUM; i++)
    {
        if(MAC_EMPTY(pnl_list[i].usr_mac))
        {
            break;
        } else
        {
            printf("%4d, ", i + 1);
            printf("%02x:%02x:%02x:%02x:%02x:%02x, ",
                   pnl_list[i].usr_mac[0], pnl_list[i].usr_mac[1],
                   pnl_list[i].usr_mac[2], pnl_list[i].usr_mac[3],
                   pnl_list[i].usr_mac[4], pnl_list[i].usr_mac[5]);

            printf("%02x:%02x:%02x:%02x:%02x:%02x, ",
                   pnl_list[i].ap_mac[0], pnl_list[i].ap_mac[1],
                   pnl_list[i].ap_mac[2], pnl_list[i].ap_mac[3],
                   pnl_list[i].ap_mac[4], pnl_list[i].ap_mac[5]);
            printf("%16s, ", pnl_list[i].ap_essid);

            printf("%6d, ", pnl_list[i].times);

            t = pnl_list[i].qry_time;
            local = localtime(&t);

            printf(" %04d-%02d-%02d %02d:%02d:%02d ", local->tm_year + 1900, local->tm_mon + 1,
                   local->tm_mday, local->tm_hour, local->tm_min, local->tm_sec);

            printf("\n");

        }

    }

}

//-----------------------------------------------------------------------------
// 按照次数排序的比较方法
//-----------------------------------------------------------------------------
int cmp_visittimes(const void *a, const void *b)
{
    struct _usr_visitlist *aa, *bb;

    aa = (struct _usr_visitlist *)a;
    bb = (struct _usr_visitlist *)b;

    return (aa->times) > (bb->times) ? -1 : 1;
}

//-----------------------------------------------------------------------------
// 按照次数排序
//-----------------------------------------------------------------------------
void sort_visitlist_list_by_times(void)
{
    qsort(visitlist, MAX_USR_VISIT_NUM, sizeof(visitlist[0]), cmp_visittimes);
}

//-----------------------------------------------------------------------------
// 按照最后更新时间排序的比较方法
//-----------------------------------------------------------------------------
int cmp_lasttime(const void *a, const void *b)
{
    struct _usr_visitlist *aa, *bb;

    aa = (struct _usr_visitlist *)a;
    bb = (struct _usr_visitlist *)b;

    return (aa->last_time) > (bb->last_time) ? -1 : 1;
}

//-----------------------------------------------------------------------------
// 按照最后更新时间排序
//-----------------------------------------------------------------------------
void sort_visitlist_list_by_lasttime(void)
{
    qsort(visitlist, MAX_USR_VISIT_NUM, sizeof(visitlist[0]), cmp_lasttime);
}

//-----------------------------------------------------------------------------
// 按照MAC地址排序的比较方法
//-----------------------------------------------------------------------------
int cmp_mac(const void *a, const void *b)
{
    struct _usr_visitlist *aa, *bb;

    aa = (struct _usr_visitlist *)a;
    bb = (struct _usr_visitlist *)b;

    return (memcmp(aa->usr_mac, bb->usr_mac, 6) > 0) ? -1 : 1;
}

//-----------------------------------------------------------------------------
// 按照MAC地址排序
//-----------------------------------------------------------------------------
void sort_visitlist_list_by_mac(void)
{
    qsort(visitlist, MAX_USR_VISIT_NUM, sizeof(visitlist[0]), cmp_mac);
}

//-----------------------------------------------------------------------------
// 把当前列表保存到指定文件：正常结束退出时调用
//-----------------------------------------------------------------------------
void fprint_pnlfile(char *mac_addr, char *logfilename)
{
    struct tm *local;
    time_t t;
    int i;

    FILE *PNL_LIST_LOG = NULL;         // 测试结果汇总文件句柄

    if(MAC_EMPTY(pnl_list[0].usr_mac))
        return;

    //打开日志文件,追加的方式读写
    PNL_LIST_LOG = fopen(logfilename, "a+");
    if(PNL_LIST_LOG == NULL)
        err(1, "couldn't open packetlog file: %s", logfilename);

    for(i = 0; i < MAX_USR_PNL_NUM; i++)
    {
        if(MAC_EMPTY(pnl_list[i].usr_mac))
        {
            break;
        } else
        {
/*		
			fprintf(PNL_LIST_LOG, "%02x%02x%02x%02x%02x%02x, ",
			eth0_mac[0],eth0_mac[1],eth0_mac[2],eth0_mac[3],eth0_mac[4],eth0_mac[5]);
*/
            fprintf(PNL_LIST_LOG, "%s, ", mac_addr);

            fprintf(PNL_LIST_LOG, "%02x:%02x:%02x:%02x:%02x:%02x, ",
                    pnl_list[i].usr_mac[0], pnl_list[i].usr_mac[1],
                    pnl_list[i].usr_mac[2], pnl_list[i].usr_mac[3],
                    pnl_list[i].usr_mac[4], pnl_list[i].usr_mac[5]);

            fprintf(PNL_LIST_LOG, "%02x:%02x:%02x:%02x:%02x:%02x, ",
                    pnl_list[i].ap_mac[0], pnl_list[i].ap_mac[1],
                    pnl_list[i].ap_mac[2], pnl_list[i].ap_mac[3],
                    pnl_list[i].ap_mac[4], pnl_list[i].ap_mac[5]);

            fprintf(PNL_LIST_LOG, "%16s, ", pnl_list[i].ap_essid);

            fprintf(PNL_LIST_LOG, "%6d, ", pnl_list[i].times);

            t = pnl_list[i].qry_time;
            local = localtime(&t);

            fprintf(PNL_LIST_LOG, " %04d-%02d-%02d %02d:%02d:%02d ", local->tm_year + 1900,
                    local->tm_mon + 1, local->tm_mday, local->tm_hour, local->tm_min,
                    local->tm_sec);

            fprintf(PNL_LIST_LOG, "\n");

        }
    }

    fclose(PNL_LIST_LOG);
}

//-----------------------------------------------------------------------------
// 打印当前aplist到文件
//-----------------------------------------------------------------------------
void fprint_aplfile(char *mac_addr, char *logfilename)
{
    struct tm *local;
    time_t t;
    int i;

    FILE *AP_LIST_LOG = NULL;          // 测试结果汇总文件句柄

    if(MAC_EMPTY(aplist[0].ap_bssid))
        return;

    //打开日志文件,追加的方式读写
    AP_LIST_LOG = fopen(logfilename, "a+");
    if(AP_LIST_LOG == NULL)
        err(1, "couldn't open packetlog file: %s", logfilename);

    for(i = 0; i < MAX_AP_LIST_NUM; i++)
    {
        if(MAC_EMPTY(aplist[i].ap_bssid))
        {
            break;
        } else
        {
/*		
			fprintf(AP_LIST_LOG, "%02x%02x%02x%02x%02x%02x, ",
			eth0_mac[0],eth0_mac[1],eth0_mac[2],eth0_mac[3],eth0_mac[4],eth0_mac[5]);
*/
            fprintf(AP_LIST_LOG, "%s, ", mac_addr);

            fprintf(AP_LIST_LOG, "%02x:%02x:%02x:%02x:%02x:%02x, ",
                    aplist[i].ap_bssid[0], aplist[i].ap_bssid[1],
                    aplist[i].ap_bssid[2], aplist[i].ap_bssid[3],
                    aplist[i].ap_bssid[4], aplist[i].ap_bssid[5]);

            fprintf(AP_LIST_LOG, "%16s, %7d, %3d, %7d, ", aplist[i].ap_essid, aplist[i].ap_channel,
                    aplist[i].sum_signal / aplist[i].ap_beacon_count, aplist[i].ap_beacon_count);

            t = aplist[i].first_time;
            local = localtime(&t);

            fprintf(AP_LIST_LOG, " %04d-%02d-%02d %02d:%02d:%02d, ", local->tm_year + 1900,
                    local->tm_mon + 1, local->tm_mday, local->tm_hour, local->tm_min,
                    local->tm_sec);

            t = aplist[i].last_time;
            local = localtime(&t);

            fprintf(AP_LIST_LOG, " %04d-%02d-%02d %02d:%02d:%02d, ", local->tm_year + 1900,
                    local->tm_mon + 1, local->tm_mday, local->tm_hour, local->tm_min,
                    local->tm_sec);

            if(aplist[i].ap_ecypt & EYPT_WEP)
                fprintf(AP_LIST_LOG, "WEP");
            if(aplist[i].ap_ecypt & EYPT_WPA)
                fprintf(AP_LIST_LOG, "|WPA");
            if(aplist[i].ap_ecypt & EYPT_WPA2)
                fprintf(AP_LIST_LOG, "|WPA2");
            if(aplist[i].ap_ecypt & EYPT_WPS)
                fprintf(AP_LIST_LOG, "|WPS");

            fprintf(AP_LIST_LOG, "\n");

        }
    }

    fclose(AP_LIST_LOG);
}

//-----------------------------------------------------------------------------
// 测试各种排序的时耗
//-----------------------------------------------------------------------------
void test_sort_time(void)
{
    struct timeval a, b;

    //默认排序
    print_visitlist();
    printf("\n\n");

    //最后更新时间排序
    gettimeofday(&a, NULL);
    sort_visitlist_list_by_lasttime();
    gettimeofday(&b, NULL);
    print_visitlist();
    printf("sort_time: %ld \n\n", b.tv_usec - a.tv_usec);

    //更新次数排序
    gettimeofday(&a, NULL);
    sort_visitlist_list_by_times();
    gettimeofday(&b, NULL);
    print_visitlist();
    printf("sort_time: %ld \n\n", b.tv_usec - a.tv_usec);

    //mac地址排序
    gettimeofday(&a, NULL);
    sort_visitlist_list_by_mac();
    gettimeofday(&b, NULL);
    print_visitlist();
    printf("sort_time: %ld \n\n", b.tv_usec - a.tv_usec);

}

//-----------------------------------------------------------------------------
// 定期check已成事实的访问记录，保存到年月日时_visit.log文件（即一个小时一个文件）
// 既成事实的逻辑：最后一次扫描到的时间距离当前时间：默认一小时
// 在主循环里调用，建议每5分钟调用一次
//-----------------------------------------------------------------------------
void visitlog2file(void)
{
    /*
       struct tm *local;
       time_t t, now;
       int diff_time;
       int i, count, j;
       char visitfilename[32];

       FILE *VISIT_LOG = NULL;      // 测试结果汇总文件句柄

       //获取当前时间   
       now = time(NULL);
       local = localtime(&now);

       //根据时间保持指定的文件
       sprintf(visitfilename, "/tmp/%04d_%02d_%02d_%02d.vit", 
       local->tm_year+1900,local->tm_mon+1,local->tm_mday, local->tm_hour);

       //打开日志文件,追加的方式读写
       VISIT_LOG = fopen(visitfilename, "a+");
       if(VISIT_LOG == NULL)
       err(1, "couldn't open packetlog file: %s", visitfilename);   

       //按照最后时间排序，最新的在最前面
       sort_visitlist_list_by_lasttime();

       now = time(NULL);

       count = 0;
       for (i=cur_pos-1; i>0; i--)
       {
       //如果超过一个小时，保持到指定文件
       if ((now - visitlist[i].last_time) > VISIT_STATISTICS_CYCLE)
       {
       count++;

       fprintf(VISIT_LOG, "%02x%02x%02x%02x%02x%02x, ",
       1,2,3,4,5,6);        

       fprintf(VISIT_LOG, "%02x:%02x:%02x:%02x:%02x:%02x, ",
       visitlist[i].usr_mac[0],visitlist[i].usr_mac[1],
       visitlist[i].usr_mac[2],visitlist[i].usr_mac[3],
       visitlist[i].usr_mac[4],visitlist[i].usr_mac[5]);

       fprintf(VISIT_LOG, "%02x:%02x:%02x:%02x:%02x:%02x, ",
       visitlist[i].ap_mac[0],visitlist[i].ap_mac[1],
       visitlist[i].ap_mac[2],visitlist[i].ap_mac[3],
       visitlist[i].ap_mac[4],visitlist[i].ap_mac[5]);

       for(j = 0; j < MAX_AP_LIST_NUM; j++)
       {
       if(MAC_NOT_EMPTY(aplist[j].ap_bssid))
       {
       if(MAC_EQUAL(visitlist[i].ap_mac, aplist[j].ap_bssid))
       {
       fprintf(VISIT_LOG, "%16s, ", aplist[j].ap_essid);
       break;
       }
       } else
       {
       fprintf(VISIT_LOG, "                , ");
       break;
       }
       }

       fprintf(VISIT_LOG, "%3d, %04x, %6d, ",visitlist[i].usr_signal,
       visitlist[i].pk_type, visitlist[i].times);

       t = visitlist[i].first_time;
       local = localtime(&t);

       fprintf(VISIT_LOG, " %04d-%02d-%02d %02d:%02d:%02d, ", local->tm_year+1900,local->tm_mon+1,
       local->tm_mday,local->tm_hour,local->tm_min,local->tm_sec);

       t = visitlist[i].last_time;
       local = localtime(&t);

       fprintf(VISIT_LOG, " %04d-%02d-%02d %02d:%02d:%02d, ", local->tm_year+1900,local->tm_mon+1,
       local->tm_mday,local->tm_hour,local->tm_min,local->tm_sec);

       diff_time = visitlist[i].last_time -visitlist[i].first_time;

       fprintf(VISIT_LOG, " %2d.%02d", diff_time/60, diff_time%60);

       fprintf(VISIT_LOG, "\n");

       //移除后重置为0
       memset(&visitlist[i], 0, sizeof(struct _usr_visitlist));
       }
       else
       break;

       }

       cur_pos = cur_pos - count;

       //恢复按照mac地址排序，为了下面的二分法查找
       sort_visitlist_list_by_mac();

       fclose(VISIT_LOG);
     */
}

void init_agl_list(void)
{
    memset(&usr_http_list, 0, sizeof(usr_http_list));
}

/*
	new_usr_qq存在解析不严谨，可能为IMEI串号，也有可能是非数字的字符串
*/
int update_agent_list(unsigned char *new_usr_mac, char *new_usr_http_agent,
                      char *new_usr_http_host)
{
    int i;
    time_t t_now;

    //获取当前时间
    t_now = time(NULL);

    for(i = 0; i < MAX_USR_HTTP_NUM; i++)
    {
        if(MAC_EQUAL(new_usr_mac, usr_http_list[i].usr_mac))
        {
            usr_http_list[i].times++;

            //保留信息长的agent
            // Windows Android iPhone iPad
            if((strstr(new_usr_http_agent, "Android")) || (strstr(new_usr_http_agent, "iPhone")) ||
               (strstr(new_usr_http_agent, "iPad")) || (strstr(new_usr_http_agent, "Windows")))
                memcpy(usr_http_list[i].usr_agent, new_usr_http_agent, 128);

            if(strlen(new_usr_http_host) > 0)
                memcpy(usr_http_list[i].usr_host, new_usr_http_host, 32);

            break;
        } else
        {
            if(MAC_EMPTY(usr_http_list[i].usr_mac))
            {
                usr_http_list[i].times = 1;
                usr_http_list[i].usr_http_time = t_now;

                memcpy(usr_http_list[i].usr_mac, new_usr_mac, MAC_LEN);
                memcpy(usr_http_list[i].usr_agent, new_usr_http_agent, 128);

                if(strlen(new_usr_http_host) > 0)
                    memcpy(usr_http_list[i].usr_host, new_usr_http_host, 32);

                break;
            }
        }
    }
    return 0;
}

/*
void print_usrhttplist(void)
{
    int i;
    struct tm *local;
    time_t t;

    printf("----------------------------------------------------------------------\n");
    printf(" *User Http Log\n");
    printf("----------------------------------------------------------------------\n");
    printf("nnnn,           usr_mac,     times,       agent,            host,  qq  \n");

    for(i = 0; i < MAX_USR_HTTP_NUM; i++)
    {
        if(MAC_EMPTY(usr_http_list[i].usr_mac))
        {
            break;
        } else
        {
            printf("%4d, ", i + 1);
            printf("%02x:%02x:%02x:%02x:%02x:%02x, ",
                   usr_http_list[i].usr_mac[0], usr_http_list[i].usr_mac[1],
                   usr_http_list[i].usr_mac[2], usr_http_list[i].usr_mac[3],
                   usr_http_list[i].usr_mac[4], usr_http_list[i].usr_mac[5]);

            printf("%6d, ", usr_http_list[i].times);

            t = usr_http_list[i].usr_http_time;
            local = localtime(&t);

            printf(" %04d-%02d-%02d %02d:%02d:%02d, ", local->tm_year + 1900, local->tm_mon + 1,
                   local->tm_mday, local->tm_hour, local->tm_min, local->tm_sec);

            printf("%s, ", usr_http_list[i].usr_agent);
            printf("%s, ", usr_http_list[i].usr_host);
            printf("%s, ", usr_http_list[i].usr_qq);

            printf("\n");

        }

    }
}

*/

/*
	虚拟身份，命名沿用 http agent，为.gal文件，其实应该是 .vid
*/
void fprint_aglfile(char *mac_addr, char *logfilename)
{
    struct tm *local;
    time_t t;
    int i;

    FILE *HTTP_LIST_LOG = NULL;        // 测试结果汇总文件句柄

    if(MAC_EMPTY(usr_http_list[0].usr_mac))
        return;

    //打开日志文件,追加的方式读写
    HTTP_LIST_LOG = fopen(logfilename, "a+");
    if(HTTP_LIST_LOG == NULL)
        err(1, "couldn't open packetlog file: %s", logfilename);

    for(i = 0; i < MAX_USR_HTTP_NUM; i++)
    {
        if(MAC_EMPTY(usr_http_list[i].usr_mac))
        {
            break;
        } else
        {
/*		
			fprintf(HTTP_LIST_LOG, "%02x%02x%02x%02x%02x%02x, ",
			eth0_mac[0],eth0_mac[1],eth0_mac[2],eth0_mac[3],eth0_mac[4],eth0_mac[5]);
*/
            fprintf(HTTP_LIST_LOG, "%s][ ", mac_addr);

            fprintf(HTTP_LIST_LOG, "%02x:%02x:%02x:%02x:%02x:%02x][ ",
                    usr_http_list[i].usr_mac[0], usr_http_list[i].usr_mac[1],
                    usr_http_list[i].usr_mac[2], usr_http_list[i].usr_mac[3],
                    usr_http_list[i].usr_mac[4], usr_http_list[i].usr_mac[5]);

            fprintf(HTTP_LIST_LOG, "%6d][ ", usr_http_list[i].times);

            t = usr_http_list[i].usr_http_time;
            local = localtime(&t);

            fprintf(HTTP_LIST_LOG, " %04d-%02d-%02d %02d:%02d:%02d][ ", local->tm_year + 1900,
                    local->tm_mon + 1, local->tm_mday, local->tm_hour, local->tm_min,
                    local->tm_sec);

            fprintf(HTTP_LIST_LOG, "%s][ ", usr_http_list[i].usr_agent);
            fprintf(HTTP_LIST_LOG, "%s][ ", usr_http_list[i].usr_host);
            fprintf(HTTP_LIST_LOG, "%s][ ", usr_http_list[i].usr_qq);

            fprintf(HTTP_LIST_LOG, "\n");

        }
    }

    for(i = 0; i < MAX_USR_VID_NUM; i++)
    {
        if(MAC_EMPTY(usr_vid_list[i].usr_mac))
        {
            break;
        } else
        {
/*		
			fprintf(HTTP_LIST_LOG, "%02x%02x%02x%02x%02x%02x, ",
			eth0_mac[0],eth0_mac[1],eth0_mac[2],eth0_mac[3],eth0_mac[4],eth0_mac[5]);
*/
            fprintf(HTTP_LIST_LOG, "%s][ ", mac_addr);

            fprintf(HTTP_LIST_LOG, "%02x:%02x:%02x:%02x:%02x:%02x][ ",
                    usr_vid_list[i].usr_mac[0], usr_vid_list[i].usr_mac[1],
                    usr_vid_list[i].usr_mac[2], usr_vid_list[i].usr_mac[3],
                    usr_vid_list[i].usr_mac[4], usr_vid_list[i].usr_mac[5]);

            fprintf(HTTP_LIST_LOG, "%6d][ ", usr_vid_list[i].times);

            t = usr_vid_list[i].get_vid_time;
            local = localtime(&t);

            fprintf(HTTP_LIST_LOG, " %04d-%02d-%02d %02d:%02d:%02d][ ", local->tm_year + 1900,
                    local->tm_mon + 1, local->tm_mday, local->tm_hour, local->tm_min,
                    local->tm_sec);

            fprintf(HTTP_LIST_LOG, "%s][ ", "");
            fprintf(HTTP_LIST_LOG, "%s][ ", usr_vid_list[i].usr_vid);
            fprintf(HTTP_LIST_LOG, "%d][ ", usr_vid_list[i].usr_vid_type);

            fprintf(HTTP_LIST_LOG, "\n");

        }
    }

    fclose(HTTP_LIST_LOG);
}

void init_vid_list(void)
{
    memset(&usr_vid_list, 0, sizeof(usr_vid_list));
}

int update_vid_list(unsigned char *new_usr_mac, char *new_usr_vid, unsigned int new_usr_vid_type)
{
    int i;
    time_t t_now;
/*
    if ((is_pro !=1)&&(new_usr_vid_type!=4))
    	return 0;    
*/

    if((new_usr_vid_type == 4) && (strlen(new_usr_vid) == 15))
        new_usr_vid_type = 2;

    /* 过滤14位的QQ */
    if((new_usr_vid_type == 4) && (strlen(new_usr_vid) == 14))
        return 0;

    /* 过滤13位的QQ */
    if((new_usr_vid_type == 4) && (strlen(new_usr_vid) == 13))
        return 0;

    /* 过滤12位的QQ */
    if((new_usr_vid_type == 4) && (strlen(new_usr_vid) == 12))
        return 0;

    //获取当前时间
    t_now = time(NULL);

    printf("update_vid_list: %s - %s\n", ether_sprintf(new_usr_mac), new_usr_vid);

    for(i = 0; i < MAX_USR_VID_NUM; i++)
    {
        if((MAC_EQUAL(new_usr_mac, usr_vid_list[i].usr_mac))
           && (strcmp(usr_vid_list[i].usr_vid, new_usr_vid) == 0)
           && (usr_vid_list[i].usr_vid_type == new_usr_vid_type))
        {
            usr_vid_list[i].times++;
            break;
        } else
        {
            if(MAC_EMPTY(usr_vid_list[i].usr_mac))
            {
                usr_vid_list[i].times = 1;
                usr_vid_list[i].get_vid_time = t_now;
                memcpy(usr_vid_list[i].usr_mac, new_usr_mac, MAC_LEN);
                usr_vid_list[i].usr_vid_type = new_usr_vid_type;
                memcpy(usr_vid_list[i].usr_vid, new_usr_vid, 64);
                break;
            }
        }
    }

    return 0;
}
/****************************************************************************
通过tcp把数据上传至服务器
****************************************************************************/
void snd_vidfile(void)
{
	int i;
	int ret;
	char send_buf[128];

	if(MAC_EMPTY(usr_vid_list[0].usr_mac))
		return;
	ret = connect_with_custom_timeout(ftp_ip, 9306);
	if(ret == 0)
	{
		for(i = 0; i < MAX_USR_VID_NUM; i++)
		{
			if(MAC_EMPTY(usr_vid_list[i].usr_mac))
			{
				break;
			}
			else
			{
				memset(send_buf, 0x00, 128);
				sprintf(send_buf, "3,%02x%02x%02x%02x%02x%02x,%d,%s,%s,%s,%d", usr_vid_list[i].usr_mac[0],usr_vid_list[i].usr_mac[1],usr_vid_list[i].usr_mac[2],	
				usr_vid_list[i].usr_mac[3],usr_vid_list[i].usr_mac[4],usr_vid_list[i].usr_mac[5], usr_vid_list[i].usr_vid_type, usr_vid_list[i].usr_vid,
				device_id, cfg_mac_addr, usr_vid_list[i].get_vid_time);
				net_notify(send_buf);
				usleep(100000);
			}
		}
		close(cli_nodify_fd); 
		init_vid_list();
	}
}



