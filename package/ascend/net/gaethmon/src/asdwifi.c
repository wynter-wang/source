/*******************************************************************************
 *	Monitor模式下的802.11帧扫描分析
 *	1.确定网卡及驱动支持monitor模式
 *	2.运行时，需要先设置为monitor模式
 *	3.不同的驱动，捕获的帧格式可能不同
 *	
 *	todolist:
 *	1.支持802.11n制式
 *	2.更加详尽的统计指标
 *	3.IP层的解析
 *	
 *	update
 *	12-08-03[5] 10_43_13 ieee802_11_parse_elems函数存在处理不当，异常数据引起
 *	12-08-14[2] 19_42_38 改进了parse_radiotap_header的解析，解析出更多的信息
 *  12-08-24[5] 16_48_08 增加了ap统计信息（信号强度和信噪比）
 
*******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <errno.h>
#include <err.h>
#include <linux/wireless.h>
#include <signal.h>                    //为了捕获Ctrl+C等信号正常退出

#include <net/if_arp.h>

//-----------------------------------------------------------------------------
//守护进程运行方式的支持
//-----------------------------------------------------------------------------
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>                     // 文件控制定义
#include <syslog.h>                    // syslog定义

#include <netdb.h>

//va_list
#include <stdarg.h>                    //标准C库 standard argument(标准参数)

#include "main.h"
#include "readcfg.h"
#include "asdwifi.h"
#include "parser.h"
#include "util.h"


#include "wifilog.h"

#define MAC_VALID(_mac1) ((_mac1[0]==0x00)&&\
  (_mac1[1]==0x0f)&&(_mac1[2]==0xe2))

//-----------------------------------------------------------------------------
// 配置定义
// 初始值的初始化
//-----------------------------------------------------------------------------
struct config conf = {
    .ifname = INTERFACE_NAME,          //wlan0，默认网卡接口名
    .debug_level = DEBUG_LEVEL_NONE,   //0 默认调试级别为0
    .change_channel_interval = CHANGE_CHANNEL_INTERVAL, //10000
    .channel_default = CHANNEL_DEFAULT, //0 [1号信道，从0开始到13]
    .recv_buffer_size = RECV_BUFFER_SIZE,   //0 not used by default 
};

/* 文件描述符，用于select */
int mon;                               /* 监控fd */

int mfd = -1;

int bQuit = 0;

//全局变量
struct packet_info newpacket;          //最关键的帧数据结构定义

// 捕获的帧序号
int packet_count;
int invalid_fcs_packet_count;          //FCS校验失败的帧序号

struct tm *local;
time_t t_begin, t_end;
int diff_time;

static FILE *PACKETLOG = NULL;         // 日志文件句柄
static FILE *PARSERLOG = NULL;         // 解析日志文件

//-----------------------------------------------------------------------------
// for select 
//-----------------------------------------------------------------------------
static fd_set read_fds;
static fd_set write_fds;
static fd_set excpt_fds;

//-----------------------------------------------------------------------------
// 时间相关的变量参数
//-----------------------------------------------------------------------------
static struct timeval tv_select;       //select超时时间
static struct timeval tv_now;
static struct timeval tv_last_channelchange;

//本地有线网卡的MAC地址，作为设备的唯一标示
unsigned char eth0_mac[6];
unsigned char eth1_mac[6];
unsigned char wlan0_mac[6];

/* receive packet buffer
 *
 * due to the way we receive packets the network (TCP connection) we have to
 * expect the reception of partial packet as well as the reception of several
 * packets at one. thus we implement a buffered receive where partially received
 * data stays in the buffer.
 *
 * we need two buffers: one for packet capture or receiving from the server and
 * another one for data the clients sends to the server.
 *
 * not sure if this is also an issue with local packet capture, but it is not
 * implemented there.
 *
 * size: max 80211 frame (2312) + space for prism2 header (144)
 * or radiotap header (usually only 26) + some extra */
static unsigned char buffer[2312 + 200];

#ifdef _DEBUG

int get_i, get_o, get_all;
struct timeval get_time;
int get_ii, get_oo;

int max_packet_len;

#endif

void start_tcpsvr(int port);

//-----------------------------------------------------------------------------
// 分选项打印调试信息
//-----------------------------------------------------------------------------
void fdebug(unsigned int level, const char *fmt, ...)
{
    if(PARSERLOG != NULL)
    {
        if(level & conf.debug_level)
        {
            va_list ap;
            va_start(ap, fmt);
            vfprintf(PARSERLOG, fmt, ap);
            va_end(ap);
        }
    }
}

int get_eth0_mac(unsigned char *mac_addr)
{
    int sock_mac;

    struct ifreq ifr_mac;

    sock_mac = socket(AF_INET, SOCK_STREAM, 0);
    if(sock_mac == -1)
    {
        perror("create socket failed...mac\n");
        return 0;
    }

    memset(&ifr_mac, 0, sizeof(ifr_mac));
    strncpy(ifr_mac.ifr_name, "eth0", sizeof(ifr_mac.ifr_name) - 1);

    if((ioctl(sock_mac, SIOCGIFHWADDR, &ifr_mac)) < 0)
    {
        printf("mac ioctl error\n");
        return 0;
    }

    memcpy(mac_addr, ifr_mac.ifr_hwaddr.sa_data, 6);

    close(sock_mac);
    return 1;
}

int get_eth1_mac(unsigned char *mac_addr)
{
    int sock_mac;

    struct ifreq ifr_mac;

    sock_mac = socket(AF_INET, SOCK_STREAM, 0);
    if(sock_mac == -1)
    {
        perror("create socket failed...mac\n");
        return 0;
    }

    memset(&ifr_mac, 0, sizeof(ifr_mac));
    strncpy(ifr_mac.ifr_name, "eth1", sizeof(ifr_mac.ifr_name) - 1);

    if((ioctl(sock_mac, SIOCGIFHWADDR, &ifr_mac)) < 0)
    {
        printf("mac ioctl error\n");
        return 0;
    }

    memcpy(mac_addr, ifr_mac.ifr_hwaddr.sa_data, 6);

    close(sock_mac);
    return 1;
}
int get_wlan0_mac(unsigned char *mac_addr)
{
    int sock_mac;

    struct ifreq ifr_mac;

    sock_mac = socket(AF_INET, SOCK_STREAM, 0);
    if(sock_mac == -1)
    {
        perror("create socket failed...mac\n");
        return 0;
    }

    memset(&ifr_mac, 0, sizeof(ifr_mac));
    strncpy(ifr_mac.ifr_name, "wlan0", sizeof(ifr_mac.ifr_name) - 1);

    if((ioctl(sock_mac, SIOCGIFHWADDR, &ifr_mac)) < 0)
    {
        printf("mac ioctl error\n");
        return 0;
    }

    memcpy(mac_addr, ifr_mac.ifr_hwaddr.sa_data, 6);

    close(sock_mac);
    return 1;
}

//-----------------------------------------------------------------------------
// 打印解析后的帧信息
//-----------------------------------------------------------------------------
static int fprint_packet_parser(struct packet_info *p)
{
    //if(p->port_dst == 80)
    {

        fdebug(DEBUG_LEVEL_MIN, "-----packet_parser[index=%07d]-------\n", packet_count);

        //fdebug(DEBUG_LEVEL_PACKET_INFO, "type[%s][%d], retry[%d], \n",
        //       get_packet_type_name(p->wlan_type), p->wlan_type, p->wlan_retry);

        fdebug(DEBUG_LEVEL_PACKET_INFO, "src[%s], ", ether_sprintf(p->wlan_src));
        fdebug(DEBUG_LEVEL_PACKET_INFO, "des[%s], ", ether_sprintf(p->wlan_dst));
        //fdebug(DEBUG_LEVEL_PACKET_INFO, "bssid[%s], \n", ether_sprintf(p->wlan_bssid));

        ////pkt_types bitmask of packet types
        ////
        //fdebug(DEBUG_LEVEL_PACKET_INFO,
        //       "type[%x], signal[%d], noise[%d], snr[%d], len[%d], rate[%d], \n", p->pkt_types,
        //       p->phy_signal, p->phy_noise, p->phy_snr, p->wlan_len, p->phy_rate);

        ////wlan_tsf timestamp from beacon
        ////wlan_mode AP,STA, IBSS
        ////wlan_channel channel from beacon, probe
        ////wlan_wep WEP on/off

        //fdebug(DEBUG_LEVEL_PACKET_INFO, "tsf[%016llx], \n", (unsigned long long)p->wlan_tsf);
        //fdebug(DEBUG_LEVEL_PACKET_INFO, "essid[%s], mode[%d], channel[%d], wep[%d], \n",
        //       p->wlan_essid, p->wlan_mode, p->wlan_channel, p->wlan_wep);
        fdebug(DEBUG_LEVEL_PACKET_INFO, "src[%s], ", ip_sprintf(p->ip_src));
        fdebug(DEBUG_LEVEL_PACKET_INFO, "dst[%s], \n", ip_sprintf(p->ip_dst));

        //// OLSR是Optimized Link State Routing 的简称
        //// 主要用于MANET网络(Mobile Ad hoc network)的路由协议。

        //fdebug(DEBUG_LEVEL_PACKET_INFO, "[%d], [%d], [%d]\n", p->olsr_type, p->olsr_neigh,
        //       p->olsr_tc);
    }

    return 0;

}

void wifiup(void)
{
    FILE *pipe_stream;

    //启动wifi
    pipe_stream = popen("wifi", "r");
    if(pipe_stream == NULL)
    {
        perror("command error");
    }
    pclose(pipe_stream);
}

//-----------------------------------------------------------------------------
// 获取对应设备的ifindex 
//-----------------------------------------------------------------------------
static int get_device_ifindex(int fd, const char *devname)
{
    //定义在/usr/include/net/if.h
    struct ifreq req;

    //将ifname赋值给req
    strncpy(req.ifr_name, devname, IFNAMSIZ);
    req.ifr_addr.sa_family = AF_INET;

    //系统调用，尝试获得设备对应的索引号
    if(ioctl(fd, SIOCGIFINDEX, &req) < 0)
    {
        err(1, "ioctl SIOCGIFINDEX faild: %s", devname);
        return -1;
    }
    //没找到
    if(req.ifr_ifindex < 0)
        err(1, "Interface %s not found", devname);

    //printf("req.ifr_ifindex: %d\n", req.ifr_ifindex);
    return req.ifr_ifindex;
}

//-----------------------------------------------------------------------------
// 将网卡接口设置为混合模式
//-----------------------------------------------------------------------------
/*
static void set_device_promisc_mode_onoff(int fd, const char *devname, int on)
{
    struct ifreq req;

    //赋值ifr_name
    strncpy(req.ifr_name, devname, IFNAMSIZ);
    req.ifr_addr.sa_family = AF_INET;

    //根据ifr_name获取接口标志
    if(ioctl(fd, SIOCGIFFLAGS, &req) < 0)
        err(1, "Could not get device flags for %s", devname);

    // 顺便打开无线网卡
    req.ifr_flags |= IFF_UP;

    if(on)
        req.ifr_flags |= IFF_PROMISC;
    else
        req.ifr_flags &= ~IFF_PROMISC;

    if(ioctl(fd, SIOCSIFFLAGS, &req) < 0)
        err(1, "Could not set promisc mode for %s", devname);
}
*/

//-----------------------------------------------------------------------------
// 设置系统tcpip的socket接收buffersize
//-----------------------------------------------------------------------------
static void set_receive_buffer(int fd, int sockbufsize)
{
    int ret;

    // the maximum allowed value is set by the rmem_max sysctl 
    // 修改系统配置
    // 设置最大的TCP数据接收缓冲
    FILE *PF = fopen("/proc/sys/net/core/rmem_max", "w");
    fprintf(PF, "%d", sockbufsize);
    fclose(PF);

    // 设置Soeckt属性
    ret = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sockbufsize, sizeof(sockbufsize));
    if(ret != 0)
        err(1, "setsockopt failed");
    else
    {
        ;                              //printf("set_socket_revbuf_size = %d\n", sockbufsize);
    }

    if(conf.debug_level)
    {
        socklen_t size = sizeof(sockbufsize);
        sockbufsize = 0;
        ret = getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sockbufsize, &size);
        if(ret != 0)
            err(1, "getsockopt failed");
        else
            printf("read_socket_revbuf_size = %d\n", sockbufsize);
    }

}

/*
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <err.h>
*/

//-----------------------------------------------------------------------------
// 创建socket
//-----------------------------------------------------------------------------
int open_packet_socket(char *devname, size_t bufsize, int recv_buffer_size)
{
    int ret;
    int mon_fd;                        //socket句柄
    int ifindex;

    // 定义在：netpacket/packet.h
    struct sockaddr_ll sall;

    //-----------------------------------------------------------------------------
    // 系统调用Socket函数
    // domain:PF_PACKET：低层封包接口，与内核的CONFIG_PACKET_MMAP配置有关
    // type:SOCK_RAW：提供原始的网络协议访问，表示抓取到的包的数据是IP包
    // protocol:ETH_P_ALL 表示抓取所有以太帧
    //
    // 当通过socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))来创建处理链路层数据包时，内核会首先调用packet_create创建套接字。
    // net/packet/af_packet.c
    // 当程序通过socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))创建完套接字后，就能捕获到到达链路层的所有数据包，
    // 如果程序再通过下述方式将网上设置成混杂模式，就能捕获到网络上所有的数据包。
    // net/dev/dev.c
    //-----------------------------------------------------------------------------

    //端口镜像以后，应该不用进入混杂模式即可采集数据，关心tcp/udp即可吧？
    //mon_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    //mon_fd = socket(AF_INET, SOCK_RAW, htons(ETH_P_ALL));

    mon_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(mon_fd < 0)
        err(1, "Could not create packet socket");

    //-----------------------------------------------------------------------------
    // 传入Socket句柄，网卡ifname，获取网卡的interface_index
    //-----------------------------------------------------------------------------
    ifindex = get_device_ifindex(mon_fd, devname);

    //避免crontab启动时wifi未准备好引起的反复重启
    if(ifindex == -1)
    {
        sleep(30);
        wifiup();
        ifindex = get_device_ifindex(mon_fd, devname);
    }
    if(ifindex == -1)
        sys_reboot();

    //-----------------------------------------------------------------------------
    // 初始化sall
    //-----------------------------------------------------------------------------
    memset(&sall, 0, sizeof(struct sockaddr_ll));
    sall.sll_ifindex = ifindex;
    sall.sll_family = AF_PACKET;
    sall.sll_protocol = htons(ETH_P_ALL);

    //-----------------------------------------------------------------------------
    // 将Socket句柄与sall绑定
    //-----------------------------------------------------------------------------
    ret = bind(mon_fd, (struct sockaddr *)&sall, sizeof(sall));
    if(ret != 0)
        err(1, "bind failed");

    //-----------------------------------------------------------------------------
    // 将网卡设置为混杂模式(PROMISC)
    //-----------------------------------------------------------------------------
    //set_device_promisc_mode_onoff(mon_fd, devname, 1);

    //-----------------------------------------------------------------------------
    // 如果启动参数里有设置要求，修改Socket的接收缓冲区大小
    //-----------------------------------------------------------------------------
    if(recv_buffer_size)
        set_receive_buffer(mon_fd, recv_buffer_size);

    return mon_fd;
}

//-----------------------------------------------------------------------------
// 传入Socket句柄，网卡ifname
//-----------------------------------------------------------------------------
/* struct ifreq
{
# define IFHWADDRLEN 6
# define IFNAMSIZ IF_NAMESIZE
    union
      {
        char ifrn_name[IFNAMSIZ]; //Interface name, e.g. "en0". 
      } ifr_ifrn;

    union
      {
        struct sockaddr ifru_addr;
        struct sockaddr ifru_dstaddr;
        struct sockaddr ifru_broadaddr;
        struct sockaddr ifru_netmask;
        struct sockaddr ifru_hwaddr;
        short int ifru_flags;
        int ifru_ivalue;
        int ifru_mtu;
        struct ifmap ifru_map;
        char ifru_slave[IFNAMSIZ]; //Just fits the size 
        char ifru_newname[IFNAMSIZ];
         __caddr_t ifru_data;
      } ifr_ifru;
}; */

/*  if_arp.h
#define ARPHRD_IEEE802_TR 800            //Magic type ident for TR      
#define ARPHRD_IEEE80211 801             //IEEE 802.11                  
#define ARPHRD_IEEE80211_PRISM 802       //IEEE 802.11 + Prism2 header  
#define ARPHRD_IEEE80211_RADIOTAP 803    //IEEE 802.11 + radiotap header 
*/
//-----------------------------------------------------------------------------
// 获取当前网络的工作模式
//-----------------------------------------------------------------------------
int get_device_arptype(int fd, char *ifname)
{
    struct ifreq ifr;

    //初始化变量
    memset(&ifr, 0, sizeof(ifr));
    //ifname赋值
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

    //获取接口地址的相关参数[SIOCGIFHWADDR]
    if(ioctl(fd, SIOCGIFHWADDR, &ifr) < 0)
        err(1, "Could not get arptype");

    return ifr.ifr_hwaddr.sa_family;
}

int diff_timeval(struct timeval s, struct timeval e)
{
    unsigned long diff;

    diff = (e.tv_sec - s.tv_sec) * 1000000 + e.tv_usec - s.tv_usec;

    return (diff);
}

void fprint_packet_raw(const unsigned char *buf, int len)
{
    int i, j;

    fdebug(DEBUG_LEVEL_PACKET_RAW, "---------[packet_len=%04d]-------------", len);

    j = 0;
    for(i = 0; i < len; i++)
    {
        if((i % 2) == 0)
            fdebug(DEBUG_LEVEL_PACKET_RAW, " ");
        if((i % 16) == 0)
        {
            fdebug(DEBUG_LEVEL_PACKET_RAW, " %d\n", j);
            j++;
        }
        fdebug(DEBUG_LEVEL_PACKET_RAW, "%02x", buf[i]);
    }

    fdebug(DEBUG_LEVEL_PACKET_RAW, "\n");



}



//-----------------------------------------------------------------------------
// 调用recv接收帧
//-----------------------------------------------------------------------------
int recv_packet(int fd, unsigned char *buffer, size_t bufsize)
{
    // MSG_DONTWAIT
    // 它的作用是告诉recv()函数如果有数据到来的话就接受全部数据并立刻返回，
    // 没有数据的话也是立刻返回，而不进行任何的等待。
    return recv(fd, buffer, bufsize, MSG_DONTWAIT);
}

//类型编号
//类型名称
//mac1，mac2，mac3
//帧类型：定义在main.h
//信号强度
//噪声强度
//信噪比
//字节长度
//速率
//tsf
//essid,模式，信道，是否加密
//源自IP，目的IP
//-----------------------------------------------------------------------------
// 写文件
//-----------------------------------------------------------------------------
static void fprint_packet(struct packet_info *p)
{
    struct timeval nowtime;
    struct tm *t;
    //int SeqNub,FragNub;

    //BEACON,CTS,RTS,ACK 自动过滤
    /*
       if ((p->wlan_type==0x0080)||((p->wlan_type==0x00c4))||
       ((p->wlan_type==0x00b4))||(p->wlan_type==0x00d4))
       return;
     */

    gettimeofday(&nowtime, NULL);
    t = localtime(&nowtime.tv_sec);

    fprintf(PACKETLOG, "%04d-%02d-%02d %02d:%02d:%02d,", (t->tm_year + 1900),
            (t->tm_mon + 1), t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);

    fprintf(PACKETLOG, "%07d, ", packet_count);
    //fprintf(PACKETLOG, "%04x, ", p->pkt_fc);
    //fprintf(PACKETLOG, "%04x, %8s, ", p->wlan_type, get_packet_type_name(p->wlan_type));
    //fprintf(PACKETLOG, "%03d, ", p->ap_ecypt);
    //fprintf(PACKETLOG, "%4d, ", ((p->wlan_seqno) >> 4));
    //fprintf(PACKETLOG, "%2d, ", ((p->wlan_seqno) & 0x000f));
    fprintf(PACKETLOG, "%s, ", ether_sprintf(p->wlan_src));
    fprintf(PACKETLOG, "%s, ", ether_sprintf(p->wlan_dst));
    //fprintf(PACKETLOG, "%s, ", ether_sprintf(p->wlan_bssid));
    //fprintf(PACKETLOG, "%05x, %3d, %3d, %3d, %5d, %3d, %2d, ", p->pkt_types,
    //        p->phy_signal, p->phy_noise, p->phy_snr, p->wlan_len, p->phy_rate, p->phy_chan);
    //fprintf(PACKETLOG, "%016llx, ", (unsigned long long)p->wlan_tsf);
    //fprintf(PACKETLOG, "%16s, %3d, %2d, %d, ", p->wlan_essid, p->wlan_mode,
    //        p->wlan_channel, p->wlan_wep);
    fprintf(PACKETLOG, "%16s, ", ip_sprintf(p->ip_src));
    fprintf(PACKETLOG, "%16s, ", ip_sprintf(p->ip_dst));
    fprintf(PACKETLOG, "%d, %d\n", p->port_src, p->port_dst);

}

//打印帧列表的列名
static void fprint_packet_column()
{
/*	
    fprintf(PACKETLOG, "[             time],[index],[ fc],[typ], [t_name], [        src_mac], [        dst_mac],");
    fprintf(PACKETLOG, "[           bssid],[p_ty][sig][nos][snr] [len][rate][ch],");
    fprintf(PACKETLOG, "[            tsf],[          essid],[mod][chan][wep]");
    fprintf(PACKETLOG, "[     src_ip],[         dst_ip],[],[],[]\n");
*/
}

//-----------------------------------------------------------------------------
//处理包
//-----------------------------------------------------------------------------
void handle_packet(struct packet_info *p)
{

    // filter on server side only 
    /*
       if (!conf.serveraddr && filter_packet(p)) {
       if (!conf.quiet && !conf.paused)
       update_display_clock();
       return;
       }
     */

    /*
       if (cli_fd != -1)
       net_send_packet(p);
     */

    if(conf.debug_level)
    {
        fprint_packet_parser(p);
    }

    fdebug(DEBUG_LEVEL_PARSER_LOG, "########################################\n\n");

    update_wifilog(p);

    //写文件    
    if(conf.do_log_packetlist)
    {
        fprint_packet(p);
    }
}

//-----------------------------------------------------------------------------
// 接收帧
//-----------------------------------------------------------------------------
static void local_receive_packet(int fd, unsigned char *buffer, size_t bufsize)
{
    int len;
    int parse_result;

    len = recv_packet(fd, buffer, bufsize);

    if(len < 0)
    {
        //#define   EDEADLK     11      /* Resource deadlock avoided */
        //#define EAGAIN          11 /* Try again */ 
        printf("recv error: %d (%d)\n", len, errno);
        //return;
    }
#ifdef _DEBUG
    if(len > max_packet_len)
        max_packet_len = len;
#endif
    //更新帧索引
    packet_count++;

    fdebug(DEBUG_LEVEL_PARSER_LOG, "\n\n");
    fdebug(DEBUG_LEVEL_PARSER_LOG, "$$$$$$$$$[packet_idx=%07d]$$$$$$$$$$\n", packet_count);

    fprint_packet_raw(buffer, len);

    //初始化指针
    memset(&newpacket, 0, sizeof(struct packet_info));

    //----------------------------------------------------------------------------
    // 解析帧
    //----------------------------------------------------------------------------
    parse_result = parse_packet(buffer, len, &newpacket);

    switch (parse_result)
    {
    case 1:
        handle_packet(&newpacket);
        break;
    case 0:
        fdebug(DEBUG_LEVEL_PARSER_LOG, "parsing failed\n");
        break;
    case -1:
        invalid_fcs_packet_count++;
        fdebug(DEBUG_LEVEL_PARSER_LOG, "fcs_error\n");
        break;
    default:
        fdebug(DEBUG_LEVEL_PARSER_LOG, "others_error\n");
        break;
    }

}

/*
int net_receive(int fd)
{
    int len;
    unsigned char buf[256];

    len = recv(fd, buf, 256, MSG_DONTWAIT);

    if(len < 0)
        return 0;

    printf("receive data, len: %d\n", len);

    return len;
}
*/

//------------------------------------------------------------------------------
// 轮询接收数据
//------------------------------------------------------------------------------
static int select_capture(void)
{
    int ret;

    char bCap;

    bCap = 0;

    //-------------------------------------------------------------------------
    //系统提供select函数来实现多路复用输入/输出模型
    //#include <sys/time.h> 
    //#include <unistd.h>
    //-------------------------------------------------------------------------
    //异步套接字基础操作
    //-------------------------------------------------------------------------
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    FD_ZERO(&excpt_fds);

    /* 监控 */
    FD_SET(mon, &read_fds);

    /* select 超时时间 1ms */
    tv_select.tv_sec = 0;
    tv_select.tv_usec = 1000;

    mfd = mfd + 1;

    //int select(int maxfd,fd_set *rdset,fd_set *wrset,fd_set *exset,struct timeval *timeout);
    //参数maxfd是需要监视的最大的文件描述符值+1；
    //rdset,wrset,exset分别对应于需要检测的可读文件描述符的集合，可写文件描述符的集合及异常文件描述符的集合。
    //struct timeval结构用于描述一段时间长度，如果在这个时间内，需要监视的描述符没有事件发生则函数返回，返回值为0。
    /*
       struct timeval* timeout是select的超时时间，这个参数至关重要，它可以使select处于三种状态:
       第一，若将NULL以形参传入，即不传入时间结构，就是将select置于阻塞状态，一定等到监视文件描述符集合中某个文件描述符发生变化为止；
       第二，若将时间值设为0秒0毫秒，就变成一个纯粹的非阻塞函数，不管文件描述符是否有变化，都立刻返回继续执行，文件无变化返回0，有变化返回一个正值；
       第三，timeout的值大于0，这就是等待的超时时间，即 select在timeout时间内阻塞，超时时间之内有事件到来就返回了，否则在超时后不管怎样一定返回，返回值同上述。
     */
    ret = select(mfd, &read_fds, &write_fds, &excpt_fds, &tv_select);

    // 出现错误，被中断interrupted 
    if(ret == -1 && errno == EINTR)
    {
        printf("E");
        return 0;
    }
    // timeout时间内select无数据，直接返回
    if(ret == 0)
    {
        //printf("O");

#ifdef _DEBUG
        get_o++;
#endif
        /* todo 如果长时间超时，可以考虑重启设备，在此处实现比较好 */
        return 0;

    } else if(ret < 0)                 //其他非EINTR出错
    {
        err(1, "select()");

    }

    /* 采集数据接口有新数据收到 */
    if(FD_ISSET(mon, &read_fds))
    {
#ifdef _DEBUG
        get_i++;
#endif
        //printf("[*]");
        local_receive_packet(mon, buffer, sizeof(buffer));
        bCap = 1;
    }

    return bCap;
}

/*
  Channel 01: 241200000MHz
  Channel 02: 241700000MHz
  Channel 03: 242200000MHz
  Channel 04: 242700000MHz
  Channel 05: 243200000MHz
  Channel 06: 243700000MHz
  Channel 07: 244200000MHz
  Channel 08: 244700000MHz
  Channel 09: 245200000MHz
  Channel 10: 245700000MHz
  Channel 11: 246200000MHz
  Channel 12: 246700000MHz
  Channel 13: 247200000MHz
  Channel 14: 248400000MHz
*/

//struct tm
//{
//  int tm_sec;                   /* Seconds.     [0-60] (1 leap second) */
//  int tm_min;                   /* Minutes.     [0-59] */
//  int tm_hour;                  /* Hours.       [0-23] */
//  int tm_mday;                  /* Day.         [1-31] */
//  int tm_mon;                   /* Month.       [0-11] */
//  int tm_year;                  /* Year - 1900.  */
//  int tm_wday;                  /* Day of week. [0-6] */
//  int tm_yday;                  /* Days in year.[0-365] */
//  int tm_isdst;                 /* DST.         [-1/0/1]*/
//#ifdef  __USE_BSD
//  long int tm_gmtoff;           /* Seconds east of UTC.  */
//  __const char *tm_zone;        /* Timezone abbreviation.  */
//#else
//  long int __tm_gmtoff;         /* Seconds east of UTC.  */
//  __const char *__tm_zone;      /* Timezone abbreviation.  */
//#endif
//};

//根据当前时间产生时间戳字符串  2012_01_01_23_59_59
int get_time_stamp(char *timestr)
{
    struct timeval nowtime;
    struct tm *p;

    gettimeofday(&nowtime, NULL);
    p = localtime(&nowtime.tv_sec);

    sprintf(timestr, "%04d_%02d_%02d_%02d_%02d_%02d", (p->tm_year + 1900),
            (p->tm_mon + 1), p->tm_mday, p->tm_hour, p->tm_min, p->tm_sec);

    return 1;
}

//只考虑小写情况                                                     
int char_to_int(unsigned char c)
{
    if((c >= '0') && (c <= '9'))
        return (c - '0');
    else if((c >= 'a') && (c <= 'f'))
        return (c - 'a' + 10);
    else
        return 0;

}

int start_mon(void)
{
    char timestamp[20];

    char packetfilename[64];
    char parserfilename[64];

    /*
       t_begin = time(NULL);        
       local = localtime(&t_begin); 
       printf("now_time: %04d-%02d-%02d_%02d:%02d:%02d\n", (local->tm_year + 1900),
       (local->tm_mon + 1), local->tm_mday, local->tm_hour, local->tm_min, local->tm_sec);
     */


#ifdef _DEBUG
    get_i = 0;
    get_ii = 0;
    get_o = 0;
    get_oo = 0;
    get_all = 0;

    max_packet_len = 0;

    gettimeofday(&get_time, NULL);
#endif

    // 初始化包索引序号
    packet_count = 0;

    // FCS校验失败帧技术
    invalid_fcs_packet_count = 0;

#ifdef _LOGPARSER
    //strcpy(conf.ifname, "mon0");
    strcpy(conf.ifname, "wlan0");
    conf.channel_default = channel;
    conf.debug_level = 0xffffffff;
    //conf.debug_level = DEBUG_LEVEL_PROTOCOL_UDP|DEBUG_LEVEL_PROTOCOL_TCP|DEBUG_LEVEL_PROTOCOL_HTTP|DEBUG_LEVEL_PACKET_INFO;
    //conf.debug_level = DEBUG_LEVEL_MIN|DEBUG_LEVEL_PROTOCOL_HTTP;
    if((device_idx == 2) || (device_idx == 3) || (device_idx == 4))
        conf.do_change_channel = 0;
    else
        conf.do_change_channel = enable_switch;
    conf.change_channel_interval = switch_interval;
#else
    strcpy(conf.ifname, "wlan0-1");
    conf.channel_default = channel;
    conf.debug_level = 0;
    if((device_idx == 2) || (device_idx == 3))
        conf.do_change_channel = 0;
    else
        conf.do_change_channel = enable_switch;
    conf.change_channel_interval = switch_interval;
#endif

#ifdef _LOGPACKET
    conf.do_log_packetlist = 1;
#else
    conf.do_log_packetlist = 0;
#endif

    // 初始化统计数据结构

    printf("\n");


    if(get_eth0_mac(eth0_mac) == 1)
	{
		printf("eth0_mac: %s\n", ether_sprintf(eth0_mac));
	}

    if(get_eth1_mac(eth1_mac) == 1)
    {
	    printf("eth1_mac: %s\n", ether_sprintf(eth1_mac));
    }
	if(get_wlan0_mac(wlan0_mac) == 1)
    {
	    printf("wlan0_mac: %s\n", ether_sprintf(wlan0_mac));
    }
    

    //根据CPU串号也是不错的识别方式
    //在某个隐藏目录下部署一个版权验证码+MAC地址校验
/*
    memset(eth0_mac, 0x00, 6);
    if(get_eth0_mac(eth0_mac) == 1)
    {
#ifdef _DEBUG
        printf("eth0_mac = %02x:%02x:%02x:%02x:%02x:%02x\n", eth0_mac[0], eth0_mac[1], eth0_mac[2],
               eth0_mac[3], eth0_mac[4], eth0_mac[5]);
#endif
        if((MAC_EQUAL(eth0_mac, VALID_MAC_01)) ||
           (MAC_EQUAL(eth0_mac, VALID_MAC_02)) ||
           (MAC_EQUAL(eth0_mac, VALID_MAC_03)) ||
           (MAC_EQUAL(eth0_mac, VALID_MAC_04)) ||
           (MAC_EQUAL(eth0_mac, VALID_MAC_05)) ||
           (MAC_EQUAL(eth0_mac, VALID_MAC_06)) ||
           (MAC_EQUAL(eth0_mac, VALID_MAC_07)) ||
           (MAC_EQUAL(eth0_mac, VALID_MAC_08)) ||
           (MAC_EQUAL(eth0_mac, VALID_MAC_09)) ||
           (MAC_EQUAL(eth0_mac, VALID_MAC_10)) ||
           (MAC_EQUAL(eth0_mac, VALID_MAC_11)) ||
           (MAC_EQUAL(eth0_mac, VALID_MAC_12)) || (MAC_VALID(eth0_mac)))
        {
            ;
        } else
        {
            printf("initial_error.\n");
#ifndef _DEBUG
            return 0;
#endif
        }
    } else
    {
        //printf("get eth0_mac failed.\n");
        return 0;                      //
    }
*/
    //b0 48 7a 51 0e 37     

    //CPU串号

    // 获取最新时间戳，生成测试总结文件
    // 2012_01_01_23_59_59
    get_time_stamp(&timestamp[0]);

    // 如果程序启动参数中带-p，则自动记录解析后的帧列表文件，为了方便分析
    // **会频繁写硬盘
    if(conf.do_log_packetlist)
    {
        // 帧列表文件
        sprintf(packetfilename, "%02x%02x%02x%02x%02x%02x_%s_packet.log",
                eth0_mac[0], eth0_mac[1], eth0_mac[2], eth0_mac[3], eth0_mac[4], eth0_mac[5],
                timestamp);
        printf("packet_filename:%s\n", packetfilename);

        PACKETLOG = fopen(packetfilename, "w");
        if(PACKETLOG == NULL)
            err(1, "couldn't open packetlog file");

        // 打印列名，为了查阅记录文件更方便
        fprint_packet_column();

    }
    //--------------------------------------------------------------------
    // 如果是详细调试模式
    // -l 支持32位整型，
    //--------------------------------------------------------------------
    if(conf.debug_level)
    {
        // 帧解析文件
        sprintf(parserfilename, "%02x%02x%02x%02x%02x%02x_%s_parser.log",
                eth0_mac[0], eth0_mac[1], eth0_mac[2], eth0_mac[3], eth0_mac[4], eth0_mac[5],
                timestamp);
        printf("parser_filename:%s\n", parserfilename);

        PARSERLOG = fopen(parserfilename, "w");
        if(PARSERLOG == NULL)
            err(1, "couldn't open parserlog file");
    }
    //----------------------------------------------------------------------------
    // 尝试打开指定的网卡
    // 输入参数：网卡ifname，buffer缓冲区大小，接收缓冲区大小（为系统配置）
    // 引用系统调用 socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))
    //----------------------------------------------------------------------------
    mon = open_packet_socket(conf.ifname, sizeof(buffer), conf.recv_buffer_size);
    if(mon <= 0)
        err(1, "Couldn't open packet socket");

    //-----------------------------------------------------------------------------
    //获取网卡的ARP类型
    //-----------------------------------------------------------------------------
    conf.arphrd = get_device_arptype(mon, conf.ifname);

    printf("device_arptype: %d\n", conf.arphrd);

    // 判断目前网卡的ARP类型
    if(conf.arphrd != ARPHRD_ETHER)
    {
        printf("wrong mode\n");
        return 0;
    }

/*
    // 判断目前网卡的ARP类型
    if(conf.arphrd != ARPHRD_IEEE80211_PRISM && conf.arphrd != ARPHRD_IEEE80211_RADIOTAP)
    {
        printf("wrong mode\n");

        return 0;
    }

    //--------------------------------------------------------------------
    // 获取当前网卡支持的通道数 
    // 函数执行时，初始化了channels列表
    // 并确定了网卡支持的通道数 conf.num_channels
    //--------------------------------------------------------------------
    conf.num_channels = wext_get_channels(mon, conf.ifname, channels);

    //--------------------------------------------------------------------
    // 获取网卡当前的工作频道
    //--------------------------------------------------------------------
    get_current_channel(mon);

    //设置为11号频点，看是否能接收到AAAAAA（1号频点）
    if(conf.channel_default > 0)
        change_channel(conf.channel_default - 1);
*/
    //--------------------------------------------------------------------
    // 初始化tv_last_channelchange时间
    //--------------------------------------------------------------------
    gettimeofday(&tv_last_channelchange, NULL);

    return 1;
}

int get_packet(void)
{
    int ret;

#ifdef _DEBUG
    struct timeval now;

    get_all++;

    if((get_all % 1000) == 0)
    {
        gettimeofday(&now, NULL);

        printf("[%07d][%07d][%07d][%07d][%07d][%d] %ld\n",
               get_all, get_i, get_o, get_i - get_ii, get_o - get_oo, max_packet_len,
               (now.tv_sec - get_time.tv_sec) * 1000000 + (now.tv_usec - get_time.tv_usec));

        get_ii = get_i;
        get_oo = get_o;
        gettimeofday(&get_time, NULL);
    }
#endif

    ret = select_capture();
    gettimeofday(&tv_now, NULL);
    //auto_change_channel(mon, conf.change_channel_interval);

    return ret;

}
