/*******************************************************************************
 *	Monitorģʽ�µ�802.11֡ɨ�����
 *	1.ȷ������������֧��monitorģʽ
 *	2.����ʱ����Ҫ������Ϊmonitorģʽ
 *	3.��ͬ�������������֡��ʽ���ܲ�ͬ
 *	
 *	todolist:
 *	1.֧��802.11n��ʽ
 *	2.�����꾡��ͳ��ָ��
 *	3.IP��Ľ���
 *	
 *	update
 *	12-08-03[5] 10_43_13 ieee802_11_parse_elems�������ڴ��������쳣��������
 *	12-08-14[2] 19_42_38 �Ľ���parse_radiotap_header�Ľ������������������Ϣ
 *  12-08-24[5] 16_48_08 ������apͳ����Ϣ���ź�ǿ�Ⱥ�����ȣ�
 
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
#include <signal.h>                    //Ϊ�˲���Ctrl+C���ź������˳�

#include <net/if_arp.h>

//-----------------------------------------------------------------------------
//�ػ��������з�ʽ��֧��
//-----------------------------------------------------------------------------
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>                     // �ļ����ƶ���
#include <syslog.h>                    // syslog����

#include <netdb.h>

//va_list
#include <stdarg.h>                    //��׼C�� standard argument(��׼����)

#include "main.h"
#include "readcfg.h"
#include "asdwifi.h"
#include "parser.h"
#include "util.h"


#include "wifilog.h"

#define MAC_VALID(_mac1) ((_mac1[0]==0x00)&&\
  (_mac1[1]==0x0f)&&(_mac1[2]==0xe2))

//-----------------------------------------------------------------------------
// ���ö���
// ��ʼֵ�ĳ�ʼ��
//-----------------------------------------------------------------------------
struct config conf = {
    .ifname = INTERFACE_NAME,          //wlan0��Ĭ�������ӿ���
    .debug_level = DEBUG_LEVEL_NONE,   //0 Ĭ�ϵ��Լ���Ϊ0
    .change_channel_interval = CHANGE_CHANNEL_INTERVAL, //10000
    .channel_default = CHANNEL_DEFAULT, //0 [1���ŵ�����0��ʼ��13]
    .recv_buffer_size = RECV_BUFFER_SIZE,   //0 not used by default 
};

/* �ļ�������������select */
int mon;                               /* ���fd */

int mfd = -1;

int bQuit = 0;

//ȫ�ֱ���
struct packet_info newpacket;          //��ؼ���֡���ݽṹ����

// �����֡���
int packet_count;
int invalid_fcs_packet_count;          //FCSУ��ʧ�ܵ�֡���

struct tm *local;
time_t t_begin, t_end;
int diff_time;

static FILE *PACKETLOG = NULL;         // ��־�ļ����
static FILE *PARSERLOG = NULL;         // ������־�ļ�

//-----------------------------------------------------------------------------
// for select 
//-----------------------------------------------------------------------------
static fd_set read_fds;
static fd_set write_fds;
static fd_set excpt_fds;

//-----------------------------------------------------------------------------
// ʱ����صı�������
//-----------------------------------------------------------------------------
static struct timeval tv_select;       //select��ʱʱ��
static struct timeval tv_now;
static struct timeval tv_last_channelchange;

//��������������MAC��ַ����Ϊ�豸��Ψһ��ʾ
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
// ��ѡ���ӡ������Ϣ
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
// ��ӡ�������֡��Ϣ
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

        //// OLSR��Optimized Link State Routing �ļ��
        //// ��Ҫ����MANET����(Mobile Ad hoc network)��·��Э�顣

        //fdebug(DEBUG_LEVEL_PACKET_INFO, "[%d], [%d], [%d]\n", p->olsr_type, p->olsr_neigh,
        //       p->olsr_tc);
    }

    return 0;

}

void wifiup(void)
{
    FILE *pipe_stream;

    //����wifi
    pipe_stream = popen("wifi", "r");
    if(pipe_stream == NULL)
    {
        perror("command error");
    }
    pclose(pipe_stream);
}

//-----------------------------------------------------------------------------
// ��ȡ��Ӧ�豸��ifindex 
//-----------------------------------------------------------------------------
static int get_device_ifindex(int fd, const char *devname)
{
    //������/usr/include/net/if.h
    struct ifreq req;

    //��ifname��ֵ��req
    strncpy(req.ifr_name, devname, IFNAMSIZ);
    req.ifr_addr.sa_family = AF_INET;

    //ϵͳ���ã����Ի���豸��Ӧ��������
    if(ioctl(fd, SIOCGIFINDEX, &req) < 0)
    {
        err(1, "ioctl SIOCGIFINDEX faild: %s", devname);
        return -1;
    }
    //û�ҵ�
    if(req.ifr_ifindex < 0)
        err(1, "Interface %s not found", devname);

    //printf("req.ifr_ifindex: %d\n", req.ifr_ifindex);
    return req.ifr_ifindex;
}

//-----------------------------------------------------------------------------
// �������ӿ�����Ϊ���ģʽ
//-----------------------------------------------------------------------------
/*
static void set_device_promisc_mode_onoff(int fd, const char *devname, int on)
{
    struct ifreq req;

    //��ֵifr_name
    strncpy(req.ifr_name, devname, IFNAMSIZ);
    req.ifr_addr.sa_family = AF_INET;

    //����ifr_name��ȡ�ӿڱ�־
    if(ioctl(fd, SIOCGIFFLAGS, &req) < 0)
        err(1, "Could not get device flags for %s", devname);

    // ˳�����������
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
// ����ϵͳtcpip��socket����buffersize
//-----------------------------------------------------------------------------
static void set_receive_buffer(int fd, int sockbufsize)
{
    int ret;

    // the maximum allowed value is set by the rmem_max sysctl 
    // �޸�ϵͳ����
    // ��������TCP���ݽ��ջ���
    FILE *PF = fopen("/proc/sys/net/core/rmem_max", "w");
    fprintf(PF, "%d", sockbufsize);
    fclose(PF);

    // ����Soeckt����
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
// ����socket
//-----------------------------------------------------------------------------
int open_packet_socket(char *devname, size_t bufsize, int recv_buffer_size)
{
    int ret;
    int mon_fd;                        //socket���
    int ifindex;

    // �����ڣ�netpacket/packet.h
    struct sockaddr_ll sall;

    //-----------------------------------------------------------------------------
    // ϵͳ����Socket����
    // domain:PF_PACKET���Ͳ����ӿڣ����ں˵�CONFIG_PACKET_MMAP�����й�
    // type:SOCK_RAW���ṩԭʼ������Э����ʣ���ʾץȡ���İ���������IP��
    // protocol:ETH_P_ALL ��ʾץȡ������̫֡
    //
    // ��ͨ��socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))������������·�����ݰ�ʱ���ں˻����ȵ���packet_create�����׽��֡�
    // net/packet/af_packet.c
    // ������ͨ��socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))�������׽��ֺ󣬾��ܲ��񵽵�����·����������ݰ���
    // ���������ͨ��������ʽ���������óɻ���ģʽ�����ܲ������������е����ݰ���
    // net/dev/dev.c
    //-----------------------------------------------------------------------------

    //�˿ھ����Ժ�Ӧ�ò��ý������ģʽ���ɲɼ����ݣ�����tcp/udp���ɰɣ�
    //mon_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    //mon_fd = socket(AF_INET, SOCK_RAW, htons(ETH_P_ALL));

    mon_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(mon_fd < 0)
        err(1, "Could not create packet socket");

    //-----------------------------------------------------------------------------
    // ����Socket���������ifname����ȡ������interface_index
    //-----------------------------------------------------------------------------
    ifindex = get_device_ifindex(mon_fd, devname);

    //����crontab����ʱwifiδ׼��������ķ�������
    if(ifindex == -1)
    {
        sleep(30);
        wifiup();
        ifindex = get_device_ifindex(mon_fd, devname);
    }
    if(ifindex == -1)
        sys_reboot();

    //-----------------------------------------------------------------------------
    // ��ʼ��sall
    //-----------------------------------------------------------------------------
    memset(&sall, 0, sizeof(struct sockaddr_ll));
    sall.sll_ifindex = ifindex;
    sall.sll_family = AF_PACKET;
    sall.sll_protocol = htons(ETH_P_ALL);

    //-----------------------------------------------------------------------------
    // ��Socket�����sall��
    //-----------------------------------------------------------------------------
    ret = bind(mon_fd, (struct sockaddr *)&sall, sizeof(sall));
    if(ret != 0)
        err(1, "bind failed");

    //-----------------------------------------------------------------------------
    // ����������Ϊ����ģʽ(PROMISC)
    //-----------------------------------------------------------------------------
    //set_device_promisc_mode_onoff(mon_fd, devname, 1);

    //-----------------------------------------------------------------------------
    // �������������������Ҫ���޸�Socket�Ľ��ջ�������С
    //-----------------------------------------------------------------------------
    if(recv_buffer_size)
        set_receive_buffer(mon_fd, recv_buffer_size);

    return mon_fd;
}

//-----------------------------------------------------------------------------
// ����Socket���������ifname
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
// ��ȡ��ǰ����Ĺ���ģʽ
//-----------------------------------------------------------------------------
int get_device_arptype(int fd, char *ifname)
{
    struct ifreq ifr;

    //��ʼ������
    memset(&ifr, 0, sizeof(ifr));
    //ifname��ֵ
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

    //��ȡ�ӿڵ�ַ����ز���[SIOCGIFHWADDR]
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
// ����recv����֡
//-----------------------------------------------------------------------------
int recv_packet(int fd, unsigned char *buffer, size_t bufsize)
{
    // MSG_DONTWAIT
    // ���������Ǹ���recv()������������ݵ����Ļ��ͽ���ȫ�����ݲ����̷��أ�
    // û�����ݵĻ�Ҳ�����̷��أ����������κεĵȴ���
    return recv(fd, buffer, bufsize, MSG_DONTWAIT);
}

//���ͱ��
//��������
//mac1��mac2��mac3
//֡���ͣ�������main.h
//�ź�ǿ��
//����ǿ��
//�����
//�ֽڳ���
//����
//tsf
//essid,ģʽ���ŵ����Ƿ����
//Դ��IP��Ŀ��IP
//-----------------------------------------------------------------------------
// д�ļ�
//-----------------------------------------------------------------------------
static void fprint_packet(struct packet_info *p)
{
    struct timeval nowtime;
    struct tm *t;
    //int SeqNub,FragNub;

    //BEACON,CTS,RTS,ACK �Զ�����
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

//��ӡ֡�б������
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
//�����
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

    //д�ļ�    
    if(conf.do_log_packetlist)
    {
        fprint_packet(p);
    }
}

//-----------------------------------------------------------------------------
// ����֡
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
    //����֡����
    packet_count++;

    fdebug(DEBUG_LEVEL_PARSER_LOG, "\n\n");
    fdebug(DEBUG_LEVEL_PARSER_LOG, "$$$$$$$$$[packet_idx=%07d]$$$$$$$$$$\n", packet_count);

    fprint_packet_raw(buffer, len);

    //��ʼ��ָ��
    memset(&newpacket, 0, sizeof(struct packet_info));

    //----------------------------------------------------------------------------
    // ����֡
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
// ��ѯ��������
//------------------------------------------------------------------------------
static int select_capture(void)
{
    int ret;

    char bCap;

    bCap = 0;

    //-------------------------------------------------------------------------
    //ϵͳ�ṩselect������ʵ�ֶ�·��������/���ģ��
    //#include <sys/time.h> 
    //#include <unistd.h>
    //-------------------------------------------------------------------------
    //�첽�׽��ֻ�������
    //-------------------------------------------------------------------------
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    FD_ZERO(&excpt_fds);

    /* ��� */
    FD_SET(mon, &read_fds);

    /* select ��ʱʱ�� 1ms */
    tv_select.tv_sec = 0;
    tv_select.tv_usec = 1000;

    mfd = mfd + 1;

    //int select(int maxfd,fd_set *rdset,fd_set *wrset,fd_set *exset,struct timeval *timeout);
    //����maxfd����Ҫ���ӵ������ļ�������ֵ+1��
    //rdset,wrset,exset�ֱ��Ӧ����Ҫ���Ŀɶ��ļ��������ļ��ϣ���д�ļ��������ļ��ϼ��쳣�ļ��������ļ��ϡ�
    //struct timeval�ṹ��������һ��ʱ�䳤�ȣ���������ʱ���ڣ���Ҫ���ӵ�������û���¼������������أ�����ֵΪ0��
    /*
       struct timeval* timeout��select�ĳ�ʱʱ�䣬�������������Ҫ��������ʹselect��������״̬:
       ��һ������NULL���βδ��룬��������ʱ��ṹ�����ǽ�select��������״̬��һ���ȵ������ļ�������������ĳ���ļ������������仯Ϊֹ��
       �ڶ�������ʱ��ֵ��Ϊ0��0���룬�ͱ��һ������ķ����������������ļ��������Ƿ��б仯�������̷��ؼ���ִ�У��ļ��ޱ仯����0���б仯����һ����ֵ��
       ������timeout��ֵ����0������ǵȴ��ĳ�ʱʱ�䣬�� select��timeoutʱ������������ʱʱ��֮�����¼������ͷ����ˣ������ڳ�ʱ�󲻹�����һ�����أ�����ֵͬ������
     */
    ret = select(mfd, &read_fds, &write_fds, &excpt_fds, &tv_select);

    // ���ִ��󣬱��ж�interrupted 
    if(ret == -1 && errno == EINTR)
    {
        printf("E");
        return 0;
    }
    // timeoutʱ����select�����ݣ�ֱ�ӷ���
    if(ret == 0)
    {
        //printf("O");

#ifdef _DEBUG
        get_o++;
#endif
        /* todo �����ʱ�䳬ʱ�����Կ��������豸���ڴ˴�ʵ�ֱȽϺ� */
        return 0;

    } else if(ret < 0)                 //������EINTR����
    {
        err(1, "select()");

    }

    /* �ɼ����ݽӿ����������յ� */
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

//���ݵ�ǰʱ�����ʱ����ַ���  2012_01_01_23_59_59
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

//ֻ����Сд���                                                     
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

    // ��ʼ�����������
    packet_count = 0;

    // FCSУ��ʧ��֡����
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

    // ��ʼ��ͳ�����ݽṹ

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
    

    //����CPU����Ҳ�ǲ����ʶ��ʽ
    //��ĳ������Ŀ¼�²���һ����Ȩ��֤��+MAC��ַУ��
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

    //CPU����

    // ��ȡ����ʱ��������ɲ����ܽ��ļ�
    // 2012_01_01_23_59_59
    get_time_stamp(&timestamp[0]);

    // ����������������д�-p�����Զ���¼�������֡�б��ļ���Ϊ�˷������
    // **��Ƶ��дӲ��
    if(conf.do_log_packetlist)
    {
        // ֡�б��ļ�
        sprintf(packetfilename, "%02x%02x%02x%02x%02x%02x_%s_packet.log",
                eth0_mac[0], eth0_mac[1], eth0_mac[2], eth0_mac[3], eth0_mac[4], eth0_mac[5],
                timestamp);
        printf("packet_filename:%s\n", packetfilename);

        PACKETLOG = fopen(packetfilename, "w");
        if(PACKETLOG == NULL)
            err(1, "couldn't open packetlog file");

        // ��ӡ������Ϊ�˲��ļ�¼�ļ�������
        fprint_packet_column();

    }
    //--------------------------------------------------------------------
    // �������ϸ����ģʽ
    // -l ֧��32λ���ͣ�
    //--------------------------------------------------------------------
    if(conf.debug_level)
    {
        // ֡�����ļ�
        sprintf(parserfilename, "%02x%02x%02x%02x%02x%02x_%s_parser.log",
                eth0_mac[0], eth0_mac[1], eth0_mac[2], eth0_mac[3], eth0_mac[4], eth0_mac[5],
                timestamp);
        printf("parser_filename:%s\n", parserfilename);

        PARSERLOG = fopen(parserfilename, "w");
        if(PARSERLOG == NULL)
            err(1, "couldn't open parserlog file");
    }
    //----------------------------------------------------------------------------
    // ���Դ�ָ��������
    // �������������ifname��buffer��������С�����ջ�������С��Ϊϵͳ���ã�
    // ����ϵͳ���� socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))
    //----------------------------------------------------------------------------
    mon = open_packet_socket(conf.ifname, sizeof(buffer), conf.recv_buffer_size);
    if(mon <= 0)
        err(1, "Couldn't open packet socket");

    //-----------------------------------------------------------------------------
    //��ȡ������ARP����
    //-----------------------------------------------------------------------------
    conf.arphrd = get_device_arptype(mon, conf.ifname);

    printf("device_arptype: %d\n", conf.arphrd);

    // �ж�Ŀǰ������ARP����
    if(conf.arphrd != ARPHRD_ETHER)
    {
        printf("wrong mode\n");
        return 0;
    }

/*
    // �ж�Ŀǰ������ARP����
    if(conf.arphrd != ARPHRD_IEEE80211_PRISM && conf.arphrd != ARPHRD_IEEE80211_RADIOTAP)
    {
        printf("wrong mode\n");

        return 0;
    }

    //--------------------------------------------------------------------
    // ��ȡ��ǰ����֧�ֵ�ͨ���� 
    // ����ִ��ʱ����ʼ����channels�б�
    // ��ȷ��������֧�ֵ�ͨ���� conf.num_channels
    //--------------------------------------------------------------------
    conf.num_channels = wext_get_channels(mon, conf.ifname, channels);

    //--------------------------------------------------------------------
    // ��ȡ������ǰ�Ĺ���Ƶ��
    //--------------------------------------------------------------------
    get_current_channel(mon);

    //����Ϊ11��Ƶ�㣬���Ƿ��ܽ��յ�AAAAAA��1��Ƶ�㣩
    if(conf.channel_default > 0)
        change_channel(conf.channel_default - 1);
*/
    //--------------------------------------------------------------------
    // ��ʼ��tv_last_channelchangeʱ��
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
