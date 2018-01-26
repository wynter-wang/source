#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <ctype.h>

#include "main.h"
#include "asdwifi.h"
//#include "ieee80211_prism.h"
//#include "radiotap.h"
//#include "radiotap_iter.h"
//#include "ieee80211.h"

#include "wifilog.h"

#include "util.h"
//#include "ieee80211_util.h"
//#include "crc32.h"

const unsigned char NULL_MAC1[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
const unsigned char FFFF_MAC1[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

//#define FCS_LEN 0 //ralink驱动不含FCS

#define FCS_LEN 4

extern FILE *PCAPLOG;

extern unsigned char eth1_mac[6];
extern unsigned char wlan0_mac[6];

//全局变量，在ip层存数据帧头，在tcp解析函数中保持pcap文件是引用
struct iphdr iphead;



static int parse_ether_header(unsigned char **buf, int len, struct packet_info *p);
static int parse_ip_header(unsigned char **buf, int len, struct packet_info *p);
static int parse_udp_header(unsigned char **buf, int len, struct packet_info *p);

static int parse_tcp_header(unsigned char **buf, int len, struct packet_info *p);
static int parse_icmp_header(unsigned char **buf, int len, struct packet_info *p);
void urldecode(char *p)         //URL解码程序
{
	int i=0;
	while(*(p+i))
	{
		if ((*p=*(p+i)) == '%')
		{
			*p=*(p+i+1) >= 'A' ? ((*(p+i+1) & 0XDF) - 'A') + 10 : (*(p+i+1) - '0');
			*p=(*p) * 16;
			*p+=*(p+i+2) >= 'A' ? ((*(p+i+2) & 0XDF) - 'A') + 10 : (*(p+i+2) - '0');
			i+=2;
		}
		else if (*(p+i)=='+')
		{
			*p=' ';
		}
		p++;
	}
	*p='\0';
}
char * ASCdecode(char *s)
{
	int i = 0;
	char buf[64];
	char key[64];
	memset(buf, 0x00, 64);
	memset(key, 0x00, 64);
	for (i = 0; i < strlen(s); i++)
	{
		sprintf(key,"%c",s[i]);
		strcat(buf,key);
	}
//	printf(buf);
	memcpy(s, buf, 64);
	return s;
}
/* return 1 if we parsed enough = min ieee header */
int parse_packet(unsigned char *buf, int len, struct packet_info *p)
{
	//fdebug(DEBUG_LEVEL_80211_HEAD, "--------CHECK_CRC32_FOR_FCS-------------\n");

	//以太网包头  目标MAC地址，源MAC地址，以太网帧长度 xxxx CRC校验

	len = parse_ether_header(&buf, len, p);
	if(len <= 0)
		return 1;
	//buf = buf + 14;

	/* 解析IP层的信息 */
	len = parse_ip_header(&buf, len, p);
	if(len <= 0)
		return 1;

	if(p->pkt_types & PKT_TYPE_ICMP)
	{
		/* 解析ICMP层的信息 */
		len = parse_icmp_header(&buf, len, p);
		if(len <= 0)
			return 1;
	}

	if(p->pkt_types & PKT_TYPE_UDP)
	{
		/* 解析UDP层的信息 */
		len = parse_udp_header(&buf, len, p);
		if(len <= 0)
			return 1;
	}

	if(p->pkt_types & PKT_TYPE_TCP)
	{
		/* 解析TCP层的信息 */
		len = parse_tcp_header(&buf, len, p);
		if(len <= 0)
			return 1;
	}

	return 1;
}

static int parse_ether_header(unsigned char **buf, int len, struct packet_info *p)
{

	memcpy(p->wlan_dst, *buf, MAC_LEN);
	memcpy(p->wlan_src, *buf + 6, MAC_LEN);

	/*
	   一个0x0800的以太类型说明这个帧包含的是IPv4数据报。
	   同样的，一个0x0806的以太类型说明这个帧是一个ARP帧
	   0x8100说明这是一个IEEE 802.1Q帧，而0x86DD说明这是一个IPv6帧。
	 */

	/*
	EtherType: 86dd
	EtherType: 0806
	EtherType: 0006
	EtherType: 888e

	*/
	fdebug(DEBUG_LEVEL_PROTOCOL_IP, "---------CHECK_ETHER_TYPE---------------\n");
	fdebug(DEBUG_LEVEL_PROTOCOL_IP, "EtherType: %02x%02x \n", (*buf)[12], (*buf)[13]);

	if(((*buf)[12]==0x08)&&((*buf)[13]==0x00))
	{
		*buf = *buf + 14;
		return len - 14;
	}
	else
		return 0;


}

/*
struct iphdr {

	#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t ihl:4,
	version:4;
	#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t version:4,
	ihl:4;
	#endif
							//4
							//5*4=20字节，最大15*4=60字节。表示IP包头最大长度20字节
	uint8_t tos; 			//Type of Service，服务类型
	uint16_t tot_len; 		//
	uint16_t id; 			//
	uint16_t frag_off; 		//
	uint8_t ttl; 			//Time To Live
	uint8_t protocol; 		//协议类型，具体参见下面
	uint16_t check; 		//checksum
	uint32_t saddr; 		//源地址
	uint32_t daddr; 		//目标地址

	//The options start here.
};

*/

/* Standard well-defined IP protocols.  */

// enum {
//   IPPROTO_IP = 0,              /* Dummy protocol for TCP               */
//   IPPROTO_ICMP = 1,            /* Internet Control Message Protocol    */
//   IPPROTO_IGMP = 2,            /* Internet Group Management Protocol   */
//   IPPROTO_IPIP = 4,            /* IPIP tunnels (older KA9Q tunnels use 94) */
//   IPPROTO_TCP = 6,             /* Transmission Control Protocol        */
//   IPPROTO_EGP = 8,             /* Exterior Gateway Protocol            */
//   IPPROTO_PUP = 12,            /* PUP protocol                         */
//   IPPROTO_UDP = 17,            /* User Datagram Protocol               */
//   IPPROTO_IDP = 22,            /* XNS IDP protocol                     */
//   IPPROTO_DCCP = 33,           /* Datagram Congestion Control Protocol */
//   IPPROTO_RSVP = 46,           /* RSVP protocol                        */
//   IPPROTO_GRE = 47,            /* Cisco GRE tunnels (rfc 1701,1702)    */
//
//   IPPROTO_IPV6   = 41,         /* IPv6-in-IPv4 tunnelling              */
//
//   IPPROTO_ESP = 50,            /* Encapsulation Security Payload protocol */
//   IPPROTO_AH = 51,             /* Authentication Header protocol       */
//   IPPROTO_BEETPH = 94,         /* IP option pseudo header for BEET */
//   IPPROTO_PIM    = 103,         /* Protocol Independent Multicast       */
//
//   IPPROTO_COMP   = 108,          /* Compression Header protocol */
//   IPPROTO_SCTP   = 132,        /* Stream Control Transport Protocol    */
//   IPPROTO_UDPLITE = 136,       /* UDP-Lite (RFC 3828)                  */
//
//   IPPROTO_RAW    = 255,        /* Raw IP packets                       */
//   IPPROTO_MAX
// };

//典型数据
//4500 003c 7f41 4000 4006 241c c0a8 0b0d  1
//c0a8 0b01 a660 1468 46a0 5b92 0000 0000  2
//a002 16d0 1801 0000 0204 05b4 0402 080a  3
//0006 24d3 0000 0000 0103 0303 07b3 9fcc

static int parse_ip_header(unsigned char **buf, int len, struct packet_info *p)
{
	struct iphdr *ih;

	int i, j;

	fdebug(DEBUG_LEVEL_PROTOCOL_IP, "* parse IP\n");

//-------------------------------------------------------------------------
	fdebug(DEBUG_LEVEL_PROTOCOL_IP, "\n\n");
	fdebug(DEBUG_LEVEL_PROTOCOL_IP, "---------[ip_packet_len=%04d]----------", len);

	j = 0;
	for(i = 0; i < len; i++)
	{
		if((i % 2) == 0)
			fdebug(DEBUG_LEVEL_PROTOCOL_IP, " ");
		if((i % 16) == 0)
		{
			fdebug(DEBUG_LEVEL_PROTOCOL_IP, " %d\n", j);
			j++;
		}
		fdebug(DEBUG_LEVEL_PROTOCOL_IP, "%02x", (*buf)[i]);
	}

	fdebug(DEBUG_LEVEL_PROTOCOL_IP, "\n");
//-------------------------------------------------------------------------

	if(len < sizeof(struct iphdr))
		return -1;

	ih = (struct iphdr *)*buf;

	fdebug(DEBUG_LEVEL_PROTOCOL_IP, "*** IP SRC: %s\n", ip_sprintf(ih->saddr));
	fdebug(DEBUG_LEVEL_PROTOCOL_IP, "*** IP DST: %s\n", ip_sprintf(ih->daddr));

	p->ip_src = ih->saddr;
	p->ip_dst = ih->daddr;
	p->pkt_types |= PKT_TYPE_IP;

	fdebug(DEBUG_LEVEL_PROTOCOL_IP, "IP protocol: %d\n", ih->protocol);
	switch (ih->protocol)
	{
	case IPPROTO_UDP:
		p->pkt_types |= PKT_TYPE_UDP;
		break;
		/* all others set the type and return. no more parsing */
	case IPPROTO_ICMP:
		p->pkt_types |= PKT_TYPE_ICMP;
		break;
		/* 进一步解析 */
		//return 0;
	case IPPROTO_TCP:
		p->pkt_types |= PKT_TYPE_TCP;
		break;
		/* 进一步解析 */
		//return 0;
	}

//-------------------------------------------------------------------------
	//无需？大小端置换
//-------------------------------------------------------------------------
	memset(&iphead, 0x00, sizeof(iphead));
//-------------------------------------------------------------------------
	iphead.version = ih->version;
	iphead.ihl = ih->ihl;
	iphead.tos = ih->tos;
	iphead.tot_len = ih->tot_len;
	iphead.id = ih->id;
	iphead.frag_off = ih->frag_off;
	iphead.ttl = ih->ttl;
	iphead.protocol = ih->protocol;
	iphead.check = ih->check;
	iphead.saddr = ih->saddr;
	iphead.daddr = ih->daddr;
//-------------------------------------------------------------------------

	*buf = *buf + ih->ihl * 4;         //4*5=20个字节
	return len - ih->ihl * 4;
}

/*
/usr/src/linux/include/linux/udp.h

struct udphdr {
        __u16   source;
        __u16   dest;
        __u16   len;
        __u16   check;
};

     |----------------|----------------|-------------
     |     source     |     dest       |
     |----------------|----------------|
     |     len        |   check 	   |
     |---------------------------------|
*/
static int parse_udp_header(unsigned char **buf, int len, struct packet_info *p)
{
	struct udphdr *uh;
	int i, j;
//-------------------------------------------------------------------------
	fdebug(DEBUG_LEVEL_PROTOCOL_UDP, "* parse UDP\n");
//-------------------------------------------------------------------------
	fdebug(DEBUG_LEVEL_PROTOCOL_UDP, "---------[udp_packet_len=%04d]---------", len);

	j = 0;
	for(i = 0; i < len; i++)
	{
		if((i % 2) == 0)
			fdebug(DEBUG_LEVEL_PROTOCOL_UDP, " ");
		if((i % 16) == 0)
		{
			fdebug(DEBUG_LEVEL_PROTOCOL_UDP, " %d\n", j);
			j++;
		}
		fdebug(DEBUG_LEVEL_PROTOCOL_UDP, "%02x", (*buf)[i]);
	}
//-------------------------------------------------------------------------
	fdebug(DEBUG_LEVEL_PROTOCOL_UDP, "\n");
//-------------------------------------------------------------------------

	if(len < sizeof(struct udphdr))
		return -1;

	uh = (struct udphdr *)*buf;

	/* ntohs =net to host short int */
	/* 将一个无符号短整形数从网络字节顺序转换为主机字节顺序 */

	fdebug(DEBUG_LEVEL_PROTOCOL_UDP, "UDP src port: %d\n", ntohs(uh->source));
	fdebug(DEBUG_LEVEL_PROTOCOL_UDP, "UDP dst port: %d\n", ntohs(uh->dest));

	p->port_src = ntohs(uh->source);
	p->port_dst = ntohs(uh->dest);

	//8 = source + dest + len + check 长度固定，与tcp不一样

	*buf = *buf + 8;
	len = len - 8;

	//UDP暂不处理
	//if ((p->port_src == 80)||(p->port_src == 8080)||(p->port_src == 8000)||
	//  (p->port_dst == 80)||(p->port_dst == 8080)||(p->port_dst == 8000))
	//{
	//  *buf = *buf + 12;
	//    len = len - 12;
	//  printf("UDP_HTTP\n");
	//    //printf("%s", *buf);
	//    fdebug(DEBUG_LEVEL_PROTOCOL_HTTP, "UDP_HTTP\n");
	//    fdebug(DEBUG_LEVEL_PROTOCOL_HTTP, "%s", *buf);
	//}

	return 0;
}

/*
/usr/src/linux-2.6.19/include/linux/tcp.h
struct tcphdr {
    __be16 source;		//2字节，本地端口
    __be16 dest;		//2字节，远程端口
    __be32 seq;			//4字节，序列号
    __be32 ack_seq;		//4字节，应答序列号
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u16   res1:4,		//reserved
            doff:4,		//tcp offset tcp包长，*4
            fin:1,		//一下是tcp flags，每位代表不同的含义
            syn:1,
            rst:1,
            psh:1,
            ack:1,
            urg:1,
            ece:1,
            cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u16   doff:4,
            res1:4,
            cwr:1,
            ece:1,
            urg:1,
            ack:1,
            psh:1,
            rst:1,
            syn:1,
            fin:1;
#else
#error "Adjust your <asm/byteorder.h> defines"
#endif
    __be16 window;
    __be16 check;
    __be16 urg_ptr;
};
     |----------------|----------------|-------------
     |     source     |     dest       |
     |----------------|----------------|
     |               seq               |
     |---------------------------------|
     |               ack_seq           | 20 Bytes
     |----|----|------|----------------|
     |doff|res1|      |     window     |
     |----|----|------|----------------|
     |     check      |     urg_ptr    |
     |----------------|----------------|-------------
     |             options             | 4 Bytes
     |---------------------------------|

Internet Header Format
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

TCP Header Format
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |           |U|A|P|R|S|F|                               |
   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
   |       |           |G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


*/

//pcap数据包头结构体 16个字节
//  时间戳：秒+微秒
//  帧最大长度：
//  帧实际长度
struct pcap_pkthdr
{
	struct timeval ts;                 /* time stamp */
	u_int32_t caplen;                  /* 此次抓包保存的数据长度 length of portion present */
	u_int32_t len;                     /* 离线数据长度，真实情况的数据长度 length this packet (off wire) */
};

//数据帧头，14个字节
struct pcap_frmhdr                     //Pcap捕获的数据帧头
{
	u_int8_t dst_mac[6];               //目的MAC地址
	u_int8_t src_mac[6];               //源MAC地址
	u_int16_t frame_type;              //帧类型
};

static int parse_tcp_header(unsigned char **buf, int len, struct packet_info *p)
{
	struct tcphdr *th;
	int i, j;
	char agent[128];
	char httphost[32];
	char qq[16];
	int bHTTP;
	char *pos;
	int tcp_offset;

	unsigned char sta_mac[MAC_LEN];
	/*
	    char http_head[1024];
	    char *phead;
	*/

//-------------------------------------------------------------------------
	fdebug(DEBUG_LEVEL_PROTOCOL_TCP, "* parse TCP\n");
//-------------------------------------------------------------------------
	fdebug(DEBUG_LEVEL_PROTOCOL_TCP, "---------[tcp_packet_len=%04d]---------", len);

	j = 0;
	for(i = 0; i < len; i++)
	{
		if((i % 2) == 0)
			fdebug(DEBUG_LEVEL_PROTOCOL_TCP, " ");
		if((i % 16) == 0)
		{
			fdebug(DEBUG_LEVEL_PROTOCOL_TCP, " %d\n", j);
			j++;
		}
		fdebug(DEBUG_LEVEL_PROTOCOL_TCP, "%02x", (*buf)[i]);
	}
//-------------------------------------------------------------------------
	fdebug(DEBUG_LEVEL_PROTOCOL_TCP, "\n");
//-------------------------------------------------------------------------
	if(len < sizeof(struct tcphdr))
		return -1;

	th = (struct tcphdr *)*buf;

	p->port_src = ntohs(th->source);
	p->port_dst = ntohs(th->dest);
	tcp_offset = ntohs(th->doff) * 4;

	*buf = *buf + tcp_offset;
	len = len - tcp_offset;

	fdebug(DEBUG_LEVEL_PROTOCOL_TCP,
	       "TCP src port: %d; TCP dst port: %d; TCP offset: %d; TCP len: %d\n", ntohs(th->source),
	       ntohs(th->dest), ntohs(th->doff) * 4, len);

	if(len < 11)
	{
		fdebug(DEBUG_LEVEL_PROTOCOL_ERROR, "too_short_break\n");
		return 0;
	}
//-------------------------------------------------------------------------
//记录tcp的pcap文件
//-------------------------------------------------------------------------

#ifdef _PCAP
	struct pcap_pkthdr ph;
	struct pcap_frmhdr fh;

	gettimeofday(&ph.ts, NULL);
	ph.caplen = len + tcp_offset + sizeof(fh) + sizeof(iphead) - 8; //-8 让wireshark以为帧不含fcs校验
	ph.len = ph.caplen;

	ph.ts.tv_sec = le32toh(ph.ts.tv_sec);
	ph.ts.tv_usec = le32toh(ph.ts.tv_usec);
	ph.len = le32toh(ph.len);
	ph.caplen = le32toh(ph.caplen);

	//pcap帧头，16个字节
	if(PCAPLOG != NULL)
		fwrite(&ph, sizeof(ph), 1, PCAPLOG);

	//mac地址不需要大小端置换
	memcpy(fh.dst_mac, p->wlan_dst, MAC_LEN);
	memcpy(fh.src_mac, p->wlan_src, MAC_LEN);
	fh.frame_type = 0x0008;

	fh.frame_type = le16toh(fh.frame_type);

	//以太网帧头，14字节
	if(PCAPLOG != NULL)
		fwrite(&fh, sizeof(fh), 1, PCAPLOG);

	//IP层帧头
	if(PCAPLOG != NULL)
		fwrite(&iphead, sizeof(iphead), 1, PCAPLOG);

	//写剩余部分
	if(PCAPLOG != NULL)
		fwrite((*buf - tcp_offset), len + tcp_offset - 8, 1, PCAPLOG);
#endif
//-------------------------------------------------------------------------

	memset(sta_mac, 0x00, 6);

	if(MAC_EQUAL(p->wlan_dst, eth1_mac))
    {
	    memcpy(sta_mac, p->wlan_src, MAC_LEN);
    }

    if(MAC_EQUAL(p->wlan_src, eth1_mac))
    {
	    memcpy(sta_mac, p->wlan_dst, MAC_LEN);
    }
//	printf("wlan_src mac: %02x:%02x%02x:%02x%02x:%02x\n",p->wlan_src[0],p->wlan_src[1],p->wlan_src[2],p->wlan_src[3],p->wlan_src[4],p->wlan_src[5] );
//	printf("wlan_dst mac: %02x:%02x%02x:%02x%02x:%02x\n",p->wlan_dst[0],p->wlan_dst[1],p->wlan_dst[2],p->wlan_dst[3],p->wlan_dst[4],p->wlan_dst[5] );
	//第一步仅处理连接80端口的HTTP协议
	if(p->port_dst == 80)
	{

		//-------------------------------------------------------------------------
		fdebug(DEBUG_LEVEL_PROTOCOL_HTTP, "* parse HTTP\n");
		//-------------------------------------------------------------------------
		fdebug(DEBUG_LEVEL_PROTOCOL_HTTP, "---------[http_packet_len=%04d]---------", len);

		j = 0;
		for(i = 0; i < len; i++)
		{
			if((i % 2) == 0)
				fdebug(DEBUG_LEVEL_PROTOCOL_HTTP, " ");
			if((i % 16) == 0)
			{
				fdebug(DEBUG_LEVEL_PROTOCOL_HTTP, " %d\n", j);
				j++;
			}
			fdebug(DEBUG_LEVEL_PROTOCOL_HTTP, "%02x", (*buf)[i]);
		}
		//-------------------------------------------------------------------------
		fdebug(DEBUG_LEVEL_PROTOCOL_HTTP, "\n");
		//-------------------------------------------------------------------------

		bHTTP = 0;

		//printf("TCP_HTTP\n");
		//printf("%s", *buf);

		//printf("\n TCP_DST_HTTP_80: %d\n",len);
		//printf("%s\n\n",*buf);

		fdebug(DEBUG_LEVEL_PROTOCOL_HTTP, "\n TCP_DST_HTTP_80: %d\n", len);
		//fdebug(DEBUG_LEVEL_PROTOCOL_HTTP, "%s\n\n",*buf);
		//fdebug(DEBUG_LEVEL_PROTOCOL_HTTP, "%.*s\n\n", len, *buf);

		/*
				//查找两个回车换行的指针位置
			    pos = strstr((char*)*buf, "\r\n\r\n");
			    if (pos)
			    {
				    memset(http_head, 0x00, 1024);
				    phead = (char*)*buf;
				    j = 0;

					do {
						http_head[j++] = *phead++;
						if (http_head[j-1] == 0x0D)
							http_head[j-1] = ']';
						if (http_head[j-1] == 0x0A)
							http_head[j-1] = '[';

					} while((phead != pos)&& (j<1024));

					//记录http
				    //printf("http_head_dst: %s\n", http_head);
				    fdebug(DEBUG_LEVEL_PROTOCOL_HTTP, "http_head_dst: %s\n", http_head);

			    }

		*/
		memset(agent, 0x00, 128);
		memset(httphost, 0x00, 32);
		memset(qq, 0x00, 16);

		pos = strstr((char *)*buf, "User-Agent");
		if(pos)
		{
			pos = pos + 11;
			bHTTP = 1;
			j = 0;
			do
			{
				agent[j++] = *pos++;
			}
			while ((*pos != 0x0D) && (j < 127));

			agent[127] = 0x00;

			//printf("agent: %s\n", agent);
			fdebug(DEBUG_LEVEL_PROTOCOL_HTTP, "agent: %s\n", agent);
		}
		/*
		        pos = strstr((char *)*buf, "pragma-device: ");
		        if(pos)
		        {
		            bHTTP = 1;
		            j = 0;

		            pos = pos + 14;

		            do
		            {
		                host[j++] = *pos++;

		            }
		            while ((*pos != 0x0D) && (j < 31));

		            host[31] = 0x00;

		            printf("[%s]IMEI: %s\n", ether_sprintf(p->wlan_src), host);
		            fdebug(DEBUG_LEVEL_PROTOCOL_HTTP, "host: %s\n", host);
		        }
		*/
		if(bHTTP)
		{
			//		update_agent_list(sta_mac,  agent);
		}

	}

	if(p->port_src == 80)
	{

		//printf("\n TCP_SRC_HTTP_80: %d\n",len);
		//printf("%s\n\n",*buf);

		fdebug(DEBUG_LEVEL_PROTOCOL_HTTP, "\n TCP_SRC_HTTP_80: %d\n", len);
		//fdebug(DEBUG_LEVEL_PROTOCOL_HTTP, "%s\n\n",*buf);
		//fdebug(DEBUG_LEVEL_PROTOCOL_HTTP, "%.*s\n\n", len, *buf);

		/*
				//查找两个回车换行的指针位置
			    pos = strstr((char*)*buf, "\r\n\r\n");
			    if (pos)
			    {
				    memset(http_head, 0x00, 1024);
				    phead = (char*)*buf;
				    j = 0;

					do {
						http_head[j++] = *phead++;
						if (http_head[j-1] == 0x0D)
							http_head[j-1] = ']';
						if (http_head[j-1] == 0x0A)
							http_head[j-1] = '[';

					} while((phead != pos)&& (j<1024));

				    //printf("http_head_src: %s\n", http_head);
				    fdebug(DEBUG_LEVEL_PROTOCOL_HTTP, "http_head_src: %s\n", http_head);
			    }
		*/

	}

	if(p->port_src == 8080)
	{
		memset(qq, 0x00, 16);

//---------[tcp_packet_len=0248]---------  0
//1f90 a01d 7f2c 57c8 a7ed 6715 5018 01f6  1
//b78e 0000 0000 00e0 0000 0008 0100 0000  2
//000e 3235 3932 3136 3237 3035 8675 6ab6  3    //2592162705

		fdebug(DEBUG_LEVEL_PROTOCOL_QQ, "src_8080_len: %d\n", len);
		if(len > 14)
		{
			fdebug(DEBUG_LEVEL_PROTOCOL_QQ, "qqlen: %d,%d,%d,%d\n", (*buf)[10], (*buf)[11],
			       (*buf)[12], (*buf)[13]);
			if((len > 14 + (*buf)[13]) && ((*buf)[10] == 0) && ((*buf)[11] == 0)
			        && ((*buf)[12] == 0))
			{
				fdebug(DEBUG_LEVEL_PROTOCOL_QQ, "\n from_8080_QQQQ:");
				for(j = 0; j < (*buf)[13] - 4; j++)
				{
					fdebug(DEBUG_LEVEL_PROTOCOL_QQ, "%c", (*buf)[14 + j]);
					qq[j] = (*buf)[14 + j];
				}

				if(is_digital_str(qq) && (strlen(qq) > 5))
				{
					update_vid_list(sta_mac,  qq, 4);
					printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^QQ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
				}
			}

		}

	}

	if(p->port_dst == 8080)
	{
		memset(qq, 0x00, 16);

//---------[tcp_packet_len=0348]---------  0
//a01d 1f90 a7ed 65d1 7f2c 57c8 5018 04e4  1
//d94e 0000 0000 0144 0000 0008 0100 0000  2
//44ce a908 32d2 42af f34a a76c 2b67 4f0a  3
//67f7 834f 5b8e 3ba5 dd32 0cbd 15b9 53e4  4
//067f 754b 4747 9148 2cd8 d384 3fd0 00d7  5
//7992 35a1 669b 14ea 6010 16f3 657c de22  6
//1500 0000 000e 3235 3932 3136 3237 3035  7  2592162705
//ac2d 60df 1e93 f34a 953e 8e32 aec2 c715  8

		fdebug(DEBUG_LEVEL_PROTOCOL_QQ, "dst_8080len: %d\n", len);
		if(len > 82)
		{
			fdebug(DEBUG_LEVEL_PROTOCOL_QQ, "qqlen: %d,%d,%d,%d\n", (*buf)[78], (*buf)[79],
			       (*buf)[80], (*buf)[81]);
			if((len > 82 + (*buf)[81]) && ((*buf)[78] == 0) && ((*buf)[79] == 0)
			        && ((*buf)[80] == 0))
			{
				fdebug(DEBUG_LEVEL_PROTOCOL_QQ, "\n to_8080_QQQQ:");
				for(j = 0; j < (*buf)[81] - 4; j++)
				{
					fdebug(DEBUG_LEVEL_PROTOCOL_QQ, "%c", (*buf)[82 + j]);
					qq[j] = (*buf)[82 + j];
				}
				if(is_digital_str(qq) && (strlen(qq) > 5))
				{
					update_vid_list(sta_mac,  qq, 4);
					printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^QQ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
				}
			}

		}
	}

	if(p->port_src == 14000)
	{
		memset(qq, 0x00, 16);

//---------[tcp_packet_len=0190]---------  0
//36b0 eb23 f664 0a43 9af8 1d2b 5018 006e  1
//ee1f 0000 0000 00a6 0000 0003 0100 0000  2
//000c 3638 3433 3932 3032 fbc2 48e6 7c2c  3    //68439202
//f18a 4504 e85e 7b77 be46 b8c9 1caf 8d14  4
//e44e 4436 fc5c c63f 56ab eb53 a12c 2ada  5
//a901 465d 4fe5 ae29 0e0e d5c0 e6f3 c139  6
//431e d904 815d a572 f5a9 3f18 3284 c9c7  7
//7487 175d f4f8 0efd 2c40 64c3 42fb aa36  8
//e87e fcb6 1b3a 2e74 9d85 204f 7372 7b6f  9
//57a0 1d72 1f8d 5268 5ee7 6edf b676 0596  10
//bce3 a441 ef2b aa43 ca09 51f2 882f c8df  11
//ff61 a992 577c 8fde d066 0d20 7245
//TCP src port: 14000
//TCP dst port: 60195

		fdebug(DEBUG_LEVEL_PROTOCOL_QQ, "src_14000_len: %d\n", len);
		if(len > 14)
		{
			fdebug(DEBUG_LEVEL_PROTOCOL_QQ, "qqlen: %d,%d,%d,%d\n", (*buf)[10], (*buf)[11],
			       (*buf)[12], (*buf)[13]);
			if((len > 14 + (*buf)[13]) && ((*buf)[10] == 0) && ((*buf)[11] == 0)
			        && ((*buf)[12] == 0))
			{
				fdebug(DEBUG_LEVEL_PROTOCOL_QQ, "\n from_14000_QQQQ:");
				for(j = 0; j < (*buf)[13] - 4; j++)
				{
					fdebug(DEBUG_LEVEL_PROTOCOL_QQ, "%c", (*buf)[14 + j]);
					qq[j] = (*buf)[14 + j];
				}

				if(is_digital_str(qq) && (strlen(qq) > 5))
				{
					update_vid_list(sta_mac,  qq, 4);
					printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^QQ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
				}
			}

		}

	}

	if(p->port_dst == 14000)
	{
		memset(qq, 0x00, 16);

//---------[tcp_packet_len=0282]---------  0
//eb23 36b0 9af8 1e2d f664 0b8f 5018 056c  1
//1bce 0000 0000 0102 0000 0003 0100 0000  2
//2c9f d900 fc68 3676 bde6 291e a7b5 b8bf  3
//a70d c371 2bad f95c 0c53 5b8c 8702 d48a  4
//e36e fb50 17dd 13b0 1900 0000 000c 3638  5   //68439202
//3433 3932 3032 bdbb 10a6 d9f4 b66d b760  6
//11be 184c c493 b4de 543a 6e9c 3603 b3d0  7
//6240 1f03 f991 93a4 3027 9145 76c1 5cb6  8
//bd59 2cb1 7bf5 8b8e 321f a5ab 0228 abed  9
//00d8 7bed 9020 115e f2a1 0cd0 b67e 5181  10
//921a 86a3 70c9 d35c 65cf 6912 f877 019b  11
//f165 2a68 1b3c 1392 fe3e c8a0 e4c9 d065  12
//795a 2096 3ae9 1956 1c0d c638 2847 02d0  13
//a2c1 3083 cecd 3355 8d2e bc6c 6636 de40  14
//ca62 e5ac 1485 bc47 21ce 0526 c2ad 1a29  15
//164b c984 c451 619b 255f abdf 395e 5a61  16
//a097 10cd fd7a a0a6 841c 8086 6b50 b209  17
//bff3 9451 b208 7bde 1879
//TCP src port: 60195
//TCP dst port: 14000

		fdebug(DEBUG_LEVEL_PROTOCOL_QQ, "dst_14000_len: %d\n", len);
		if(len > 58)
		{
			fdebug(DEBUG_LEVEL_PROTOCOL_QQ, "qqlen: %d,%d,%d,%d\n", (*buf)[54], (*buf)[55],
			       (*buf)[56], (*buf)[57]);
			if((len > 58 + (*buf)[57]) && ((*buf)[54] == 0) && ((*buf)[55] == 0)
			        && ((*buf)[56] == 0))
			{
				fdebug(DEBUG_LEVEL_PROTOCOL_QQ, "\n to_14000_QQQQ:");
				for(j = 0; j < (*buf)[57] - 4; j++)
				{
					fdebug(DEBUG_LEVEL_PROTOCOL_QQ, "%c", (*buf)[58 + j]);
					qq[j] = (*buf)[58 + j];
				}
				if(is_digital_str(qq) && (strlen(qq) > 5))
				{
					update_vid_list(sta_mac,  qq, 4);
					printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^QQ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
				}
			}

		}

	}

	if(p->port_src == 443)
	{
		memset(qq, 0x00, 16);

//---------[tcp_packet_len=0512]---------  0
//01bb 862f 88fe 8c9c 3593 b79c 5018 00fb  1
//58ad 0000 0000 01e8 0000 0008 0100 0000  2
//000e 3235 3932 3136 3237 3035 65ba 74a7  3  //2592162705
//74a5 16f9 46ac ab68 d79b 930a 829b 05c4  4

		fdebug(DEBUG_LEVEL_PROTOCOL_QQ, "src_443_len: %d\n", len);
		if(len > 14)
		{
			fdebug(DEBUG_LEVEL_PROTOCOL_QQ, "qqlen: %d,%d,%d,%d\n", (*buf)[10], (*buf)[11],
			       (*buf)[12], (*buf)[13]);
			if((len > 14 + (*buf)[13]) && ((*buf)[10] == 0) && ((*buf)[11] == 0)
			        && ((*buf)[12] == 0))
			{
				fdebug(DEBUG_LEVEL_PROTOCOL_QQ, "\n from_443_QQQQ:");
				for(j = 0; j < (*buf)[13] - 4; j++)
				{
					fdebug(DEBUG_LEVEL_PROTOCOL_QQ, "%c", (*buf)[14 + j]);
					qq[j] = (*buf)[14 + j];
				}

				if(is_digital_str(qq) && (strlen(qq) > 5))
				{
					update_vid_list(sta_mac,  qq, 4);
					printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^QQ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
				}
			}

		}

	}

	if(p->port_dst == 443)
	{
		memset(qq, 0x00, 16);

//---------[tcp_packet_len=0316]---------  0
//862f 01bb 3593 b870 88fe 90c4 5018 0a30  1
//e4f4 0000 0000 0124 0000 0008 0100 0000  2
//44fc cd30 9b5f 18ae 1537 2e35 8117 d0f3  3
//d2ec e965 07c4 c1bd 4107 db6b 53e3 cc46  4
//0010 a443 2546 83d2 c771 060f 0f6b 39f9  5
//71bf cb0b dab0 3897 9b47 8ff8 5b98 2b54  6
//3000 0000 000e 3235 3932 3136 3237 3035  7  //2592162705
//bb84 0800 7b06 03a3 21d9 3b63 8b60 00e1  8
//e37f aad4 2f95 ba75 6498 b24c a04d bd27  9

		fdebug(DEBUG_LEVEL_PROTOCOL_QQ, "dst_443_len: %d\n", len);
		if(len > 82)
		{
			fdebug(DEBUG_LEVEL_PROTOCOL_QQ, "qqlen: %d,%d,%d,%d\n", (*buf)[78], (*buf)[79],
			       (*buf)[80], (*buf)[81]);
			if((len > 82 + (*buf)[81]) && ((*buf)[78] == 0) && ((*buf)[79] == 0)
			        && ((*buf)[80] == 0))
			{
				fdebug(DEBUG_LEVEL_PROTOCOL_QQ, "\n to_443_QQQQ:");
				for(j = 0; j < (*buf)[81] - 4; j++)
				{
					fdebug(DEBUG_LEVEL_PROTOCOL_QQ, "%c", (*buf)[82 + j]);
					qq[j] = (*buf)[82 + j];
				}
				if(is_digital_str(qq) && (strlen(qq) > 5))
				{
					update_vid_list(sta_mac,  qq, 4);
					printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^QQ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
				}
					
			}

		}
	}

	/* 根据host和关键字过滤 */
	char *phost;
	char *pkeyword;

	char host[64];
	char keyword[64];

	//unsigned char sta_mac[6];
	//unsigned char p->wlan_bssid[6];


	//memcpy(sta_mac, sta_mac, 6);
	//memcpy(  6);

	memset(host, 0x00, 64);
	strcat(host, "zhizi.qq");
	phost = memmem((char *)*buf,len,host,strlen(host));
	if(phost)
	{
		pkeyword = memmem((char *)*buf,len,"uin",3);

		if(pkeyword)
		{
			char qqid[64];
			int i;

			memset(qqid,0x00,64);

			pkeyword = pkeyword + strlen("uid")+3;
			i=0;
			do
			{
				qqid[i++] = *(pkeyword++);
			}
			while(((*pkeyword)!='\r')&&(i < 63)&&(*pkeyword)!='&'&&(*pkeyword)!='"');
			if(strlen(qqid)<16)
			{
				printf("qqid=%s\n",qqid);
				update_vid_list(sta_mac,  qqid, 4);
				printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^QQ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
			}
		}
	}
	memset(host, 0x00, 64);
	strcat(host, "ti.qq.com");
	phost = memmem((char *)*buf,len,host,strlen(host));
	if(phost)
	{
		printf("find QQ3 \n");
		char *pqqid3;
		char *pqqid4;
		pqqid3 = memmem((char *)*buf,len,"uin=o0",6);
		pqqid4 = memmem((char *)*buf,len,"qq=",3);
		if(pqqid3)
		{
			char qqid3[64];
			int i;

			memset(qqid3,0x00,64);

			pqqid3 = pqqid3 + strlen("uin=o0");
			i=0;
			do
			{
				qqid3[i++] = *(pqqid3++);
			}
			while(((*pqqid3)!='\r')&&(i < 63)&&(*pqqid3)!=';'&&(*pqqid3)!='"');
			if(qqid3[3]!=0)
			{
				printf("qqid3=%s\n",qqid3);
				update_vid_list(sta_mac,  qqid3, 50);
				printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^qqid3^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
			}
		}
		if(pqqid4)
		{
			char qqid4[64];
			int i;

			memset(qqid4,0x00,64);

			pqqid4 = pqqid4 + strlen("qq=");
			i=0;
			do
			{
				qqid4[i++] = *(pqqid4++);
			}
			while(((*pqqid4)!='\r')&&(i < 63)&&(*pqqid4)!='&'&&(*pqqid4)!='"');
			if(qqid4[3]!=0)
			{
				printf("qqid4=%s\n",qqid4);
				update_vid_list(sta_mac,  qqid4, 50);
				printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^qqid4^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
			}
		}
	}
	/*****************************************************************************

		手机号码
		来源：
			手机邮箱
			手机网上营业厅
			上网认证

	*****************************************************************************/
	memset(keyword, 0x00, 64);
	strcat(keyword, "mobile\":\"");

	pkeyword = strstr((char *)*buf, keyword);

	if(pkeyword)
	{

		printf("find[%s]\n", keyword);

		char mobile[32];
		int i = 0;

		memset(mobile, 0x00, 32);
		pkeyword = pkeyword + strlen(keyword);

		do
		{
			mobile[i++] = *(pkeyword++);
		}
		while ((isdigit(*pkeyword)) && (i < 31));

		printf("mobile = %s\n", mobile);
		//fprintf(fp_vidlist, "[%06d][%s]mobile = %s\n", i_pkt, ether_sprintf(dev_mac), mobile);
		if(is_digital_str(mobile) && (strlen(mobile) > 7))
		{
			update_vid_list(sta_mac,  mobile, 1);
			printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^mobile^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
		}
			
	}

	memset(keyword, 0x00, 64);
	strcat(keyword, "phone=");
	pkeyword = strstr((char *)*buf, keyword);

	if(pkeyword)
	{

		printf("find[%s]\n", keyword);

		char phone[32];
		int i = 0;

		memset(phone, 0x00, 32);
		pkeyword = pkeyword + strlen(keyword);

		do
		{
			phone[i++] = *(pkeyword++);
		}
		while ((isdigit(*pkeyword)) && (i < 11));

		printf("phone = %s\n", phone);
		//fprintf(fp_vidlist, "[%06d][%s]phone = %s\n", i_pkt, ether_sprintf(dev_mac), phone);
		if(is_digital_str(phone) && (strlen(phone) > 7))
		{
			update_vid_list(sta_mac,  phone, 1);
			printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^phone^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
		}

	}


	memset(keyword, 0x00, 64);
	strcat(keyword, "mobile=");

	pkeyword = strstr((char *)*buf, keyword);

	if(pkeyword)
	{

		printf("find[%s]\n", keyword);

		char mobile[32];
		int i = 0;

		memset(mobile, 0x00, 32);
		pkeyword = pkeyword + strlen(keyword);

		do
		{
			mobile[i++] = *(pkeyword++);
		}
		while ((isdigit(*pkeyword)) && (i < 31));

		printf("mobile = %s\n", mobile);
		//fprintf(fp_vidlist, "[%06d][%s]mobile = %s\n", i_pkt, ether_sprintf(dev_mac), mobile);
		if(is_digital_str(mobile) && (strlen(mobile) > 7))
		{
			update_vid_list(sta_mac,  mobile, 1);
			printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^mobile^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
		}
			

	}



	memset(keyword, 0x00, 64);
	strcat(keyword, "mobile:");

	pkeyword = strstr((char *)*buf, keyword);

	if(pkeyword)
	{

		printf("find[%s]\n", keyword);

		char mobile[32];
		int i = 0;

		memset(mobile, 0x00, 32);
		pkeyword = pkeyword + strlen(keyword);

		do
		{
			mobile[i++] = *(pkeyword++);
		}
		while ((isdigit(*pkeyword)) && (i < 31));

		printf("mobile = %s\n", mobile);
		//fprintf(fp_vidlist, "[%06d][%s]mobile = %s\n", i_pkt, ether_sprintf(dev_mac), mobile);
		if(is_digital_str(mobile) && (strlen(mobile) > 7))
		{
			update_vid_list(sta_mac,  mobile, 1);
			printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^mobile^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
		}

	}

	/*****************************************************************************

		IMEI
		第一步仅支持严谨的判据：imei=
		还有其他格式下一步考虑

	*****************************************************************************/
	pkeyword = strstr((char *)*buf, "imei=");

	if(pkeyword)
	{

		printf("imei=\n");

		char imei[32];
		int i = 0;

		memset(imei, 0x00, 32);
		pkeyword = pkeyword + 5;

		do
		{
			imei[i++] = *(pkeyword++);
		}
		while ((isdigit(*pkeyword)) && (i < 31));

		if(strlen(imei) == 15)
		{
			if(strcmp(imei, "000000000000000") != 0)
			{
				printf("imei = %s\n", imei);
				update_vid_list(sta_mac,  imei, 2);
				printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^imei^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
			}
		}
	}

	pkeyword = strstr((char *)*buf, "imei%3D");

	if(pkeyword)
	{

		printf("imei=\n");

		char imei[32];
		int i = 0;

		memset(imei, 0x00, 32);
		pkeyword = pkeyword + 7;

		do
		{
			imei[i++] = *(pkeyword++);
		}
		while ((isdigit(*pkeyword)) && (i < 31));

		if(strlen(imei) == 15)
		{
			if(strcmp(imei, "000000000000000") != 0)
			{
				printf("imei = %s\n", imei);
				update_vid_list(sta_mac,  imei, 2);
				printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^imei^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
			}
		}
	}


	pkeyword = strstr((char *)*buf, "imei%3d");

	if(pkeyword)
	{

		printf("imei=\n");

		char imei[32];
		int i = 0;

		memset(imei, 0x00, 32);
		pkeyword = pkeyword + 7;

		do
		{
			imei[i++] = *(pkeyword++);
		}
		while ((isdigit(*pkeyword)) && (i < 31));

		if(strlen(imei) == 15)
		{
			if(strcmp(imei, "000000000000000") != 0)
			{
				printf("imei = %s\n", imei);
				update_vid_list(sta_mac,  imei, 2);
				printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^imei^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
			}
		}
	}

	/*****************************************************************************

		IMSI
		第一步仅支持严谨的判据：imsi=
		还有其他格式下一步考虑

	*****************************************************************************/
	pkeyword = strstr((char *)*buf, "imsi=");

	if(pkeyword)
	{

		printf("find imsi\n");

		char imsi[32];
		int i = 0;

		memset(imsi, 0x00, 32);
		pkeyword = pkeyword + 5;

		do
		{
			imsi[i++] = *(pkeyword++);
		}
		while ((isdigit(*pkeyword)) && (i < 31));

		if(strlen(imsi) == 15)
		{
			//printf("imsi = %s\n", imsi);
			update_vid_list(sta_mac,  imsi, 3);
			printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^imsi^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
		}

	}

	pkeyword = strstr((char *)*buf, "imsi%3D");

	if(pkeyword)
	{

		printf("find imsi\n");

		char imsi[32];
		int i = 0;

		memset(imsi, 0x00, 32);
		pkeyword = pkeyword + 7;

		do
		{
			imsi[i++] = *(pkeyword++);
		}
		while ((isdigit(*pkeyword)) && (i < 31));

		if(strlen(imsi) == 15)
		{
			//printf("imsi = %s\n", imsi);
			//fprintf(fp_vidlist, "[%06d][%s]imsi = %s\n", i_pkt, ether_sprintf(dev_mac), imsi);
			update_vid_list(sta_mac,  imsi, 3);
			printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^imsi^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
		}

	}


	pkeyword = strstr((char *)*buf, "imsi%3d");

	if(pkeyword)
	{

		printf("find imsi\n");

		char imsi[32];
		int i = 0;

		memset(imsi, 0x00, 32);
		pkeyword = pkeyword + 7;

		do
		{
			imsi[i++] = *(pkeyword++);
		}
		while ((isdigit(*pkeyword)) && (i < 31));

		if(strlen(imsi) == 15)
		{
			//printf("imsi = %s\n", imsi);
			//fprintf(fp_vidlist, "[%06d][%s]imsi = %s\n", i_pkt, ether_sprintf(dev_mac), imsi);
			update_vid_list(sta_mac,  imsi, 3);
			printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^imsi^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
		}

	}

	pkeyword = strstr((char *)*buf, "460");

	if(pkeyword)
	{

		printf("find imsi\n");

		char imsi[32];
		int i = 0;

		memset(imsi, 0x00, 32);
		pkeyword = pkeyword;

		do
		{
			imsi[i++] = *(pkeyword++);
		}
		while ((isdigit(*pkeyword)) && (i < 31));

		if(strlen(imsi) == 15)
		{
			//printf("imsi = %s\n", imsi);
			//fprintf(fp_vidlist, "[%06d][%s]imsi = %s\n", i_pkt, ether_sprintf(dev_mac), imsi);
			update_vid_list(sta_mac,  imsi, 3);
			printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^imsi^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
		}

	}

	/*****************************************************************************

		微信

	*****************************************************************************/

	memset(host, 0x00, 64);
	strcat(host, "weixin");
	memset(keyword, 0x00, 64);
	strcat(keyword, "uin=");

	phost = strstr((char *)*buf, host);

	if(phost)
	{
		printf("find[%s]\n", host);

		pkeyword = strstr((char *)*buf, keyword);
		if(pkeyword)
		{
			printf("find[%s]\n", keyword);

			char weixin[64];
			int i = 0;

			memset(weixin, 0x00, 64);

			pkeyword = pkeyword + strlen(keyword);
			do
			{
				weixin[i++] = *(pkeyword++);
			}
			while ((*pkeyword != '&') && (i < 63));

			if(is_digital_str(weixin) && (strlen(weixin) > 5))
			{
				printf("weixin = %s\n", weixin);
				//fprintf(fp_vidlist, "[%06d][%s]weixin = %s\n", i_pkt, ether_sprintf(dev_mac),
				//weixin);
				update_vid_list(sta_mac,  weixin, 5);
				printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^weixin^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
			}

		}

	}

	/*****************************************************************************

		淘宝

	*****************************************************************************/
	memset(host, 0x00, 64);
	strcat(host, "taobao.com");
	phost = memmem((char *)*buf, len, host, strlen(host));
	if(phost)
	{
		char taobao_nick[64];
		printf("find[%s]\n", host);
		pkeyword = memmem((char *)*buf, len,"_w_tb_nick=",strlen("_w_tb_nick="));
		if(pkeyword)
		{
			int i = 0;
			printf("find[%s]\n", "_w_tb_nick=");

			memset(taobao_nick, 0x00, 64);

			pkeyword = pkeyword + strlen("_w_tb_nick=");
			do
			{
				taobao_nick[i++] = *(pkeyword++);
			}
			while ((*pkeyword != 0x0d) && (*pkeyword != 0x0a) && (*pkeyword != ';') && (i< 63));
			if(taobao_nick[1]!=0)
			{
				urldecode(taobao_nick);
				printf("taobao_nick = %s\n", taobao_nick);
			}
			update_vid_list(sta_mac,  taobao_nick, 6);
			printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^taobao^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
		}

		pkeyword = memmem((char *)*buf, len,"&uid=cntaobao",strlen("&uid=cntaobao"));
		if(pkeyword)
		{
			int i = 0;
			printf("find[%s]\n", "&uid=cntaobao");
			memset(taobao_nick, 0x00, 64);

			pkeyword = pkeyword + strlen("&uid=cntaobao");
			do
			{
				taobao_nick[i++] = *(pkeyword++);
			}
			while ((*pkeyword != 0x0d) && (*pkeyword != 0x0a) && (*pkeyword != '&') && (i< 63));
			if(taobao_nick[1]!=0)
			{
				urldecode(taobao_nick);
				printf("taobao_nick = %s\n", taobao_nick);
			}
			update_vid_list(sta_mac,  taobao_nick, 6);
			printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^taobao_nick^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
		}
	}
	memset(host, 0x00, 64);
	strcat(host, "cntaobao");
	phost = memmem((char *)*buf, len, host, strlen(host));
	if(phost)//&& (len<50))
	{
		/*len是获取的tcp包长度。这里选择是长度小于50的包
		  一般长度为46的包 都是以cntaobao用户名结尾
		  超过46的包，在cntaobao用户名后面都会增加一些空字符，或者其他未知字符串
		*/
		printf("find taobao\n");
		char keyword[64];
		int i;
		int taobao_len;
		char *ascii_key;
		memset(keyword,0x00,64);

		pkeyword = phost + strlen("cntaobao");
		taobao_len = *(phost - 1) - 8;
		if(taobao_len > 32)
			taobao_len = 32;
		i=0;
		do
		{
			keyword[i++] = *(pkeyword++);
		}
		while (i < taobao_len);
		ascii_key = ASCdecode(keyword);
		update_vid_list(sta_mac,  ascii_key, 6);
		printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^taobao^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
	}

	/*****************************************************************************

		微博

	*****************************************************************************/

	char *sina;
	char *sina2;
	char weibo[64];
	sina = memmem((char *)*buf,len,"mobile.sina.cn",14);
	sina2 = memmem((char *)*buf,len,"sinaimg.cn",10);
	if(sina)
	{
		//printf("find[sina]\n");
		pkeyword= memmem((char *)*buf,len,"&uid=",5);
		if(pkeyword)
		{
			int i = 0;
			memset(weibo, 0x00, 64);

			pkeyword = pkeyword + strlen("&uid=");
			do
			{
				weibo[i++] = *(pkeyword++);
			}
			while ((*pkeyword != 0x0d) && (*pkeyword != 0x0a) && (*pkeyword != '&') && (i< 63));


			if(weibo[1]!=0&&weibo[1]!='_')
			{
				//printf("weibo = %s\n", weibo);
				update_vid_list(sta_mac,  weibo, 7);
				printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^weibo^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
			}

		}
	}
	if(sina2)
	{
		pkeyword= memmem((char *)*buf,len,"X-Log-Uid: ",11);
		if(pkeyword)
		{
			int i = 0;
			//printf("find[%s]\n", keyword);
			memset(weibo, 0x00, 64);

			pkeyword = pkeyword + strlen("X-Log-Uid: ");
			do
			{
				weibo[i++] = *(pkeyword++);
			}
			while ((*pkeyword != 0x0d) && (*pkeyword != 0x0a) && (*pkeyword != '\n') && (i< 63));


			if(weibo[1]!=0)
			{
				//printf("weibo = %s\n", weibo);
				update_vid_list(sta_mac,  weibo, 7);
				printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^weibo^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
			}

		}
	}

	/*****************************************************************************

	百度账号

	*****************************************************************************/
	/* 百度帐号 */

	memset(host, 0x00, 64);
	strcat(host, "domain=.baidu.com");
	memset(keyword, 0x00, 64);
	strcat(keyword, "username");

	phost = strstr((char *)*buf, host);

	if(phost)
	{
		printf("find[%s]\n", host);

		pkeyword = strstr((char *)*buf, keyword);
		if(pkeyword)
		{
			printf("find[%s]\n", keyword);

			char baidu[64];
			int i = 0;

			memset(baidu, 0x00, 64);
			pkeyword = strstr((char *)*buf, "username");
			pkeyword = pkeyword + strlen(keyword) + 3;
			do
			{
				baidu[i++] = *(pkeyword++);
			}
			while ((*pkeyword != 0x0d) && (*pkeyword != 0x0a) && (*pkeyword != '"') && (i < 63));

			//printf("baiduid = %s\n", baidu);
			//fprintf(fp_vidlist, "[%06d][%s]weibo = weibo.com/u/%s\n", i_pkt, ether_sprintf(dev_mac),
			//weibo);
			update_vid_list(sta_mac,  baidu, 8);
			printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^baidu^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
		}

	}
	/*****************************************************************************

		coco

	POST /user/login/cocoidlogin.json HTTP/1.1
	Host: signup.onetwosixone.com
	Connection: close
	User-Agent: Dalvik/2.1.0 (Linux; U; Android 6.0; Nexus 5 Build/MRA58N) CocoVoice/87(zh-cn)[ver:7.4.3];[devkey:5270e513-d774-42b3-bc28-7cd2aef65b99];[devtype:Android]
	Charset: UTF-8
	deviceId: 5270e513-d774-42b3-bc28-7cd2aef65b99
	Content-Type: multipart/form-data;boundary=0xKhTmLbOuNdArY
	Content-Length: 619
	Accept-Encoding: gzip

	--0xKhTmLbOuNdArY
	Content-Disposition: form-data; name="sourceid"

	play
	--0xKhTmLbOuNdArY
	Content-Disposition: form-data; name="password"

	asdfasdf
	--0xKhTmLbOuNdArY
	Content-Disposition: form-data; name="adxkey"

	1445400455923-8210585131262811814
	--0xKhTmLbOuNdArY
	Content-Disposition: form-data; name="devicekey"

	5270e513-d774-42b3-bc28-7cd2aef65b99
	--0xKhTmLbOuNdArY
	Content-Disposition: form-data; name="version"

	7.4.3
	--0xKhTmLbOuNdArY
	Content-Disposition: form-data; name="account"

	18535873
	--0xKhTmLbOuNdArY
	Content-Disposition: form-data; name="devicetype"

	1



	POST /user/login/phonepwdlogin.json HTTP/1.1
	Host: signup.onetwosixone.com
	Accept-Encoding: gzip
	Content-Type: application/x-www-form-urlencoded; charset=utf-8
	Content-Length: 124
	Connection: close
	Cache-Control: no-transform
	User-Agent: Mozilla/5.0 Coco 7.4.1 rv:800 (iPhone; iPhone OS 9.1; zh; iPhone 5)

	countrycode=86&password=asdfasdf&devicekey=CBF1F20B-F57B-4CBB-A3D8-7B4BBAA7E9DA&phone=13067881132&devicetype=0&version=7.4.1


	*****************************************************************************/
	memset(host, 0x00, 64);
	strcat(host, "onetwosixone.com");
	phost = strstr((char *)*buf, host);

	if(phost)
	{
		printf("find[%s]\n", host);
		update_vid_list(sta_mac,  "1", 10);
		printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^onetwosixone^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
	}


	/*





	这个通信帧由两个tcp组成：

	第一部分
		POST /user/login/phonepwdlogin.json HTTP/1.1
		Host: signup.onetwosixone.com
		Accept-Encoding: gzip
		Content-Type: application/x-www-form-urlencoded; charset=utf-8
		Content-Length: 124
		Connection: close
		Cache-Control: no-transform
		User-Agent: Mozilla/5.0 Coco 7.4.1 rv:800 (iPhone; iPhone OS 9.1; zh; iPhone 5)

	第二部分
		countrycode=86&password=asdfasdf&devicekey=CBF1F20B-F57B-4CBB-A3D8-7B4BBAA7E9DA&phone=13067881132&devicetype=0&version=7.4.1



	*/

	memset(host, 0x00, 64);
	strcat(host, "countrycode=");
	memset(keyword, 0x00, 64);
	strcat(keyword, "password=");

	phost = strstr((char *)*buf, host);

	if(phost)
	{
		printf("find[%s]\n", host);

		char countrycode[64];
		int i = 0;

		memset(countrycode, 0x00, 64);

		phost = phost + strlen(host);
		do
		{
			countrycode[i++] = *(phost++);
		}
		while ((*phost != '&') && (i < 63));

		printf("countrycode = %s\n", countrycode);


		char cc[64];

		memset(cc, 0x00, 64);
		strcat(cc, "cc(");
		strcat(cc, countrycode);
		strcat(cc, ")");

		update_vid_list(sta_mac,  cc, 10);
		printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^Coco^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");

		//printf("buf[%s]\n", *buf);

		pkeyword = strstr((char *)*buf, keyword);
		if(pkeyword)
		{
			printf("find[%s]\n", keyword);

			char coco_pwd[64];
			int i = 0;

			memset(coco_pwd, 0x00, 64);

			pkeyword = pkeyword + strlen(keyword);
			do
			{
				coco_pwd[i++] = *(pkeyword++);
			}
			while ((*pkeyword != '&') && (i < 63));

			printf("coco_pwd = %s\n", coco_pwd);

			char pwd[64];

			memset(pwd, 0x00, 64);
			strcat(pwd, "pwd(");
			strcat(pwd, coco_pwd);
			strcat(pwd, ")");

			update_vid_list(sta_mac,  pwd, 10);
			printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^Coco^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
		}

	}

	memset(host, 0x00, 64);
	strcat(host, "onetwosixone.com");
	memset(keyword, 0x00, 64);
	strcat(keyword, "name=\"password\"");

	phost = strstr((char *)*buf, host);

	if(phost)
	{
		printf("find[%s]\n", host);

		pkeyword = strstr((char *)*buf, keyword);
		if(pkeyword)
		{
			printf("find[%s]\n", keyword);

			char coco_pwd[64];
			int i = 0;

			memset(coco_pwd, 0x00, 64);

			pkeyword = pkeyword + strlen(keyword) + 4;  //两个 0x0d0x0a 0x0d0x0a
			do
			{
				coco_pwd[i++] = *(pkeyword++);
			}
			while ((*pkeyword != 0x0d) && (i < 63));

			printf("coco_pwd = %s\n", coco_pwd);

			char pwd[64];

			memset(pwd, 0x00, 64);
			strcat(pwd, "pwd(");
			strcat(pwd, coco_pwd);
			strcat(pwd, ")");

			update_vid_list(sta_mac,  pwd, 10);
			printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^Coco^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
		}

	}


	memset(host, 0x00, 64);
	strcat(host, "onetwosixone.com");
	memset(keyword, 0x00, 64);
	strcat(keyword, "name=\"account\"");

	phost = strstr((char *)*buf, host);

	if(phost)
	{
		printf("find[%s]\n", host);

		pkeyword = strstr((char *)*buf, keyword);
		if(pkeyword)
		{
			printf("find[%s]\n", keyword);

			char coco_account[64];
			int i = 0;

			memset(coco_account, 0x00, 64);

			pkeyword = pkeyword + strlen(keyword) + 4;  //两个 0x0d0x0a 0x0d0x0a
			do
			{
				coco_account[i++] = *(pkeyword++);
			}
			while ((*pkeyword != 0x0d) && (i < 63));

			printf("coco_account = %s\n", coco_account);

			char id[64];

			memset(id, 0x00, 64);
			strcat(id, "id(");
			strcat(id, coco_account);
			strcat(id, ")");

			update_vid_list(sta_mac,  id, 10);
			printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^Coco^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
		}

	}

	/*****************************************************************************/

//talkbox

//POST /aas.do HTTP/1.1
//Host: data.flurry.com
//Accept-Encoding: gzip, deflate
//Content-Type: application/octet-stream
//Content-Length: 356
//Accept-Language: zh-cn
//Accept: */*
//Connection: keep-alive
//User-Agent: TalkBox/1.95 CFNetwork/758.1.6 Darwin/15.0.0



//#define _GNU_SOURCE

	memset(host, 0x00, 64);
	strcat(host, "talkbox");
	phost = strcasestr((char *)*buf, host);

	if(phost)
	{
		printf("find[%s]\n", host);
		update_vid_list(sta_mac,  "1", 12);
		printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^TalkBox^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
	}





	/*****************************************************************************/


//POST /apkeyword033c63d HTTP/1.1
//Host: 91.108.56.188:443
//Content-Type: application/x-www-form-urlencoded
//Accept-Encoding: gzip
//Content-Length: 40
//Accept-Language: zh-Hans-CN, en-us;q=0.8
//Accept: */*
//Connection: keep-alive
//User-Agent: ph.telegra.Telegraph/51100 (unknown, iPhone OS 9.1, iPhone, Scale/2.000000)


	memset(host, 0x00, 64);
	strcat(host, "telegra");
	phost = strcasestr((char *)*buf, host);

	if(phost)
	{
		printf("find[%s]\n", host);
		update_vid_list(sta_mac,  "1", 13);
		
	}



	/* 91.108.56.0 - 91.108.56.255  */


	unsigned char *srcip = (unsigned char *)&(p->ip_src);
	if((srcip[0]==91)&&(srcip[1]==108)&&(srcip[2]==56))
	{
		printf("src_ip[%d.%d.%d.%d]\n", srcip[0], srcip[1], srcip[2], srcip[3]);
		update_vid_list(sta_mac,  "1", 13);
		printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^telegra^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
	}


	unsigned char *dstip = (unsigned char *)&(p->ip_dst);
	if((dstip[0]==91)&&(dstip[1]==108)&&(dstip[2]==56))
	{
		printf("dst_ip[%d.%d.%d.%d]\n", dstip[0], dstip[1], dstip[2], dstip[3]);
		update_vid_list(sta_mac,  "1", 13);
		printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^telegra^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");

	}
	/*****************************************************************************/


	/*
		443端口，ssl协议，必须用memmem寻找

	*/
	memset(host, 0x00, 64);
	strcat(host, "voxer");
	/* 不能用strstr，因为dns里含有0x00，截取了字符串  */
	phost = memmem((char *)*buf, len, host, strlen(host));

	if(phost)
	{
		printf("find[%s]\n", host);
		update_vid_list(sta_mac,  "1", 14);
		printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^voxer^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
	}

	/*抓取大众点评中的ID号*/
	memset(host, 0x00, 64);
	strcat(host, "dianping");
	phost = memmem((char *)*buf, len, host, strlen(host));

	if(phost)
	{
		/*寻找用户ID号*/
		/* 根据host和关键字过滤 */
		char *pdhost;

		printf("find dianping\n");
		pdhost = memmem ((char *)*buf,len,"api.",4);
		pkeyword = memmem ((char *)*buf,len,"userid=",7);

		if((pdhost)&&(pkeyword))
		{
			printf("find dianping id \n");
			memset(keyword,0x00,64);
			int i = 0;
			pkeyword = pkeyword + 7;
			do
			{
				keyword[i++] = *(pkeyword++);
			}
			while (((*pkeyword) != ' ') &&((*pkeyword) != '"') && (i < 63));
			if(keyword[1]!=0)
			{
				//printf("dianping id=%s\n", keyword);
				update_vid_list(sta_mac,  keyword, 15);
				printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^dianping^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
			}

		}
		pkeyword = memmem ((char *)*buf,len,"user_id%3D",10);
		if(pkeyword)
		{
			char keyword2[64];
			int i = 0;
			printf("find dianping id \n");
			memset(keyword2,0x00,64);
			pkeyword = pkeyword + strlen("user_id%3D");
			do
			{
				keyword2[i++] = *(pkeyword++);
			}
			while (((*pkeyword) != ' ') &&((*pkeyword) != '%') && (i < 63));
			if(keyword2[1]!=0)
			{
				//printf("dianping id=%s\n", keyword2);
				update_vid_list(sta_mac,  keyword2, 15);
				printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^dianping^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
			}
		}
	}

	/*京东抓取用户信息*/
	memset(host, 0x00, 64);
	strcat(host, "api.m.jd.com");
	phost = memmem((char *)*buf, len, host, strlen(host));
	if(phost)
	{
		printf("find jingdong\n");
		pkeyword = memmem((char *)*buf,len,"pin=",4);

		if(pkeyword)
		{
			char jdid[32];
			memset(jdid, 0x00, 32);

			pkeyword = pkeyword + 4;
			int i = 0;
			do
			{
				jdid[i++] = *(pkeyword++);

			}
			while (((*pkeyword) != '&') &&((*pkeyword) != ';') && (i < 31));

			//printf("jingdong id=%s\n", jdid);
			update_vid_list(sta_mac,  jdid, 16);
			printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^jingdong^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
		}
		char *pjdword;
		char *pjdword2;
		pjdword =memmem((char *)*buf,len,"pt_pin=",7);
		pjdword2 =memmem((char *)*buf,len,"pwdt_id=",8);
		if((pjdword)&&(pjdword2))
		{
			char jdid2[64];
			int i = 0;

			memset(jdid2, 0x00,64);

			pjdword2 = pjdword2 + strlen("pwdt_id=jd_");
			do
			{
				jdid2[i++] = *(pjdword2++);
			}
			while (((*pkeyword) != ';') &&((*pjdword2) != ';') && (i < 63));
			if(jdid2[1]!=0)
			{
				//printf("jingdong id=%s\n", jdid2);
				update_vid_list(sta_mac,  jdid2, 16);
				printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^jingdong^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
			}
		}
	}
	/*获取优酷上的用户ID和手机用户的手机号码*/
	memset(host, 0x00, 64);
	strcat(host, "youku.com");
	phost = memmem((char *)*buf, len, host, strlen(host));
	if(phost)
	{
		pkeyword = memmem ((char *)*buf , len,"username=",9);
		printf("find youku\n");
		if(pkeyword)
		{
			char youkuuser[64];
			int i = 0;
			memset (youkuuser,0x00,64);
			pkeyword = pkeyword+strlen("youku.com");
			do
			{
				youkuuser[i++]=*(pkeyword++);
			}
			while(((*pkeyword) != '&') && (i < 63));

			urldecode(youkuuser);
			if(youkuuser[1]!=0)
			{
				//printf("youku username=%s\n",youkuuser);
				update_vid_list(sta_mac,  youkuuser, 17);
				printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^youku^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
			}
		}
		char *pykb;
		char *pykc;
		/*另外的寻找用户名，若该用户名为中文与英文混编，读取相应的中文编码和英文字母及数字组成。若用户名为英文与数字混编，则能完整显示*/
		pykb = memmem((char *)*buf,len," k=",3);
		pykc = memmem((char *)*buf,len,"u=",2);

		if((pykb)&&(pykc))
		{
			char ykb[64];
			int i = 0;
			memset(ykb,0x00,64);

			pykb = pykb + strlen(" k=");
			do
			{
				ykb[i++]=*(pykb++);
			}
			while(((*pykb)!=';')&(i<63));

			urldecode(ykb);

			if(ykb[1]!=0)
			{
				//printf("youku user=%s\n",ykb);
				update_vid_list(sta_mac,  ykb, 17);
				printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^youku^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
			}
		}
	}

	/*米聊用户账号查找*/
	memset(host, 0x00, 64);
	strcat(host, "chat.xiaomi");
	phost = memmem((char *)*buf, len, host, strlen(host));
	if(phost)
	{
		char *pmlid;
		char *pmluser;
		printf("find miliao\n");
		pmlid = memmem((char *)*buf,len,"uuid=",5);
		pmluser = memmem ((char *)*buf,len,"user",4);

		if((pmlid)&&(pmluser))
		{
			char mlid[32],mluser[32];
			memset(mlid,0x00,32);
			memset(mluser,0x00,32);
			pmlid =pmlid+strlen("uuid=");
			int i=0;
			do
			{
				mlid[i++]=*(pmlid++);
			}
			while(((*pmlid)!='&')&&(i < 31));

			pmluser = pmluser+strlen("user");
			i=0;
			do
			{
				mluser[i++]=*(pmluser++);
			}
			while(((*pmluser)!='/')&&(i < 31));
			if(mlid[1]!=0)
			{
				//printf("miliao id=%s\n",mlid);
				update_vid_list(sta_mac,  mlid, 18);
				printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^miliao^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
			}
		}
	}
	/*携程用户ID信息*/
	memset(host, 0x00, 64);
	strcat(host, "ctrip.com");
	phost = memmem((char *)*buf, len, host, strlen(host));
	if(phost)
	{
		char *cuid;
		char *cvid;
		char *cflag;

		cuid = memmem((char *)*buf,len,"UID",3);
		cvid = memmem((char *)*buf,len,"Business",8);
		cflag = memmem((char *)*buf,len,"head",4);
		if(((cuid)&&(cvid))||((cuid)&&(cflag)))
		{
			char uid[64];
			int i = 0;
			memset(uid,0x00,64);
			cuid = cuid + strlen("UID")+3;
			do
			{
				uid[i++]=*(cuid++);
			}
			while(((*cuid)!='"')&&(i < 63));
			if(uid[1]!=0)
			{
				//printf("xiechen id=%s\n",uid);
				update_vid_list(sta_mac,  uid, 19);
				printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^xiechen^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
			}
		}
		char *cuid2;
		char *ctype;
		cuid2 = memmem((char *)*buf,len,"uid",3);
		ctype = memmem((char *)*buf,len,"channelType",11);
		if(cuid2&&cflag&&ctype)
		{
			char uid2[64];
			int i = 0;
			memset(uid2,0x00,64);
			cuid2 = cuid2 + strlen("uid")+3;
			do
			{
				uid2[i++]=*(cuid2++);
			}
			while(((*cuid2)!='"')&&(i < 63));

			if(uid2[1]!=0)
			{
				//printf("xiechen id=%s\n",uid2);
				update_vid_list(sta_mac,  uid2, 19);
				printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^xiechen^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
			}
		}
	}
	/*检测陌陌ID号*/
	memset(host, 0x00, 64);
	strcat(host, "momo");
	phost = memmem((char *)*buf, len, host, strlen(host));
	if(phost)
	{
		pkeyword = memmem((char *)*buf,len,"momoid=",7);
		printf("find momo\n");
		if(pkeyword)
		{
			char momoid[64];
			memset(momoid,0x00,64);
			pkeyword = pkeyword + strlen("momoid=");
			int i=0;
			do
			{
				momoid[i++] = *(pkeyword++);
			}
			while(((*pkeyword)!=' ')&&((*pkeyword)!='\n')&&((*pkeyword)!='\r')&&(i < 63)&&((*pkeyword)!='&'));
			if(momoid[3]!='+')
			{
				//printf("momoid =%s\n",momoid);
				update_vid_list(sta_mac,  momoid, 20);
				printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^momo^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
			}
		}
		char *pmomoid2;
		pmomoid2 = memmem((char *)*buf,len,"momoid%3D",9);

		if(pmomoid2)
		{
			char momoid2[64];
			int i = 0;

			memset(momoid2,0x00,64);

			pmomoid2 = pmomoid2 + strlen("momoid%3D");
			do
			{
				momoid2[i++] = *(pmomoid2++);
			}
			while(((*pmomoid2)!='%')&&(i < 63)&&(*pmomoid2)!='&');
			if(momoid2[1]!=0)
			{
				//printf("momoid=%s\n",momoid2);
				update_vid_list(sta_mac,  momoid2, 20);
				printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^momo^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
			}
		}
	}
	/*检测唱吧ID号*/
	memset(host, 0x00, 64);
	strcat(host, "changba");
	phost = memmem((char *)*buf, len, host, strlen(host));
	if(phost)
	{
		printf("find changba\n");
		pkeyword=memmem((char *)*buf,len,"curuserid=",10);
		if(pkeyword)
		{
			int i=0;
			char curuserid[32];

			memset(curuserid,0x00,32);

			pkeyword=pkeyword+strlen("curuserid=");
			do
			{
				curuserid[i++]=*(pkeyword++);
			}
			while(i<31&&((*pkeyword)!='&'));
			//printf("changba id:%s\n",curuserid);
			update_vid_list(sta_mac,  curuserid, 21);
			printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^changba^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
		}
	}
	/*检测滴滴打车ID号*/
	memset(host, 0x00, 64);
	strcat(host, "diditaxi");
	phost = memmem((char *)*buf, len, host, strlen(host));
	if(phost)
	{
		char *plng, *plat,*p_phone;
		printf("find diditaxi\n");
		p_phone=memmem((char *)*buf,len,"phone=",6);
		plng = strstr((char *)*buf, "lat=");
		plat = strstr((char *)*buf, "lng=");
		if ((plng)&&(plat)&&p_phone)
		{
			char lng[32],lat[32],phone[32];
			memset(phone,0x00,32);
			memset(lng, 0x00, 32);
			memset(lat, 0x00, 32);
			plng = plng + strlen("lng=");
			int i = 0;
			do
			{
				lng[i++] = *(plng++);
			}
			while (((*plng) != '&') && (i < 31));

			plat = plat + strlen("lat=");
			i = 0;
			do
			{
				lat[i++] = *(plat++);
			}
			while (((*plat) != '&') && (i < 31));

			printf("%s, %s\n", lng, lat);
			i=0;
			p_phone=p_phone+strlen("phone=");
			if(*p_phone>='0'&&*p_phone<='9')
			{
				do
				{
					phone[i++]=*(p_phone++);
				}
				while((*p_phone)!='&'&&i<32);
				//printf("diditaxi id:%s\n",phone);
				update_vid_list(sta_mac,  phone, 22);
				printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^diditaxi^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
			}
		}
	}
	memset(host, 0x00, 64);
	strcat(host, "didi");
	phost = memmem((char *)*buf, len, host, strlen(host));
	if(phost)
	{

		printf("find didi\n");
		char didi_num[32];
		char *pinfo;
		int i;
		memset(didi_num,0x00,32);

		pinfo = memmem ((char *)*buf, len, "vinfo=phone%3D",14);

		if(pinfo)
		{
			pinfo = pinfo + strlen("vinfo=phone%3D");
			i=0;
			do
			{
				didi_num[i++] = *(pinfo++);
			}
			while (((*pinfo)!='%')&&(i < 31));
			//printf("didi_num=%s\n",didi_num);
			update_vid_list(sta_mac,  didi_num, 22);
			printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^diditaxi^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
		}
	}
	/*检测飞信ID号*/
	memset(host, 0x00, 64);
	strcat(host, "fetion");
	phost = memmem((char *)*buf, len, host, strlen(host));
	if(phost)
	{
		printf("find feixin\n");
		pkeyword=memmem((char *)*buf,len,"fetionId=",9);
		if(pkeyword)
		{
			char id[32];
			memset(id,0x00,32);
			int i=0;
			pkeyword=pkeyword+strlen("fetionId=")+1;
			do
			{
				id[i++]=*(pkeyword++);
			}
			while(i<31&&((*pkeyword)!='"'));
			//printf("feixin id:%s\n",id);
			update_vid_list(sta_mac,  id, 23);
			printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^feixin^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
		}
	}


	/*检测快滴打车ID号*/
	memset(host, 0x00, 64);
	strcat(host, "kuaidadi");
	phost = memmem((char *)*buf, len, host, strlen(host));
	if(phost)
	{
		printf("find kuaidi\n");
		pkeyword=memmem((char *)*buf,len,"idx=",4);
		if(pkeyword)
		{
			char idx[32];
			memset(idx,0x00,32);
			pkeyword=pkeyword+strlen("idx=");
			int i=0;
			do
			{
				idx[i++]=*(pkeyword++);
			}
			while(i<32&&((*pkeyword)!='&'));
			//printf("kuaidi id:%s\n",idx);
			update_vid_list(sta_mac,  idx, 24);
			printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^kuaidi^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
		}
	}
	/* 检测美团ID号 */
	memset(host, 0x00, 64);
	strcat(host, "meituan");
	phost = memmem((char *)*buf, len, host, strlen(host));
	if(phost)
	{
		printf("find meituan\n");
		pkeyword = memmem((char *)*buf,len, "userid=",7);
		if(pkeyword)
		{
			char meituanid[32];
			memset(meituanid, 0x00, 32);
			pkeyword = pkeyword + strlen("userid=");
			int i = 0;
			if(((*pkeyword)!='-')&&((*pkeyword)!='0')) //排除-1
			{
				do
				{
					meituanid[i++] = *(pkeyword++);
				}
				while (((*pkeyword) != '&') &&((*pkeyword) != ' ')&&((*pkeyword) != '"') && (i < 32));
				//printf("meituan id:%s\n",meituanid);
				update_vid_list(sta_mac,  meituanid, 25);
				printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^meituan^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
			}
		}
	}
	memset(host, 0x00, 64);
	strcat(host, "meituan.com");
	phost = memmem((char *)*buf, len, host, strlen(host));
	if(phost)
	{
		printf("find meituan \n");
		pkeyword = memmem((char *)*buf,len,"userid:",7);

		if(pkeyword)
		{
			char meituanid2[64];
			int i;

			memset(meituanid2,0x00,64);

			pkeyword = pkeyword + strlen("userId:")+1;
			i=0;
			do
			{
				meituanid2[i++] = *(pkeyword++);
			}
			while(((*pkeyword)!='\r')&&(i < 63)&&(*pkeyword)!='&'&&(*pkeyword)!='"');
			if(meituanid2[3]!= 0)
			{
				//printf("meituanid2=%s\n",meituanid2);
				update_vid_list(sta_mac,  meituanid2, 25);
				printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^meituan2^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
				printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^meituan^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
			}
		}
	}
	/* 检测糯米ID号 */
	memset(host, 0x00, 64);
	strcat(host, "nuomi");
	phost = memmem((char *)*buf, len, host, strlen(host));
	if(phost)
	{
		printf("find nuomi\n");
		char *puserid;
		puserid=memmem((char *)*buf,len,"userid=",7);//能找到  但是会出现-1
		if(puserid)
		{
			puserid=puserid+strlen("userid=");
			if((*puserid)!='-')
			{
				char userid[32];
				int i=0;
				memset(userid,0x00,32);
				do
				{
					userid[i++]=*(puserid++);
				}
				while(i<31&&((*puserid)!='&'));
				//printf("nuomi userid:%s\n",userid);
				update_vid_list(sta_mac,  userid, 26);
				printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^nuomi^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
			}
		}

		char *puser,*puid;
		puser=memmem((char *)*buf,len,"&uid=",5);
		puid=memmem((char *)*buf,len," UID=",5);
		if(puser)
		{
			char user[32];
			i=0;
			memset(user,0x00,32);
			puser=puser+strlen("&uid=");

			do
			{
				user[i++]=*(puser++);
			}
			while(i<31&&((*puser)!='&'));
			//printf("nuomi user:%s\n",user);
			update_vid_list(sta_mac,  user, 26);
			printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^nuomi^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
		}


		if(puid)
		{
			char userid[32];
			i=0;
			memset(userid,0x00,32);
			puid=puid+strlen(" UID=");

			do
			{
				userid[i++]=*(puid++);
			}
			while(i<31&&((*puid)!=';')&&((*puid)!='\r'));
			//printf("nuomi id:%s\n",userid);
			update_vid_list(sta_mac,  userid, 26);
			printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^nuomi^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
		}
	}
	/* 检测土豆ID号 */
	memset(host, 0x00, 64);
	strcat(host, "tudou");
	phost = memmem((char *)*buf, len, host, strlen(host));
	if(phost)
	{
		pkeyword=memmem((char *)*buf,len,"u_id=",4);
		if(pkeyword)
		{
			char u_user[32];
			int i = 0;
			memset(u_user,0x00,32);

			pkeyword=pkeyword+strlen("u_id=");
			do
			{
				u_user[i++]=*(pkeyword++);
			}
			while(i<31&&((*pkeyword)!=';')&&((*pkeyword)!='\r'));
			//printf("tudou id:%s\n",u_user);
			update_vid_list(sta_mac,  u_user, 27);
			printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^tudou^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
		}
	}
	/* 检测支付宝号 */
	memset(host, 0x00, 64);
	strcat(host, "alipay.com");
	phost = memmem((char *)*buf, len, host, strlen(host));
	if(phost)
	{
		pkeyword = memmem((char *)*buf,len,"utdid",5);
		if(pkeyword)
		{
			char *palipayid;

			palipayid = memmem((char *)*buf,len,"uid",3);

			if(palipayid)
			{
				char alipayid[64];
				int i;

				memset(alipayid,0x00,64);

				palipayid = palipayid + strlen("uid")+3;
				i=0;
				do
				{
					alipayid[i++] = *(palipayid++);
				}
				while(((*palipayid)!='\r')&&(i < 63)&&(*palipayid)!='&'&&(*palipayid)!='"');
				if(strlen(alipayid)<20)
				{
					//printf("alipayid=%s\n",alipayid);
					update_vid_list(sta_mac,  alipayid, 49);
					printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^alipay^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
				}
			}
		}
	}

	memset(host, 0x00, 64);
	strcat(host, "alipay");
	phost = memmem((char *)*buf, len, host, strlen(host));
	if(phost)
	{
		char *palipayid2;
		char *palipayid3;
		palipayid2 = memmem((char *)*buf, len,"userId:",7);
		palipayid3 = memmem((char *)*buf, len,"&userId=",8);

		if(palipayid2)
		{
			char alipayid2[64];
			int i;

			memset(alipayid2,0x00,64);

			palipayid2 = palipayid2 + strlen("userId:")+1;
			i=0;
			do
			{
				alipayid2[i++] = *(palipayid2++);
			}
			while(((*palipayid2)!='\r')&&(i < 63)&&(*palipayid2)!='&'&&(*palipayid2)!='"');
			if(alipayid2[3]!=0)
			{
				//printf("alipayid2=%s\n",alipayid2);
				update_vid_list(sta_mac,  alipayid2, 49);
				printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^alipay2^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
			}
		}

		if(palipayid3)
		{
			char alipayid3[64];
			int i;

			memset(alipayid3,0x00,64);
			printf("userId=\n");
			palipayid3 = palipayid3 + strlen("&userId=");
			i=0;
			do
			{
				alipayid3[i++] = *(palipayid3++);
			}
			while(((*palipayid3)!='\r')&&(i < 63)&&(*palipayid3)!='&'&&(*palipayid3)!='"');
			if(alipayid3[3]!=0)
			{
				//printf("alipayid3=%s\n",alipayid3);
				update_vid_list(sta_mac,  alipayid3, 49);
				printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^alipay3^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
			}
		}
	}
	return 0;
}

static int parse_icmp_header(unsigned char **buf, int len, struct packet_info *p)
{
	int i, j;
//-------------------------------------------------------------------------
	fdebug(DEBUG_LEVEL_PROTOCOL_ICMP, "* parse ICMP\n");
//-------------------------------------------------------------------------
	fdebug(DEBUG_LEVEL_PROTOCOL_ICMP, "---------[icmp_packet_len=%04d]--------", len);

	j = 0;
	for(i = 0; i < len; i++)
	{
		if((i % 2) == 0)
			fdebug(DEBUG_LEVEL_PROTOCOL_ICMP, " ");
		if((i % 16) == 0)
		{
			fdebug(DEBUG_LEVEL_PROTOCOL_ICMP, " %d\n", j);
			j++;
		}
		fdebug(DEBUG_LEVEL_PROTOCOL_ICMP, "%02x", (*buf)[i]);
	}
//-------------------------------------------------------------------------
	fdebug(DEBUG_LEVEL_PROTOCOL_ICMP, "\n");
//-------------------------------------------------------------------------

	return 0;
}
