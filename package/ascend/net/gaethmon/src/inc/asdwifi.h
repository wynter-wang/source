/*
*/

#ifndef _ASDWIFI_H_
#define _ASDWIFI_H_

//-----------------------------------------------------------------------------
//全局常量定义
//-----------------------------------------------------------------------------

//调试信息级别及分类定义，支持32个独立分类
#define DEBUG_LEVEL_NONE 			0x00000000

#define DEBUG_LEVEL_PARSER_LOG 		0x00000001	
#define DEBUG_LEVEL_MIN 			0x00000002
#define DEBUG_LEVEL_SUBTYPE_STAS	0x00000004
#define DEBUG_LEVEL_PACKET_RAW 		0x00000008
#define DEBUG_LEVEL_RADIO 			0x00000010
#define DEBUG_LEVEL_PACKET_INFO 	0x00000020
#define DEBUG_LEVEL_80211_HEAD	 	0x00000040
#define DEBUG_LEVEL_80211_ELEMS 	0x00000080

#define DEBUG_LEVEL_STA_STATISTICS 	0x00000100
#define DEBUG_LEVEL_DURATION    	0x00000200
#define DEBUG_LEVEL_CHANNEL_SWITCH  0x00000400
#define DEBUG_LEVEL_A			    0x00000800
#define DEBUG_LEVEL_B  				0x00001000
#define DEBUG_LEVEL_C  				0x00002000
#define DEBUG_LEVEL_D  				0x00004000
#define DEBUG_LEVEL_E  				0x00008000

#define DEBUG_LEVEL_PROTOCOL_LLC  	0x00010000
#define DEBUG_LEVEL_PROTOCOL_IP   	0x00020000
#define DEBUG_LEVEL_PROTOCOL_UDP  	0x00040000
#define DEBUG_LEVEL_PROTOCOL_TCP  	0x00080000
#define DEBUG_LEVEL_PROTOCOL_HTTP  	0x00100000 
#define DEBUG_LEVEL_PROTOCOL_ICMP  	0x00200000
#define DEBUG_LEVEL_PROTOCOL_OLSR  	0x00400000
#define DEBUG_LEVEL_PROTOCOL_QQ     0x00800000


#define DEBUG_LEVEL_PROTOCOL_ERROR  0x80000000

//MAC地址字节数
#define MAC_LEN			6

#define VISIT_LOG_INTERVAL    3 		//单位：秒
#define VISIT_STATISTICS_CYCLE  3600  	//单位：秒

#define MAX_NODES		255
#define MAX_ESSIDS		255
#define MAX_BSSIDS		255
#define MAX_HISTORY		255
#define MAX_CHANNELS	64
#define MAX_ESSID_LEN	32             //最大长度32字节，ESSID为中文时乱码

/*
		 12<----> 540;
		 11<----> 480;
		 10<----> 360;
		 9<----> 240;
		 8<----> 180;
		 7<----> 120;
		 6<----> 110;
		 5<----> 90;
		 4<----> 60;
		 3<----> 50;
		 2<----> 20;
		 1<----> 10;
*/

/*
0	1	BPSK	1/2	6.50	7.20	13.50	15.00
1	1	QPSK	1/2	13.00	14.40	27.00	30.00
2	1	QPSK	3/4	19.50	21.70	40.50	45.00
3	1	16-QAM	1/2	26.00	28.90	54.00	60.00
4	1	16-QAM	3/4	39.00	43.30	81.00	90.00
5	1	64-QAM	2/3	52.00	57.80	108.00	120.00
6	1	64-QAM	3/4	58.50	65.00	121.50	135.00
7	1	64-QAM	5/6	65.00	72.20	135.00	150.00
8	2	BPSK	1/2	13.00	14.40	27.00	30.00
9	2	QPSK	1/2	26.00	28.90	54.00	60.00
10	2	QPSK	3/4	39.00	43.30	81.00	90.00
11	2	16-QAM	1/2	52.00	57.80	108.00	120.00
12	2	16-QAM	3/4	78.00	86.70	162.00	180.00
13	2	64-QAM	2/3	104.00	115.60	216.00	240.00
14	2	64-QAM	3/4	117.00	130.00	243.00	270.00
15	2	64-QAM	5/6	130.00	144.40	270.00	300.00
16	3	BPSK	1/2	19.50	21.70	40.50	45.00
17	3	QPSK	1/2	39.00	43.30	81.00	90.00
18	3	QPSK	3/4	58.50	65.00	121.50	135.00
19	3	16-QAM	1/2	78.00	86.70	162.00	180.00
20	3	16-QAM	3/4	117.00	130.00	243.00	270.00
21	3	64-QAM	2/3	156.00	173.30	324.00	360.00
22	3	64-QAM	3/4	175.50	195.00	364.50	405.00
23	3	64-QAM	5/6	195.00	216.70	405.00	450.00
24	4	BPSK	1/2	26.00	28.80	54.00	60.00
25	4	QPSK	1/2	52.00	57.60	108.00	120.00
26	4	QPSK	3/4	78.00	86.80	162.00	180.00
27	4	16-QAM	1/2	104.00	115.60	216.00	240.00
28	4	16-QAM	3/4	156.00	173.20	324.00	360.00
29	4	64-QAM	2/3	208.00	231.20	432.00	480.00
30	4	64-QAM	3/4	234.00	260.00	486.00	540.00
31	4	64-QAM	5/6	260.00	288.80	540.00	600.00
*/

// 12 + 32

#define MAX_RATES		44             // 12 legacy rates and 32 MCS
#define MAX_FSTYPE		0xff

//-----------------------------------------------------------------------------
// default config values 
//-----------------------------------------------------------------------------
#define INTERFACE_NAME		"wlan0"
#define CHANGE_CHANNEL_INTERVAL 10000  // msec 
#define CHANNEL_DEFAULT 0              // 1号信道，从0开始到13

/* packet types we actually care about, e.g filter */
#define PKT_TYPE_CTRL		0x000001
#define PKT_TYPE_MGMT		0x000002
#define PKT_TYPE_DATA		0x000004

#define PKT_TYPE_BADFCS		0x000008   //错误的FCS帧类型

#define PKT_TYPE_BEACON		0x000010
#define PKT_TYPE_PROBE		0x000020
#define PKT_TYPE_ASSOC		0x000040
#define PKT_TYPE_AUTH		0x000080
#define PKT_TYPE_RTS		0x000100
#define PKT_TYPE_CTS		0x000200
#define PKT_TYPE_ACK		0x000400
#define PKT_TYPE_NULL		0x000800

#define PKT_TYPE_ARP		0x001000
#define PKT_TYPE_IP			0x002000
#define PKT_TYPE_ICMP		0x004000
#define PKT_TYPE_UDP		0x008000
#define PKT_TYPE_TCP		0x010000
#define PKT_TYPE_OLSR		0x020000
#define PKT_TYPE_OLSR_LQ	0x040000
#define PKT_TYPE_OLSR_GW	0x080000
#define PKT_TYPE_BATMAN		0x100000
#define PKT_TYPE_MESHZ		0x200000

#define PKT_TYPE_ALL_MGMT	(PKT_TYPE_BEACON | PKT_TYPE_PROBE | PKT_TYPE_ASSOC | PKT_TYPE_AUTH)
#define PKT_TYPE_ALL_CTRL	(PKT_TYPE_RTS | PKT_TYPE_CTS | PKT_TYPE_ACK)
#define PKT_TYPE_ALL_DATA	(PKT_TYPE_NULL | PKT_TYPE_ARP | PKT_TYPE_ICMP | PKT_TYPE_IP | \
				 PKT_TYPE_UDP | PKT_TYPE_TCP | PKT_TYPE_OLSR | PKT_TYPE_OLSR_LQ | \
				 PKT_TYPE_OLSR_GW | PKT_TYPE_BATMAN | PKT_TYPE_MESHZ)

#define WLAN_MODE_AP		0x01
#define WLAN_MODE_IBSS		0x02
#define WLAN_MODE_STA		0x04
#define WLAN_MODE_PROBE		0x08
#define WLAN_MODE_BRIDGE	0x10  //网桥模式

#define PHY_FLAG_SHORTPRE	0x0001
#define PHY_FLAG_BADFCS		0x0002     /* radiotap的fcs校验不通过 */
#define PHY_FLAG_A		0x0010
#define PHY_FLAG_B		0x0020
#define PHY_FLAG_G		0x0040
#define PHY_FLAG_MODE_MASK	0x00f0


#define RECV_BUFFER_SIZE	655350          /* not used by default */

#ifndef ARPHRD_IEEE80211_RADIOTAP
#define ARPHRD_IEEE80211_RADIOTAP 803  /* IEEE 802.11 + radiotap header */
#endif

#ifndef ARPHRD_IEEE80211_PRISM
#define ARPHRD_IEEE80211_PRISM 802     /* IEEE 802.11 + Prism2 header  */
#endif

#define max(_x, _y) ((_x) > (_y) ? (_x) : (_y))
#define min(_x, _y) ((_x) < (_y) ? (_x) : (_y))


//-----------------------------------------------------------------------------
// 物理帧数据结构
//-----------------------------------------------------------------------------
struct packet_info {
    /* general */
    unsigned int pkt_types;            /* bitmask of packet types */



    /* wlan mac */
    unsigned int wlan_len;             /* packet length */
    unsigned int wlan_type;            /* frame control field */
    unsigned int pkt_fc;			   // 原始的FrameControl
    unsigned char wlan_src[MAC_LEN];
    unsigned char wlan_dst[MAC_LEN];
    unsigned char wlan_bssid[MAC_LEN];
    char wlan_essid[MAX_ESSID_LEN];
    u_int64_t wlan_tsf;                /* timestamp from beacon */
    unsigned int wlan_bintval;         /* beacon interval */
    unsigned int wlan_mode;            /* AP, STA or IBSS */
    unsigned char wlan_channel;        /* channel from beacon, probe */
    unsigned char ap_ecypt;			   // AP的加密方式，从beacon帧中获取  [n|n|n|n|wps|wpa2|wpa|wep]  
    //unsigned char wlan_qos_class;      /* for QDATA frames */
    unsigned int wlan_nav;             /* frame NAV duration */
    unsigned int wlan_seqno;           /* sequence number */
    unsigned int qos_ctrl;             /* qos_control_field */

    /* flags */
    unsigned int wlan_wep:1,           /* WEP on/off */
     wlan_retry:1;

    /* IP */
    unsigned int ip_src;
    unsigned int ip_dst;
    unsigned int port_src;
    unsigned int port_dst;
    unsigned int olsr_type;
    unsigned int olsr_neigh;
    unsigned int olsr_tc;

    /* calculated from other values */
    unsigned int pkt_duration;         /* packet "airtime" */
    int pkt_chan_idx;                  /* received while on channel */
    int wlan_retries;                  /* retry count for this frame */
};

//-----------------------------------------------------------------------------
//系统配置参数，从启动命令行里读取
//-----------------------------------------------------------------------------
struct config {
    char ifname[32];                   //interface name
    unsigned int debug_level;         //
    int poll_select_times;             //
    int channel_default;               //  
    int channel_max;                   //
    int current_channel;               // index into channels array 
    int change_channel_interval;       // 
    int recv_buffer_size;              //

    unsigned char do_change_channel;
    unsigned char do_log_packetlist;

    int arphrd;                        // the device ARP type
    //int paused;
    int num_channels;
};

 

// 系统全局配置
extern struct config conf;



//
void fdebug(unsigned int level, const char *fmt, ...);

//根据当前时间产生时间戳字符串
int get_time_stamp(char *timestr);

int start_mon(void);
int get_packet(void);



void fprint_http(struct packet_info *p, char *httpstr);

int nonblock_connect_with_custom_timeout(char *host, int port);
int nonblock_connect_with_custom_timeout_senddata(char *host, int port);

#endif
