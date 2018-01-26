/*
	主函数单元
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/time.h>

#include <signal.h>

/* 获取指定文件下的文件数 */
#include <dirent.h>
#include <sys/stat.h>

/* 通过luci接口读取配置，必须放在wap.h之前，因为引用了 uint8_t 定义 */
#include "readcfg.h"

#include "main.h"
#include "asdwifi.h"
#include "util.h"

#include "wifilog.h"

/***********************************************
	根据编译条件动态生成版本信息
***********************************************/
#define VERSION "gaethmon_v1.01"

#ifdef _PCAP
#define vPCAP "_pcap"
#else
#define vPCAP ""
#endif

FILE *PCAPLOG = NULL;

/* 本次测试开始时间 */
time_t t_begin;

int last_logfile_num;

char logfilename[64];

extern int mon;
extern int bQuit;

/* pcap帧文件，每条比较长，且不合并，故不在内存保持列表，以追加方式写入文件 */
char pcapfilename[64];

void end_test(void);

//-----------------------------------------------------------------------------
// 版本信息打印
//-----------------------------------------------------------------------------
void usage()
{
    if(is_pro == 1)
        printf("%s_pro%s build@(%s %s)\n", VERSION, vPCAP, __DATE__, __TIME__);
    else
        printf("%s%s build@(%s %s)\n", VERSION, vPCAP, __DATE__, __TIME__);
}

//-----------------------------------------------------------------------------
// 捕获Ctrl+C，可作相应的处理
// 原来消息处理函数是设置 bStopBreak 标志位，跳出while循环
// 后来发现直接 exit(0)即可，相应的测试保存工作可以在 exit_handler里实现
// 减少一个全局变量的定义
//-----------------------------------------------------------------------------

static void sigint_handler(int sig)
{
    //必须调用exit函数，触发exit_handler句柄
    exit(0);
}

static void sigterm_handler(int sig)
{
    //必须调用exit函数，触发exit_handler句柄
    exit(0);
}

static void sigkill_handler(int sig)
{
    //必须调用exit函数，触发exit_handler句柄
    exit(0);
}

//-----------------------------------------------------------------------------
//  当服务器close一个连接时，若client端接着发数据。根据TCP协议的规定，
//  会收到一个RST响应，client再往这个服务器发送数据时，系统会发出一个
//  SIGPIPE信号给进程，告诉进程这个连接已经断开了，不要再写了。
//  根据信号的默认处理规则SIGPIPE信号的默认执行动作是terminate(终止、
//  退出),所以client会退出。若不想客户端退出可以把SIGPIPE设为SIG_IGN。

//  当程序含socket通信时，必须注意该消息信号，否则会引起程序异常退出
//-----------------------------------------------------------------------------
static void sigpipe_handler(int sig)
{
    /* ignore signal here - we will handle it after write failed */
}

//-----------------------------------------------------------------------------
//程序退出时需要完成的相关工作，比如保持数据等
//-----------------------------------------------------------------------------
static void exit_handler(void)
{
    printf("exit query\n");
 //   end_test();
}

//asd000001[1]
void get_deviceid_str(char *str)
{
    char deviceid_str[64];

    memset(deviceid_str, 0x00, 64);
    strcpy(deviceid_str, device_id);

    if(device_idx == 0)
    {
        //一般情况，dev_lan_ip不是 192.168.111.xx 系列
        strcat(deviceid_str, "[1]");
    } else if(device_idx == 1)
    {
        //主设备
        strcat(deviceid_str, "[");
        strcat(deviceid_str, dev_wan_ip);
        strcat(deviceid_str, "]");
    } else if(device_idx == 2)
    {
        strcat(deviceid_str, "[2]");
    } else if(device_idx == 3)
    {
        strcat(deviceid_str, "[3]");
    } else if(device_idx == 4)
    {
        strcat(deviceid_str, "[4]");
    } else if(device_idx == 5)
    {
        strcat(deviceid_str, "[5]");
    } else if(device_idx == 6)
    {
        strcat(deviceid_str, "[6]");
    }
    sprintf(str, "%s", deviceid_str);

}

struct pcap_file_header {
    u_int32_t magic;                   /* 0xa1b2c3d4 */
    u_int16_t version_major;           /* magjor Version 2 */
    u_int16_t version_minor;           /* magjor Version 4 */
    int32_t thiszone;                  /* gmt to local correction */
    u_int32_t sigfigs;                 /* accuracy of timestamps */
    u_int32_t snaplen;                 /* max length saved portion of each pkt */
    u_int32_t linktype;                /* data link type (LINKTYPE_*) */
};

void open_pcap_file(void)
{
    char timestamp[20];
    char device_id[32];
    struct pcap_file_header pfh;

    memset(timestamp, 0x00, 20);
    memset(device_id, 0x00, 32);

    get_time_stamp(&timestamp[0]);
    get_deviceid_str(&device_id[0]);

    if(PCAPLOG == NULL)
    {
        //sprintf(pcapfilename, "/tmp/%s_%s.pcap", device_id, timestamp);
        sprintf(pcapfilename, "/mnt/%s_%s.pcap", device_id, timestamp);
        sprintf(pcapfilename, "%s_%s.pcap", device_id, timestamp);
        printf("pacp_filename:%s\n", pcapfilename);

        PCAPLOG = fopen(pcapfilename, "wb");
        if(PCAPLOG == NULL)
        {
            printf("couldn't open pcap_log_file[%s]\n", pcapfilename);
        } else
        {
            //大小端置换，为了能在x86机器上读写
            pfh.magic = le32toh(0xa1b2c3d4);
            pfh.version_major = le16toh(2);
            pfh.version_minor = le16toh(4);
            pfh.thiszone = le32toh(0);
            pfh.sigfigs = le32toh(0);
            pfh.snaplen = le32toh(65535);
            pfh.linktype = le32toh(1);
            fwrite(&pfh, sizeof(pfh), 1, PCAPLOG);
        }
    }
}


/* 重启系统，当发现wifi再也获取不到新数据帧时 */
void sys_reboot(void)
{
    FILE *pipe_stream;

    pipe_stream = popen("reboot", "r");
    if(pipe_stream == NULL)
    {
        perror("command error");
    }
    pclose(pipe_stream);

}

//-----------------------------------------------------------------------------
//
//-----------------------------------------------------------------------------
int main(int argc, char **argv)
{
    int ret;

    /* 读取基本型或增强型配置 */
    read_ispro();

    /* 查看版本 */
    if(argc > 1)
    {
        if(!strcmp(argv[1], "-v") || !strcmp(argv[1], "--version"))
            usage();
        return 0;
    }

    /* 注册Ctrl+C消息处理，方便调试时即可退出，一般直接exit(0) */
    signal(SIGINT, sigint_handler);

    /* 进程被kill或者系统重启时，会触发该消息，以及时保存数据
     * 同时系统reboot命令时会发送以下消息，开启时会引起重启变慢 */
    signal(SIGTERM, sigterm_handler);
    signal(SIGKILL, sigkill_handler);

    /* SIGPIPE */
    signal(SIGPIPE, sigpipe_handler);

    /* 退出是相关的处理 */
    atexit(exit_handler);

    /* 首先读取配置 */
    read_cfg();

    printf("\nmode:    \n");
    printf("     channel[%d]\n", channel);
    printf("     enbale_switch[%d]\n", enable_switch);
    printf("     switch_interval[%d]\n", switch_interval);
    printf("     report_interval[%d]\n", report_interval);

    /**********************************************************
    初始化接口接口，开始监控
    ***********************************************************/
    ret = start_mon();

    if(ret == 0)
    {
        printf("Segmentation Fault.\n");
        return 0;
    }

//-----------------------------------------------------------------------------

    unsigned int interval_cap_num = 0;
//    start_test();
	t_begin = time(NULL);
    while (1)
    {

        if(get_packet() > 0)
            interval_cap_num++;

        /* 主模块模式，根据上报间隔进行测试 */
        if((time(NULL) - t_begin) > report_interval)
        {
			t_begin = time(NULL);
            printf("end_test...\n");
			snd_vidfile();
           // end_test();

            if(interval_cap_num == 0)
            {
                //如果上报间隔内没有收到任何帧，推测网卡异常，不再接收到数据
                //一般重启，或者信道切换后恢复
                printf("sys_reboot\n");
                //sys_reboot();
            }

            printf("restart_test...\n");
            interval_cap_num = 0;
        }

    }

    printf("end\n");
    return 0;
}
