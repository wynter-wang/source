/*
	��������Ԫ
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/time.h>

#include <signal.h>

/* ��ȡָ���ļ��µ��ļ��� */
#include <dirent.h>
#include <sys/stat.h>

/* ͨ��luci�ӿڶ�ȡ���ã��������wap.h֮ǰ����Ϊ������ uint8_t ���� */
#include "readcfg.h"

#include "main.h"
#include "asdwifi.h"
#include "util.h"

#include "wifilog.h"

/***********************************************
	���ݱ���������̬���ɰ汾��Ϣ
***********************************************/
#define VERSION "gaethmon_v1.01"

#ifdef _PCAP
#define vPCAP "_pcap"
#else
#define vPCAP ""
#endif

FILE *PCAPLOG = NULL;

/* ���β��Կ�ʼʱ�� */
time_t t_begin;

int last_logfile_num;

char logfilename[64];

extern int mon;
extern int bQuit;

/* pcap֡�ļ���ÿ���Ƚϳ����Ҳ��ϲ����ʲ����ڴ汣���б���׷�ӷ�ʽд���ļ� */
char pcapfilename[64];

void end_test(void);

//-----------------------------------------------------------------------------
// �汾��Ϣ��ӡ
//-----------------------------------------------------------------------------
void usage()
{
    if(is_pro == 1)
        printf("%s_pro%s build@(%s %s)\n", VERSION, vPCAP, __DATE__, __TIME__);
    else
        printf("%s%s build@(%s %s)\n", VERSION, vPCAP, __DATE__, __TIME__);
}

//-----------------------------------------------------------------------------
// ����Ctrl+C��������Ӧ�Ĵ���
// ԭ����Ϣ������������ bStopBreak ��־λ������whileѭ��
// ��������ֱ�� exit(0)���ɣ���Ӧ�Ĳ��Ա��湤�������� exit_handler��ʵ��
// ����һ��ȫ�ֱ����Ķ���
//-----------------------------------------------------------------------------

static void sigint_handler(int sig)
{
    //�������exit����������exit_handler���
    exit(0);
}

static void sigterm_handler(int sig)
{
    //�������exit����������exit_handler���
    exit(0);
}

static void sigkill_handler(int sig)
{
    //�������exit����������exit_handler���
    exit(0);
}

//-----------------------------------------------------------------------------
//  ��������closeһ������ʱ����client�˽��ŷ����ݡ�����TCPЭ��Ĺ涨��
//  ���յ�һ��RST��Ӧ��client���������������������ʱ��ϵͳ�ᷢ��һ��
//  SIGPIPE�źŸ����̣����߽�����������Ѿ��Ͽ��ˣ���Ҫ��д�ˡ�
//  �����źŵ�Ĭ�ϴ������SIGPIPE�źŵ�Ĭ��ִ�ж�����terminate(��ֹ��
//  �˳�),����client���˳���������ͻ����˳����԰�SIGPIPE��ΪSIG_IGN��

//  ������socketͨ��ʱ������ע�����Ϣ�źţ��������������쳣�˳�
//-----------------------------------------------------------------------------
static void sigpipe_handler(int sig)
{
    /* ignore signal here - we will handle it after write failed */
}

//-----------------------------------------------------------------------------
//�����˳�ʱ��Ҫ��ɵ���ع��������籣�����ݵ�
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
        //һ�������dev_lan_ip���� 192.168.111.xx ϵ��
        strcat(deviceid_str, "[1]");
    } else if(device_idx == 1)
    {
        //���豸
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
            //��С���û���Ϊ������x86�����϶�д
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


/* ����ϵͳ��������wifi��Ҳ��ȡ����������֡ʱ */
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

    /* ��ȡ�����ͻ���ǿ������ */
    read_ispro();

    /* �鿴�汾 */
    if(argc > 1)
    {
        if(!strcmp(argv[1], "-v") || !strcmp(argv[1], "--version"))
            usage();
        return 0;
    }

    /* ע��Ctrl+C��Ϣ�����������ʱ�����˳���һ��ֱ��exit(0) */
    signal(SIGINT, sigint_handler);

    /* ���̱�kill����ϵͳ����ʱ���ᴥ������Ϣ���Լ�ʱ��������
     * ͬʱϵͳreboot����ʱ�ᷢ��������Ϣ������ʱ�������������� */
    signal(SIGTERM, sigterm_handler);
    signal(SIGKILL, sigkill_handler);

    /* SIGPIPE */
    signal(SIGPIPE, sigpipe_handler);

    /* �˳�����صĴ��� */
    atexit(exit_handler);

    /* ���ȶ�ȡ���� */
    read_cfg();

    printf("\nmode:    \n");
    printf("     channel[%d]\n", channel);
    printf("     enbale_switch[%d]\n", enable_switch);
    printf("     switch_interval[%d]\n", switch_interval);
    printf("     report_interval[%d]\n", report_interval);

    /**********************************************************
    ��ʼ���ӿڽӿڣ���ʼ���
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

        /* ��ģ��ģʽ�������ϱ�������в��� */
        if((time(NULL) - t_begin) > report_interval)
        {
			t_begin = time(NULL);
            printf("end_test...\n");
			snd_vidfile();
           // end_test();

            if(interval_cap_num == 0)
            {
                //����ϱ������û���յ��κ�֡���Ʋ������쳣�����ٽ��յ�����
                //һ�������������ŵ��л���ָ�
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
