#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>
#include <time.h>
#include <sys/time.h>
#include <fcntl.h>                     
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "tea.h"



/* ���豸�����ڽ������豸�Ŀ��ƣ��ύ���� */
int svr_fd = -1;                       /* ���豸��������ģʽ�����������������������ڽ��������� */
int cli_fd = -1;					   /* ���豸��������ģʽ����������һ������ */

int cli_nodify_fd = -1;

//��������:����socketΪ��������  
static int make_socket_non_blocking(int sfd)
{
    int flags, s;

    //�õ��ļ�״̬��־  
    flags = fcntl(sfd, F_GETFL, 0);
    if(flags == -1)
    {
        perror("fcntl");
        return -1;
    }
    //�����ļ�״̬��־  
    flags |= O_NONBLOCK;
    s = fcntl(sfd, F_SETFL, flags);
    if(s == -1)
    {
        perror("fcntl");
        return -1;
    }

    return 0;
}


int connect_with_custom_timeout(char *host, int port)
{
	struct hostent *he;
    struct sockaddr_in server;
    int ret;
    fd_set myset;
    struct timeval tv;
    int valopt;
    socklen_t lon;


    if((he = gethostbyname(host)) == NULL)
    {
        printf("gethostbyname() error\n");
        return -1;
    }

	//ȷ��֧������
    printf("ip_addr:%s\n",inet_ntoa(*((struct in_addr *)he->h_addr)));    

    //����socket
    if((cli_nodify_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        printf("socket() error\n");
        return -1;
    }

    make_socket_non_blocking(cli_nodify_fd);

    memset(&server, 0x00, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr = *((struct in_addr *)he->h_addr);

    /* ������ģʽ�����ܴ�connect�����жϷ���ֵ����Ҫͨ��select�ж� */
    ret = connect(cli_nodify_fd, (struct sockaddr *)&server, sizeof(server));
    if(ret < 0)
    {
        if(errno == EINPROGRESS)
        {
            //fprintf(stderr, "EINPROGRESS in connect() - selecting\n");
            do
            {
                /* 10���� */
                tv.tv_sec = 10;
                tv.tv_usec = 10000;
                FD_ZERO(&myset);
                FD_SET(cli_nodify_fd, &myset);
                ret = select(cli_nodify_fd + 1, NULL, &myset, NULL, &tv);
                if(ret < 0 && errno != EINTR)
                {
                    fprintf(stderr, "Error connecting %d - %s\n", errno, strerror(errno));
                    close(cli_nodify_fd);
                    cli_nodify_fd = -1;
                    return -1;
                } else if(ret > 0)
                {
                    // Socket selected for write 
                    lon = sizeof(int);
                    if(getsockopt(cli_nodify_fd, SOL_SOCKET, SO_ERROR, (void *)(&valopt), &lon) < 0)
                    {
                        fprintf(stderr, "Error in getsockopt() %d - %s\n", errno, strerror(errno));
                        close(cli_nodify_fd);
                        cli_nodify_fd = -1;
                        return -1;
                    }
                    // Check the value returned... 
                    if(valopt)
                    {
                        fprintf(stderr, "Error in delayed connection() %d - %s\n", valopt,
                                strerror(valopt));
                        close(cli_nodify_fd);
                        cli_nodify_fd = -1;
                        return -1;
                    }
                    break;
                } else
                {
                    fprintf(stderr, "Timeout in select() - Cancelling!\n");
                    close(cli_nodify_fd);
                    cli_nodify_fd = -1;
                    return -1;
                }
            }
            while (1);
        } else
        {
            fprintf(stderr, "Error connecting %d - %s\n", errno, strerror(errno));
            close(cli_nodify_fd);
            return -1;
        }
    }

    printf("connect() ok\n");
    
    return 0;

}


void net_notify(char *notifystr)
{
	int i;
	int len;
	int send_len;
	int snd_num;
	if(cli_nodify_fd != 0)
	{
		send_len = 0;
		len = strlen(notifystr);
		//printf(notifystr);
		for(i = 0; i < len/8+1; i ++)
		{
			tea_encrypt((uint32_t *)(notifystr+8*i), TEAKey);
			send_len += 8;
		}
		snd_num = write(cli_nodify_fd, notifystr, send_len);
		if (snd_num == -1)
			printf("send nofity failed\n");
		
		printf("send_notify() ok\n");  					
	}
			
}
