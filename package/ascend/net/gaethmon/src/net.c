
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

#include "main.h"
#include "tea.h"



/* 从设备，用于接收主设备的控制，提交数据 */
int svr_fd = -1;                       /* 从设备（服务器模式）：启动服务器侦听，用于接收新连接 */
int cli_fd = -1;					   /* 从设备（服务器模式）：仅接收一个连接 */

int cli_nodify_fd = -1;

//函数功能:设置socket为非阻塞的  
static int make_socket_non_blocking(int sfd)
{
    int flags, s;

    //得到文件状态标志  
    flags = fcntl(sfd, F_GETFL, 0);
    if(flags == -1)
    {
        perror("fcntl");
        return -1;
    }
    //设置文件状态标志  
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

	//确认支持域名
    printf("ip_addr:%s\n",inet_ntoa(*((struct in_addr *)he->h_addr)));    

    //创建socket
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

    /* 非阻塞模式，不能从connect函数判断返回值，需要通过select判断 */
    ret = connect(cli_nodify_fd, (struct sockaddr *)&server, sizeof(server));
    if(ret < 0)
    {
        if(errno == EINPROGRESS)
        {
            //fprintf(stderr, "EINPROGRESS in connect() - selecting\n");
            do
            {
                /* 10毫秒 */
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







int start_tcpsvr(void)
{
	struct sockaddr_in server_addr;    // server address information
	int yes = 1;
	
    //创建socket句柄，tcp方式
    if((svr_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("socket");
        return -1;
    }

	//设置socket属性
    if(setsockopt(svr_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
    {
        perror("setsockopt");
        close(svr_fd);
        svr_fd = -1;
        return -1;
    }

    //绑定所有ip
    server_addr.sin_family = AF_INET;  // host byte order
    server_addr.sin_port = htons(21302);   // short, network byte order
    server_addr.sin_addr.s_addr = INADDR_ANY;   // automatically fill with my IP
    memset(server_addr.sin_zero, '\0', sizeof(server_addr.sin_zero));
    if(bind(svr_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
    {
        perror("bind");
        close(svr_fd);
		svr_fd = -1;
		sys_reboot();
		
        return -1;
    }

    //开始侦听
    if(listen(svr_fd, 3) == -1)
    {
        perror("listen");
        close(svr_fd);
        svr_fd = -1;
        return -1;
    }
    printf("listen port %d\n", 21302);	
    
    return 0;
}


//void start_tcpsvr(int port)
//{
//	struct sockaddr_in sock_in;
//	int reuse = 1;

//	//printlog("Initializing server port %d", port);

//	memset(&sock_in, 0, sizeof(struct sockaddr_in));
//	sock_in.sin_family = AF_INET;
//	sock_in.sin_addr.s_addr = htonl(INADDR_ANY);
//	sock_in.sin_port = htons(port);

//	if ((svr_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
//		err(1, "Could not open server socket");

//	if (setsockopt(svr_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
//		err(1, "setsockopt SO_REUSEADDR");

//	if (bind(svr_fd, (struct sockaddr*)&sock_in, sizeof(sock_in)) < 0)
//		err(1, "bind");

//	if (listen(svr_fd, 0) < 0)
//		err(1, "listen");
//} 