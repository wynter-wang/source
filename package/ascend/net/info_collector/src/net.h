#ifndef _NET_H_
#define _NET_H_


/* 从设备，用于接收主设备的控制，提交数据 */
extern int svr_fd;                       /* 从设备（服务器模式）：启动服务器侦听，用于接收新连接 */
extern int cli_fd;					   /* 从设备（服务器模式）：仅接收一个连接 */



void start_tcpsvr(int port);
int connect_with_custom_timeout(char *host, int port);
void net_notify(char *notifystr);


#endif
