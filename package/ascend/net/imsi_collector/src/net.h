#ifndef _NET_H_
#define _NET_H_


/* ���豸�����ڽ������豸�Ŀ��ƣ��ύ���� */
extern int svr_fd;                       /* ���豸��������ģʽ�����������������������ڽ��������� */
extern int cli_fd;					   /* ���豸��������ģʽ����������һ������ */



void start_tcpsvr(int port);
int connect_with_custom_timeout(char *host, int port);
void net_notify(char *notifystr);


#endif
