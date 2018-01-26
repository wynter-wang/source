#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>

#include "uci.h"
#include "tea.h"
#include "net.h"

#define FILEPATH "/tmp/person.dat"

time_t oldtime = 0;
extern int cli_nodify_fd;
int port = 9306;

//-----------------------------------------------------------------------------
//读取配置项接口
//-----------------------------------------------------------------------------
int read_item(char *cfg_path, char *value)
{
    struct uci_ptr ptr;
    struct uci_context *ctx = NULL;
    char path[64];

    /* !!!字符串常量传入有问题，赋值给变量，然后指针传入 */
    /* uci库接口设计的缺陷 */
    memset(path, 0x00, 64);
    strcat(path, cfg_path);

    ctx = uci_alloc_context();

    if(!ctx)
        return 0;

    if((uci_lookup_ptr(ctx, &ptr, path, true) != UCI_OK) ||
       (ptr.o == NULL || ptr.o->v.string == NULL))
    {
        //fprintf(stderr, "read_item_error: %s\n", path);
        uci_free_context(ctx);
        return 0;
    }

    if(ptr.flags & UCI_LOOKUP_COMPLETE)
        strcpy(value, ptr.o->v.string);

    uci_free_context(ctx);

    return 1;
}

/*
 * 检测文件是否被修改
 * 返回值大于0则表示文件被修改
 */
int file_is_modified(const char *path, time_t oldMTime)
{
	struct stat file_stat;
	int err = -1;
	
	err = stat(path, &file_stat);
	if(err != 0)
	{
		perror("[file_is_modified]");
		exit(-1);
	}
	
	return file_stat.st_mtime > oldMTime;
}

/*
 * 非阻塞发送数据到云平台
 */
void sendData(char *stream)
{
	int iRet = 0;
	char serverip[20] = {0};
	
	read_item("iwmoncfg.bbb.ftp_ip", serverip);
	iRet = connect_with_custom_timeout(serverip, port);
	
	if(iRet == 0)
	{
		net_notify(stream);
		usleep(100000);
	}
}

/* 判断文件是否存在 */
int check_file(char *file)
{
	if(access(file, 0) == 0)
		return 1;
	else
		return 0;
}

int file_size(char* filename)  
{  
    struct stat statbuf;  
    stat(filename, &statbuf);  
    int size=statbuf.st_size;  
  
    return size;  
}  

/*
 * 读取文件最后一行
 */
void readfile(void)
{
	FILE *fd;
	static const long max_len = 128;
	char buff[max_len + 1];
	oldtime = time(NULL);
	
	if(file_size(FILEPATH) == 0)
		return;
	
	if((fd = fopen(FILEPATH, "rb")) != NULL)  {      

		fseek(fd, -max_len, SEEK_END);            
		fread(buff, max_len-1, 1, fd);            
		fclose(fd);                              

		buff[max_len-1] = '\0';                   
		char *last_newline = strrchr(buff, '\n'); 
		char *last_line = last_newline + 1;         
		sendData(last_line);
		close(cli_nodify_fd);
	}
}

void readoneline(char *oneline)
{
	FILE *fp;
	
	fp = fopen(FILEPATH, "rb");
	if(fp == NULL)
		return;
	
	//while(!feof(fp))
	//{
		fgets(oneline, 128, fp);
	//}
	sendData(oneline);
	close(cli_nodify_fd);
	fclose(fp);
}

int main()
{
	char oneline[66];
	while(!check_file(FILEPATH))
	{
		usleep(100000);
	}
	readoneline(oneline);
	
	while(1)
	{
		if(file_is_modified(FILEPATH, oldtime) > 0)
		{
			readfile();
		}
		usleep(100000);
	}
	
	return 0;
}