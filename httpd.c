//gcc -o httpd httpd.c ./crypto/sha1.c ./crypto/base64_encoder.c ./http_parser/http_parser.c

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <sys/epoll.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define IP "172.16.0.4"
#define SIZE 1024

#include "./crypto/sha1.h"
#include "./crypto/base64_encoder.h"
#include "./http_parser/http_parser.h"

const char* GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

#define HEAD "HTTP/1.0 200 OK\r\n" \
			 "Content-Type: %s; charset=utf-8\r\n" \
			 "Transfer-Encoding: chunked\r\n" \
			 "Connection: Keep-Alive\r\n" \
			 "Accept-Ranges:bytes\r\n" \
			 "Content-Length:%d\r\n\r\n"


//客户端结构体  有的是http请求，有的是websocket连接
typedef struct session {
	int 			fd;				
	char 			addr[64];
	int 			is_shake_hand;	// 是否是websocket连接,是否已经握手
	char 			* 	data;			// 读取数据的buf
	uint8_t 		sha1_data[256];
	int 			sha1_size;

	struct session * 	next;
}session;

//不带头的单链表
session * client_list = NULL;
session * tail = NULL;

static char url_buf[1024];//保存GET 内容

static int on_url(http_parser*p, const char *at, size_t length) {
	strncpy(url_buf, at, length);
	url_buf[length] = '\0';
	return 0;
}

static http_parser_settings settings = {
	.on_url = on_url,
};
static http_parser parser;

void save_log(char *buf);
const char *get_filetype(const char *filename); //根据扩展名返回文件类型描述
int get_file_content(const char *file_name, char **content);
int make_http_content(const char *command, char **content);
char LOGBUF[1024];

static int tcp_socket(int port);
static int sp_add(int efd, int sock, void *ud);

static void handle_ws(session *s);
static void ws_send_data(int fd,char* data, int len);
static void ws_on_recv_data(session *s,int fd,char* data, unsigned int len);

void handle_accept(int lfd,int efd);
void handle_recv(session *s,int efd);
void daemon_run();
int main(int argc,char *argv[])
{
	if(argc != 2)
	{
		printf("Usage : %s port\n",argv[0]);
		return 1;
	}
	daemon_run();
	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

    http_parser_init(&parser, HTTP_REQUEST);
	int port = atoi(argv[1]);
	int lfd = tcp_socket(port);
	assert(lfd > 0);
	int efd = epoll_create(1);
	assert(efd > 0);
	session server;
	server.fd = lfd;
	sp_add(efd, lfd, &server);

	struct epoll_event event[1024];
	printf("server listen on %s:%d\n",IP,port);

	//epoll 同步io 阻塞
	for(;;)
	{   
		int r = epoll_wait(efd, event, 1024, -1);
		for(int i = 0; i < r; i++)
		{
			session *s = (session *)event[i].data.ptr;
			int fd = s->fd;
			if(fd == lfd && event[i].events & EPOLLIN)
			{
				handle_accept(lfd, efd);
			}
			else if(event[i].events & EPOLLIN)
			{
				handle_recv(s, efd);
			}
		}
	}
	close(lfd);
	close(efd);
	return 0;
}


void handle_accept(int lfd,int efd)
{
	struct sockaddr_in cli_addr;
	bzero(&cli_addr,sizeof(cli_addr));
	socklen_t len = sizeof(cli_addr);

	int cfd = accept(lfd,(struct sockaddr*)&cli_addr,&len);
	assert(cfd > 0);

	session *ns = malloc(sizeof(*ns));// session;
	ns->is_shake_hand = 0;
	ns->fd = cfd;
	ns->data = (char*)malloc(SIZE);//new char[SIZE];
	ns->next = NULL;
	sprintf(ns->addr,"%s:%d",inet_ntoa(cli_addr.sin_addr),ntohs(cli_addr.sin_port));

	if(client_list == NULL)
	{
		client_list = ns;
		tail = ns;
	}
	else
	{
		tail->next = ns;
		tail = ns;
	}
	sp_add(efd, cfd, (void*)ns);
	printf("new client fd = %d from %s:%d\n",
		cfd,inet_ntoa(cli_addr.sin_addr),ntohs(cli_addr.sin_port));

	memset(LOGBUF,0,sizeof(LOGBUF));
	sprintf(LOGBUF,"new client fd = %d from %s:%d\n",
		cfd,inet_ntoa(cli_addr.sin_addr),ntohs(cli_addr.sin_port));
	save_log(LOGBUF);
}

void handle_recv(session *s,int efd){
	int fd = s->fd;
	char tmp[64];
	char head[128];
	memset(s->data,0,1024);
	int ret = recv(fd, s->data, 1024,0);
	if(ret > 0 )
	{   
		s->data[ret] = '\0';
		printf("recv from:%d ,msg_len = %d\n",fd,ret);

		if(strstr(s->data,"websocket") || s->data[0] == 0xffffff81 || s->data[0] == 0xffffff82)
		{
			printf("client %d %s websocket req\n",fd,s->addr);
			
			handle_ws(s);
		}
		else
		{	
			//http请求包不止50
			if(strlen(s->data) < 50)//websocket有时候出现一些不正常包
			{
				printf("%x %d strlen() < 50\n",s->data[0],fd);
				return;
			}
            printf("client %d %s http req\n",fd,s->addr);
			//printf("%s\n",s->data);

            //解析出GET 内容
			http_parser_execute(&parser, &settings, s->data, strlen(s->data));
            //printf("GET:%s\n",url_buf);
            char *content = NULL;
			int ilen = make_http_content(url_buf, &content); //根据用户在GET中的请求，生成相应的回复内容
			if (ilen > 0)
			{
				//printf("%s\n",content);
				send(fd, content, ilen, 0); //将回复的内容发送给client端socket
                free(content);
			}
			else{
				printf("null content\n");
			}
		}
	}
	else if(ret <= 0)
	{
		epoll_ctl(efd,EPOLL_CTL_DEL,fd,NULL); 
		close(fd);

        memset(LOGBUF,0,sizeof(LOGBUF));
		sprintf(LOGBUF,"%s close\n",s->addr);
		save_log(LOGBUF);

        char addr[64];
        sprintf(addr,"%s",s->addr);
        int flag = s->is_shake_hand;

        if(client_list->fd == fd)
		{
			session* p = client_list;
            printf("closed client fd:%d %s\n",fd,p->addr);

			client_list = p->next;
            free(p->data);
			free(p);
		}
		else
		{
			for(session * it = client_list; it->next!=NULL; it = it->next)
			{
				if(it->next->fd == fd)
				{
					session* p = it->next;
                    printf("closed client fd:%d %s\n",fd,p->addr);
					it->next = p->next;
					free(p->data);
			        free(p);
					break;
				}
			}
		}
        //加入了聊天室的人退出了才能广播
        if(flag == 1)
        {
            for(session * it = client_list; it != NULL; it = it->next)
		    {
                if(it->is_shake_hand == 1)
                {
                    sprintf(tmp,"client %d 离开了群聊",fd);
			        ws_send_data(it->fd, tmp, strlen(tmp));
                }
		    }
        }    	
	}
}

// 收到的是一个数据包;
static void ws_on_recv_data(session *s,int fd,char* data, unsigned int len) {
	printf("ws_on_recv_data\n");
	/*
	判断是否是最后一个包
	第一个字节  [0,7]，第一位是FIN，1000 ，文本类型0001/ 二进制类型0002
	0x81  0x82
	*/
	if (data[0] != 0xffffff81 && data[0] != 0xffffff82) {
		printf("data[0] != 0xffffff81 && data[0] != 0xffffff82\n");
		return;
	}
	/*
	8(MASK) 9 0 1 2 3 4 5(Payload len (7))
	& 0111 1111
	*/

	//Masking-key, if MASK set to 1
	//判断MASK位是否为1
	unsigned int flag_mask = data[1] & 0x80;//1000 0000
	//printf("flag_mask %d\n",flag_mask);

	unsigned int data_len = data[1] & 0x7f;
	int head_size = 2;
	printf("ws data_len: %u\n",data_len);

	if (data_len == 126) { // 后面两个字节表示的是数据长度;data[2], data[3]
		data_len = data[3] | (data[2] << 8);
		head_size += 2;
	}
	else if (data_len == 127) { // 后面8个字节表示数据长度; 2, 3, 4, 5 | 6, 7, 8, 9
		unsigned int low = data[5] | (data[4] << 8) | (data[3] << 16) | (data[2] << 24);
		unsigned int hight = data[9] | (data[8] << 8) | (data[7] << 16) | (data[6] << 24);

		data_len = low;
		head_size += 8;
	}


	char* body = data + head_size;

	if(flag_mask == 128){
		char* mask = data + head_size;
		body += 4;

		for (unsigned int i = 0; i < data_len; i++) { // 遍历后面所有的数据;
			body[i] = body[i] ^ mask[i % 4];
		}
	}


	// test
	static char test_buf[4096];
	memcpy(test_buf, body, data_len);
	test_buf[data_len] = '\0';
	printf("recv ws_data:%s\n", test_buf);

	memset(LOGBUF,0,sizeof(LOGBUF));
	sprintf(LOGBUF,"%s :%s\n",s->addr,test_buf);
	save_log(LOGBUF);

    //群发聊天室
	for(session * it = client_list;it!=NULL;it = it->next)
	{
		if(it->fd != fd && it->is_shake_hand == 1)
		{	
			printf("广播给 %d\n",it->fd);
			char tmp[1024];
			sprintf(tmp,"client %d : %s",s->fd, test_buf);
			ws_send_data(it->fd,tmp,strlen(tmp));
		}
	}
}
static void ws_send_data(int fd,char* data, int len) {
	int head_size = 2;
	if (len > 125 && len < 65536) { // 两个字节[0, 65535]
		head_size += 2;
	}
	else if (len >= 65536) { // 不做处理
		head_size += 8;
	}

	unsigned char* data_buf = (unsigned char*)malloc(head_size + len);
	data_buf[0] = 0x81;	//1000 0001
	if (len <= 125) {
		data_buf[1] = len;//不考虑mask
	}
	else if (len > 125 && len < 65536) {
		data_buf[1] = 126;
		data_buf[2] = (len & 0x0000ff00) >> 8;
		data_buf[3] = (len & 0x000000ff);
	}
	else { // 127不写了

		return;
	}

	memcpy(data_buf + head_size, data, len);
	send(fd,data_buf, head_size + len,0);
	free(data_buf);
}


//根据用户在GET中的请求，生成相应的回复内容
int make_http_content(const char *command, char **content)
{
	//printf("make_http_content\n");
	char *file_buf;
	int file_length;
	char headbuf[256];
	memset(headbuf, 0, sizeof(headbuf));
	//printf("strlen(command) %d\n",strlen(command));

	if (command[0] == '/' && strlen(command) == 1)
	{
		file_length = get_file_content("/index.html", &file_buf);
	} 
	else
	{
		file_length = get_file_content(command, &file_buf);
	}
	if (file_length == 0)
	{
		return 0;
	}

	sprintf(headbuf, HEAD, get_filetype(command), file_length); //设置消息头

	int iheadlen = strlen(headbuf); //得到消息头长度
    (*content) = (char*)malloc(file_length + iheadlen);
	
	memcpy( *content, headbuf, iheadlen);				  //安装消息头
	memcpy( *content + iheadlen, file_buf, file_length);//安装消息体

    free(file_buf);
	return iheadlen + file_length; //返回消息总长度
}


static void handle_ws(session *s){
	char tmp[64];
	//未握手
	if(s->is_shake_hand == 0)
	{
		//printf("%s\n",s->data);
		s->is_shake_hand = 1;
		char *p = strstr(s->data,"Sec-WebSocket-Key:");
		uint8_t key[256] = {0};
		if(p)
		{
			//get key
			char *end = strstr(s->data,"==");
			memcpy(key,p + strlen("Sec-WebSocket-Key: "),end + 2 - p - strlen("Sec-WebSocket-Key: "));
			//printf("get:%s\n",key);
		}
		else
		{
			fprintf(stderr,"no Sec-WebSocket-Key");
		}
		//+GUID
		strcat((char*)key,GUID);

		//+sha1
		crypt_sha1((uint8_t*)key,strlen((char*)key),s->sha1_data,&s->sha1_size);

		//+base64
		int encode_sz;
		char *res = base64_encode(s->sha1_data, s->sha1_size, &encode_sz);
		char head[1024] = {0};

		sprintf(head,
			"HTTP/1.1 101 Switching Protocols\r\n"\
			"Upgrade:websocket\r\n"\
			"Connection: Upgrade\r\n"\
			"Sec-WebSocket-Accept: %s\r\n\r\n",
			res);

		//printf("%s\n",head);
		send(s->fd, head, strlen(head), 0);


		sprintf(tmp,"client %d websocket握手成功",s->fd);
		//printf("%s\n",tmp);

		memset(LOGBUF,0,sizeof(LOGBUF));
		sprintf(LOGBUF,"%s\n",tmp);
		save_log(LOGBUF);


		ws_send_data(s->fd, tmp, strlen(tmp));

        for(session * it = client_list; it!=NULL; it = it->next)
		{
			if(it->fd != s->fd && it->is_shake_hand == 1)
			{
				sprintf(tmp,"client %d 加入了群聊", s->fd);
				ws_send_data(it->fd,tmp,strlen(tmp));
			}
		}
	}
	else{

		ws_on_recv_data(s,s->fd,s->data,strlen(s->data));
	}
}


void save_log(char *buf)
{
	FILE *fp = fopen("log.txt","a+");  
	fputs(buf,fp);  
	fclose(fp);  
}

const char *get_filetype(const char *filename) //根据扩展名返回文件类型描述
{
	////////////得到文件扩展名///////////////////
	char sExt[32];
	const char *p_start=filename;
	memset(sExt, 0, sizeof(sExt));
	while(*p_start)
	{
		if (*p_start == '.')
		{
			p_start++;
			strncpy(sExt, p_start, sizeof(sExt));
			break;
		}
		p_start++;
	}

	////////根据扩展名返回相应描述///////////////////

	if (strncmp(sExt, "bmp", 3) == 0)
		return "image/bmp";

	if (strncmp(sExt, "gif", 3) == 0)
		return "image/gif";

	if (strncmp(sExt, "ico", 3) == 0)
		return "image/x-icon";

	if (strncmp(sExt, "jpg", 3) == 0)
		return "image/jpeg";

	if (strncmp(sExt, "j88", 3) == 0)
		return "video/avi";

	if (strncmp(sExt, "css", 3) == 0)
		return "text/css";

	if (strncmp(sExt, "dll", 3) == 0)
		return "application/x-msdownload";

	if (strncmp(sExt, "js", 2) == 0)
		return "application/x-javascript";

	if (strncmp(sExt, "dtd", 3) == 0)
		return "text/xml";

	if (strncmp(sExt, "mp3", 3) == 0)
		return "audio/mp3";

	if (strncmp(sExt, "mpg", 3) == 0)
		return "video/mpg";

	if (strncmp(sExt, "png", 3) == 0)
		return "image/png";

	if (strncmp(sExt, "ppt", 3) == 0)
		return "application/vnd.ms-powerpoint";

	if (strncmp(sExt, "xls", 3) == 0)
		return "application/vnd.ms-excel";

	if (strncmp(sExt, "doc", 3) == 0)
		return "application/msword";

	if (strncmp(sExt, "mp4", 3) == 0)
		return "video/mpeg4";

	if (strncmp(sExt, "ppt", 3) == 0)
		return "application/x-ppt";

	if (strncmp(sExt, "wma", 3) == 0)
		return "audio/x-ms-wma";

	if (strncmp(sExt, "wmv", 3) == 0)
		return "video/x-ms-wmv";

	return "text/html";
}

int get_file_content(const char *file_name, char **content) // 得到文件内容
{
	int  file_length = 0;
	FILE *fp = NULL;

	if (file_name == NULL)
	{
		return file_length;
	}

	char fl[64];
	sprintf(fl,".%s",file_name);
	fp = fopen(fl, "rb");

	if (fp == NULL)
	{
		printf("fp == null\n");
		memset(LOGBUF,0,sizeof(LOGBUF));
		sprintf(LOGBUF,"file name: %s,%s,%d:open file failture %s \n",file_name, __FILE__, __LINE__,
			strerror(errno));
		save_log(LOGBUF);
		return file_length;
	}

	fseek(fp, 0, SEEK_END);
	file_length = ftell(fp);
	rewind(fp);

	*content = (char *) malloc(file_length);
	if (*content == NULL)
	{
		printf("malloc\n");
		memset(LOGBUF,0,sizeof(LOGBUF));
		sprintf(LOGBUF,"%s,%d:malloc failture %s \n", __FILE__, __LINE__,
			strerror(errno));
		save_log(LOGBUF);
		return 0;
	}
	//printf("file length %d\n",file_length);
	//assert(file_length < 1024);
	fread(*content, file_length, 1, fp);
	fclose(fp);
	return file_length;
}

static int sp_add(int efd, int sock, void *ud) {
	struct epoll_event ev;
	ev.events = EPOLLIN;  
	ev.data.ptr = ud;
	if (epoll_ctl(efd, EPOLL_CTL_ADD, sock, &ev) == -1) {
		return 1;
	}
	return 0;
}

static int tcp_socket(int port){
	int sock;
	struct sockaddr_in addr;
	memset(&addr,0,sizeof addr);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(IP);//htonl(INADDR_ANY);
	addr.sin_port=htons(port);

	sock = socket(AF_INET,SOCK_STREAM,0);
	const int on=1;
	if (setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&on,sizeof on))
	{
		printf("setsockopt\n");
		return -1;
	}
	if(bind(sock,(struct sockaddr*)&addr,sizeof(addr)) == -1)
		return -1;
	if(listen(sock,10) == -1)
		return -1;
	return sock;
}
void daemon_run()
{  
    int pid;  
    signal(SIGCHLD, SIG_IGN);  
    //1）在父进程中，fork返回新创建子进程的进程ID；  
    //2）在子进程中，fork返回0；  
    //3）如果出现错误，fork返回一个负值；  
    pid = fork();  
    if (pid < 0)  
    {  
        //std:: cout << "fork error" << std::endl;  
		printf("fork error\n");
        exit(-1);  
    }  
    //父进程退出，子进程独立运行  
    else if (pid > 0) {  
        exit(0);  
    }  
    //之前parent和child运行在同一个session里,parent是会话（session）的领头进程,  
    //parent进程作为会话的领头进程，如果exit结束执行的话，那么子进程会成为孤儿进程，并被init收养。  
    //执行setsid()之后,child将重新获得一个新的会话(session)id。  
    //这时parent退出之后,将不会影响到child了。  
    setsid();  
    int fd;  
    fd = open("/dev/null", O_RDWR, 0);  
    if (fd != -1)  
    {  
        dup2(fd, STDIN_FILENO);  
        dup2(fd, STDOUT_FILENO);  
        dup2(fd, STDERR_FILENO);  
    }  
    if (fd > 2)  
        close(fd);  
}  