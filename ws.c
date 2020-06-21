/*
websocket 简易聊天室

gcc -o ws ws.c ./crypto/sha1.c ./crypto/base64_encoder.c

GET / HTTP/1.1
Origin: null
Sec-WebSocket-Key: WT2VuR4jNM0gYxecWmvXMQ==
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Version: 13
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36 Edge/17.17134
Host: 106.13.232.15:9998
Cache-Control: no-cache

HTTP/1.1 101 Switching Protocols
Upgrade:websocket
Connection: Upgrade
Sec-WebSocket-Accept: Kfh9QIsMVZcl6xEPYxPHzW8SZ8w=

*/

/*
4个字节  32位
[前面2字节是固定的]: FIN:是否最后一个包,  MASK:是否掩码处理,
Payload len长度，[0,125]后续(判断是否有MASK掩码处理)直接接数据,[126]后续2字节为数据的长度,[127]后续8字节为数据的长度

-------------------------------------------------------------------
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-------+-+-------------+-------------------------------+
|F|R|R|R| opcode|M| Payload len |    Extended payload length    |
|I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
|N|V|V|V|       |S|             |   (if payload len==126/127)   |
| |1|2|3|       |K|             |                               |
+-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
|     Extended payload length continued, if payload len == 127  |
+ - - - - - - - - - - - - - - - +-------------------------------+
|                               |Masking-key, if MASK set to 1  |
+-------------------------------+-------------------------------+
| Masking-key (continued)       |          Payload Data         |
+-------------------------------- - - - - - - - - - - - - - - - +
:                     Payload Data continued ...                :
+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
|                     Payload Data continued ...                |
+---------------------------------------------------------------+
--------------------------------------------------------------------*/


#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <sys/epoll.h>

#include "./crypto/sha1.h"
#include "./crypto/base64_encoder.h"

const char* GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

#define IP "172.16.0.4"

//客户端结构体
typedef struct session {
	int 				fd;				
	char 				addr[64];
	int 				is_shake_hand;	// 是否已经握手
	unsigned char * 	data;			// 读取数据的buf
	unsigned char 		sha1_data[256];
	int 				sha1_size;
	struct session * 	next;
}session;

//不带头的单链表
session * client_list = NULL;
session * tail = NULL;


static int tcp_socket(int port);
static int sp_add(int efd, int sock, void *ud);

static void ws_send_data(int fd,unsigned char* data, int len);
static void ws_on_recv_data(session *s,int fd,unsigned char* data, unsigned int len);

void handle_accept(int lfd,int efd);
void handle_recv(session *s,int efd);

int main(int argc,char *argv[])
{
	if(argc != 2)
	{
		printf("Usage : %s port\n",argv[0]);
		return 1;
	}
	int lfd = tcp_socket(atoi(argv[1]));
	assert(lfd > 0);

	int efd = epoll_create(1);
	assert(efd > 0);

	session server;
	server.fd = lfd;
	sp_add(efd, lfd, &server);

	struct epoll_event event[1024];

	for(;;)
	{   
		int r = epoll_wait(efd, event, 1024, -1);
		for(int i = 0; i < r; i++)
		{
			session *s = event[i].data.ptr;
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
	ns->data = malloc(1024);
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
}
void handle_recv(session *s,int efd){
	int fd = s->fd;
	unsigned char tmp[64];
	int ret = recv(fd, s->data, 1024,0);
	if(ret > 0 )
	{   
		//printf("recv %d %s\n",ret,s->data);
		s->data[ret] = '\0';

		if(s->is_shake_hand == 0)
		{
			printf("%s\n",s->data);
			s->is_shake_hand = 1;
			char *p = strstr(s->data,"Sec-WebSocket-Key:");
			char key[256] = {0};
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
			strcat(key,GUID);

			//+sha1
			crypt_sha1(key,strlen(key),s->sha1_data,&s->sha1_size);

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

			printf("%s\n",head);
			send(fd, head, strlen(head), 0);


			sprintf(tmp,"%s 握手成功",s->addr);
			ws_send_data(fd, (unsigned char*) tmp, strlen(tmp));

			for(session * it = client_list; it!=NULL; it = it->next)
			{
				if(it->fd != fd)
				{
					sprintf(tmp,"%s 加入了群聊", s->addr);
					ws_send_data(it->fd,(unsigned char*)tmp,strlen(tmp));
				}
			}
		}
		else
		{
			//printf("data\n");
			ws_on_recv_data(s,fd,s->data,ret);
		}
	}
	else if(ret <= 0)
	{
		epoll_ctl(efd,EPOLL_CTL_DEL,fd,NULL); 
		close(fd);
		printf("closed client fd:%d\n",fd);

		if(client_list->fd == fd)
		{
			session* p = client_list;
			client_list = client_list->next;
			free(p);
		}
		else
		{
			for(session * it = client_list; it->next!=NULL; it = it->next)
			{
				if(it->next->fd == fd)
				{
					session* p = it->next;
					it->next = p->next;
					free(p);
					break;
				}
			}
		}
		for(session * it = client_list; it != NULL; it = it->next)
		{
			sprintf(tmp,"%s 离开了群聊",s->addr);
			ws_send_data(it->fd, (unsigned char*)tmp, strlen(tmp));
		}	
	}
}

// 收到的是一个数据包;
static void ws_on_recv_data(session *s,int fd,unsigned char* data, unsigned int len) {
	/*
	判断是否是最后一个包
	第一个字节  [0,7]，第一位是FIN，1000 ，文本类型0001/ 二进制类型0002
	0x81  0x82
	*/
	if (data[0] != 0x81 && data[0] != 0x82) {
		// printf("!=\n");
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
	printf("data_len； %u\n",data_len);

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


	unsigned char* body = data + head_size;

	if(flag_mask == 128){
		unsigned char* mask = data + head_size;
		body += 4;

		for (unsigned int i = 0; i < data_len; i++) { // 遍历后面所有的数据;
			body[i] = body[i] ^ mask[i % 4];
		}
	}


	// test
	static char test_buf[4096];
	memcpy(test_buf, body, data_len);
	test_buf[data_len] = '\0';
	printf("recv:%s\n", test_buf);

	//sscanf(test_buf,"%s:");

	//群发聊天室
	for(session * it = client_list;it!=NULL;it = it->next)
	{
		if(it->fd != fd)
		{	
			printf("广播给 %d\n",it->fd);
			unsigned char tmp[1024];
			sprintf(tmp,"%s : %s",s->addr, test_buf);
			ws_send_data(it->fd,(unsigned char*)tmp,strlen(tmp));
		}
	}
}
static void ws_send_data(int fd,unsigned char* data, int len) {
	int head_size = 2;
	if (len > 125 && len < 65536) { // 两个字节[0, 65535]
		head_size += 2;
	}
	else if (len >= 65536) { // 不做处理
		head_size += 8;
	}

	unsigned char* data_buf = malloc(head_size + len);
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
	int r = bind(sock,(struct sockaddr*)&addr,sizeof(addr));
	if(r == -1)
		return -1;
	r=listen(sock,10);
	if(r == -1)
		return -1;
	return sock;
}
