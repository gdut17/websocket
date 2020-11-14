
#include "websocket.h"

const char* GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

#define WS_HEAD "HTTP/1.1 101 Switching Protocols\r\n"\
	            "Upgrade:websocket\r\n"\
	            "Connection: Upgrade\r\n"\
	            "Sec-WebSocket-Accept: %s\r\n\r\n"


static websocket_t *cli_list = NULL;

static int sp_add(int efd, int sock, void *ud) {
	struct epoll_event ev;
	ev.events = EPOLLIN;  
	ev.data.ptr = ud;
	if (epoll_ctl(efd, EPOLL_CTL_ADD, sock, &ev) == -1) {
		return 1;
	}
	return 0;
}
static int sp_del(int efd, int sock) {

	if (epoll_ctl(efd, EPOLL_CTL_DEL, sock, NULL) == -1) {
		return 1;
	}
	return 0;
}

static void Add_ws_cli(websocket_t *node)
{   
    if(!node)
        return ;

    sp_add(node->epfd, node->sockfd, (void*)node);

    if(!cli_list)
        cli_list = node;

    node->next = cli_list;
    cli_list = node;
}

static void Del_ws_cli(websocket_t *node)
{
    fprintf(stderr, "close %d\n", node->sockfd);
    websocket_t *p = cli_list;
    if(p->sockfd == node->sockfd)
    {
        cli_list = p->next;
        close(p->sockfd);
        free(p);
        sp_del(node->epfd, node->sockfd);
        return ;
    }
    while(p->next && p->next->sockfd != node->sockfd)
    {
        p = p->next;
    }
    websocket_t *q = p->next;
    p->next = q->next;
    close(q->sockfd);
    free(q);
    sp_del(node->epfd, node->sockfd);
    
}



void sig_handler(int signo)
{
    websocket_t *p = cli_list;
    while(p)
    {
        websocket_t *q=p->next;
        free(p);
        p=q;
    }
}

//只支持文本、二进制模式
size_t ws_on_recv(websocket_t *ws)
{
    memset(ws->buf, 0, sizeof(ws->buf));
    ws->recvd = recv(ws->sockfd, ws->buf, sizeof(ws->buf), 0);
    if(ws->recvd <= 0)
    {
        Del_ws_cli(ws);
        return 0;
    }
    printf("%d\n", ws->recvd);
    printf("%x\n", ws->buf[0]);
    if(ws->buf[0] == 0xffffff88){
        printf("ws close\n");
        Del_ws_cli(ws);
        return 0;
    }
    if (ws->buf[0] != 0xffffff81 && ws->buf[0] != 0xffffff82) {
		printf("data[0] != 0xffffff81 && data[0] != 0xffffff82\n");
		return 0;
	}
    
    unsigned int flag_mask = ws->buf[1] & 0x80;//Masking-key 1000 0000B
	unsigned int data_len = ws->buf[1] & 0x7f; //Payload len (7) 0111 1111B
	int head_size = 2;
	printf("flag_mask %u, ws data_len: %u\n", flag_mask, data_len);

	// 后面两个字节表示的是数据长度;data[2](存储高位), data[3],最大65535
	if (data_len == 126) { 
		//data_len = data[3] | (data[2] << 8);
		data_len = ws->buf[2]*256 + ws->buf[3];
		printf("126, data_len: %u\n",data_len);
		head_size += 2;
	}
	// 后面8个字节表示数据长度; 2, 3, 4, 5 | 6, 7, 8, 9
	//太大，不考虑
	else if (data_len == 127) { 
		//unsigned int low = data[5] | (data[4] << 8) | (data[3] << 16) | (data[2] << 24);
		//unsigned int hight = data[9] | (data[8] << 8) | (data[7] << 16) | (data[6] << 24);
		//printf("127, low: %u	low: %u\n",low,hight);
		//data_len = low;
		//head_size += 8;
		return 0;
	}

	char* body = ws->buf + head_size;

	//是否有mask掩码
	if(flag_mask == 0x80){
		char* mask = ws->buf + head_size;
		body += 4;

		for (unsigned int i = 0; i < data_len; i++) { // 遍历后面所有的数据;
			body[i] = body[i] ^ mask[i % 4];
		}
	}

	//包太大，不处理
	if(data_len > 4096){
		return 0;
	}

	static char test_buf[4096];
	memcpy(test_buf, body, data_len);
	test_buf[data_len] = '\0';
	printf("recv from %d ws_data:%s\n", ws->sockfd, test_buf);

    //echo
    ws->cb_send(ws, test_buf, strlen(test_buf));
    return data_len;
}

size_t ws_on_send(websocket_t *ws, const char* data, unsigned int len)
{
    int head_size = 2;
	//126
	if (len > 125 && len < 65536) { // 两个字节[0, 65535]
		head_size += 2;
	}
	//127
	else if (len >= 65536) { // 不做处理
		//head_size += 8;
		return 0;
	}

	unsigned char* data_buf = (unsigned char*)malloc(head_size + len);
	data_buf[0] = 0x81;	//1000 0001B
	if (len <= 125) {
		data_buf[1] = len;//不考虑mask
	}
	else if (len > 125 && len < 65536) {//126
		data_buf[1] = 126;
		data_buf[2] = (len & 0x0000ff00) >> 8;//高位，右移8位
		data_buf[3] = (len & 0x000000ff);
	}
	else { // 127不写了

		return 0;
	}

	memcpy(data_buf + head_size, data, len);
	send(ws->sockfd, data_buf, head_size + len, 0);
	free(data_buf);
    return head_size + len;
}

bool ws_handshake(websocket_t *ws)
{
    ws->recvd = recv(ws->sockfd, ws->buf, sizeof(ws->buf), 0);
    if(ws->recvd <= 0)
    {
        Del_ws_cli(ws);
        return false;
    }
    ws->buf[ws->recvd] = 0;
    printf("%s\n", ws->buf);

    char *p = strstr(ws->buf,"Sec-WebSocket-Key:");
	uint8_t key[256] = {0};
    if(!p)
	{
        return false;
    }

	//get key
	char *end = strstr(ws->buf,"==");
	memcpy(key, p + strlen("Sec-WebSocket-Key: "), end + 2 - p - strlen("Sec-WebSocket-Key: "));
	//printf("get:%s\n",key);
    //+GUID
	strcat((char*)key,GUID);

	//+sha1
	crypt_sha1((uint8_t*)key, strlen((char*)key), ws->buf, (int*)&ws->recvd);

	//+base64
	int encode_sz;
	char *res = base64_encode(ws->buf, ws->recvd, &encode_sz);
	
    char head[1024] = {0};
	sprintf(head, WS_HEAD, res);

    printf("%s\n", head);
    send(ws->sockfd, head, strlen(head), 0);
    ws->handshake = true;
}

void handle_accept(int lfd,int efd)
{
	struct sockaddr_in cli_addr;
	bzero(&cli_addr,sizeof(cli_addr));
	socklen_t len = sizeof(cli_addr);

	int cfd = accept(lfd,(struct sockaddr*)&cli_addr,&len);
	assert(cfd > 0);

	websocket_t *ns = malloc(sizeof(websocket_t));
	ns->handshake = false;
	ns->sockfd = cfd;
    ns->epfd = efd;
    ns->cb_hs = ws_handshake;
    ns->cb_recv = ws_on_recv;
    ns->cb_send = ws_on_send;
	ns->next = NULL;

	Add_ws_cli(ns);
	

	printf("new client fd = %d from %s:%d\n",
		    cfd,inet_ntoa(cli_addr.sin_addr),
            ntohs(cli_addr.sin_port));
}



int ws_server_loop(const char *ip, int port)
{
    int lfd;
    struct sockaddr_in addr;
	memset(&addr,0,sizeof addr);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(ip);//htonl(INADDR_ANY);
	addr.sin_port=htons(port);
    lfd = socket(AF_INET,SOCK_STREAM,0);
    assert(lfd > 0);
	const int on=1;
	if (setsockopt(lfd,SOL_SOCKET,SO_REUSEADDR,&on,sizeof on))
	{
		fprintf(stderr, "setsockopt\n");
		return -1;
	}
    int r = bind(lfd,(struct sockaddr*)&addr,sizeof(addr));
    assert(r == 0);
    r = listen(lfd,10);
    assert(r == 0);

    int epfd = epoll_create(1);
    assert(epfd > 0);

    websocket_t *ws_s = (websocket_t*)malloc(sizeof(websocket_t));
    assert(ws_s != NULL);
    ws_s->sockfd = lfd;

    sp_add(epfd, lfd, (void*)ws_s);

    //signal(SIGINT, sig_handler);

    struct epoll_event event[1024];
    printf("ws server listen on %s:%d\n", ip, port);
    for(;;)
	{	
		int ready = epoll_wait(epfd, event, 1024, -1);
		for(unsigned int i = 0; i < ready; i++)
		{
			websocket_t *s = (websocket_t *)event[i].data.ptr;
			int fd = s->sockfd;
			if(fd == lfd && event[i].events & EPOLLIN) //新连接
			{

				handle_accept(lfd, epfd);
			}
			else if(event[i].events & EPOLLIN)
			{
                if(s->handshake)
                {
                    s->cb_recv(s);
                }
                else
                {
                    s->cb_hs(s);
                }
			}
		}
	}
}