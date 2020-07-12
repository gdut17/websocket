# websocket
--------------------------------------------------------------------
/*-------------------------------------------------------------------
0               1               2               3
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


GET / HTTP/1.1
Host: 106.13.232.15:9998
Connection: Upgrade
Pragma: no-cache
Cache-Control: no-cache
Upgrade: websocket
Origin: http://106.13.232.15:9998
Sec-WebSocket-Version: 13
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3314.0 Safari/537.36 SE 2.X MetaSr 1.0
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: Hm_lvt_eaa57ca47dacb4ad4f5a257001a3457c=1593046318,1593046946,1594380558,1594523424; Hm_lpvt_eaa57ca47dacb4ad4f5a257001a3457c=1594525854
Sec-WebSocket-Key: kSBh2WG5GiBKHt7MDxEQmQ==
Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits


HTTP/1.1 101 Switching Protocols
Upgrade:websocket
Connection: Upgrade
Sec-WebSocket-Accept: tcZ1hwzkvkEE9kGoEtfqHOtpSFg=

