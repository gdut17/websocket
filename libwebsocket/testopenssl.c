#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#include <stdio.h>
#include <string.h>

//https://blog.csdn.net/lell3538/article/details/59122211
//https://blog.csdn.net/lell3538/article/details/59137414

const char* GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

int base64_encode(const char *in_str, int in_len, char *out_str);

//gcc testopenssl.c -lssl -lcrypto
int main()
{
    const char *ws_key = "WT2VuR4jNM0gYxecWmvXMQ==";
    unsigned char key[128] = {0};
    unsigned char tmp[128] = {0};
    sprintf(key, "%s%s", ws_key, GUID);
    printf("%s\n", key);
    SHA1(key, strlen(key), tmp);
    
    printf("%d\n", strlen(tmp));
    //unsigned char *SHA1(const unsigned char *d, size_t n, unsigned char *md);
    base64_encode(tmp, strlen(tmp), key);
    printf("%s\n", key);
}



int base64_encode(const char *in_str, int in_len, char *out_str)
{
    BIO *b64, *bio;
    BUF_MEM *bptr = NULL;
    size_t size = 0;
 
    if (in_str == NULL || out_str == NULL)
        return -1;
 
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
 
    BIO_write(bio, in_str, in_len);
    BIO_flush(bio);
 
    BIO_get_mem_ptr(bio, &bptr);
    memcpy(out_str, bptr->data, bptr->length);
    out_str[bptr->length] = '\0';
    size = bptr->length;
 
    BIO_free_all(bio);
    return size;
}


/*
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