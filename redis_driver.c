
#include "redis_driver.h"

redisContext* get_connect(){
	struct timeval timeout = { 1, 500000 }; // 1.5 seconds
	redisContext* c = redisConnectWithTimeout((char*)"127.0.0.1", 6379, timeout);
	if (c == NULL ||c->err) {
		if (c) {
            printf("Connection error: %s\n", c->errstr);
            redisFree(c);
        } else {
            printf("Connection error: can't allocate redis context\n");
        }
		return NULL;
	}
	return c;
}

bool Register(redisContext*c, const char* name,const char* password){
	redisReply *reply;
	reply = redisCommand(c,"keys user:*");
	
	redisContext*conn = get_connect();
	assert(conn != NULL);
	int j;
    if (reply->type == REDIS_REPLY_ARRAY) {
        for ( j = 0; j < reply->elements; j++) {
            //printf("%u) %s\n", j, reply->element[j]->str);
			redisReply *tmp = redisCommand(conn,"hget %s name",reply->element[j]->str);
			if(!strcmp(name,tmp->str)){
				
				freeReplyObject(tmp);
				freeReplyObject(reply);
				redisFree(conn);
				return false;
			}
			freeReplyObject(tmp);
        }
    }
    freeReplyObject(reply);
	
	reply = redisCommand(conn,"hmset user:%d name %s password %s",j+1,name,password);
	//printf("%s\n",replay->str);
	freeReplyObject(reply);
	redisFree(conn);
	return true;
}

bool Login(redisContext*c, const char* name,const char* password){
	redisReply *reply;
	reply = redisCommand(c,"keys user:*");
	
	redisContext*conn = get_connect();
	assert(conn != NULL);
	
    if (reply->type == REDIS_REPLY_ARRAY) {
        for (int j = 0; j < reply->elements; j++) {
            //printf("%u) %s\n", j, reply->element[j]->str);
			redisReply *tmp = redisCommand(conn,"hget %s name",reply->element[j]->str);
			if(!strcmp(name,tmp->str)){
				freeReplyObject(tmp);
				
				tmp = redisCommand(conn,"hget %s password",reply->element[j]->str);
				if(!strcmp(password,tmp->str)){
					freeReplyObject(reply);
					freeReplyObject(tmp);
					return true;
				}else{
					freeReplyObject(reply);
					freeReplyObject(tmp);
					return false;
				}
			}
        }
    }
    freeReplyObject(reply);
	redisFree(conn);
	return false;
}

