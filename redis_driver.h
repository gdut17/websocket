
#ifndef REDIS_DRIVER
#define REDIS_DRIVER

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <hiredis/hiredis.h>

redisContext* get_connect();
bool Register(redisContext*c, const char* name,const char* password);
bool Login(redisContext*c, const char* name,const char* password);

#endif