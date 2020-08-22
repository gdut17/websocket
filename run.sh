gcc -o httpd httpd.c redis_driver.c ./mjson/json.c ./crypto/sha1.c ./crypto/base64_encoder.c ./http_parser/http_parser.c -lhiredis
	
#./httpd 9998