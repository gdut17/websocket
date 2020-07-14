gcc -o httpd httpd.c ./mjson/json.c ./crypto/sha1.c ./crypto/base64_encoder.c ./http_parser/http_parser.c 
./httpd 9998