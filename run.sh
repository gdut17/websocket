gcc -o httpd httpd.c ./crypto/sha1.c ./crypto/base64_encoder.c ./http_parser/http_parser.c 
./httpd 9998