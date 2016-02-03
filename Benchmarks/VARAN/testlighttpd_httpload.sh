HOST="localhost"
cd http_load-14aug2014
make
echo "http://$HOST:8080/" > url
./http_load -parallel 1 -seconds 10 url
cd -
