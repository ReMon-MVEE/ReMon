# set up beanstalkd
rm -rf beanstalkd
cp -R beanstalkd.orig beanstalkd
cd beanstalkd
make -j 16
cd ..

# set up lighttpd
rm -rf  lighttpd-1.4.36
cp -R lighttpd-1.4.36.orig lighttpd-1.4.36
cd lighttpd-1.4.36
./configure
make -j 16
mkdir -p /tmp/lighttpd/servers/
mkdir -p /tmp/lighttpd/logs/
cp tests/docroot/www/index.html /tmp/lighttpd/servers
cd ..

# set up memcached
sudo apt-get install libevent-pthreads-2.0-5  libevent-dev libmemcached-tools
rm -rf memcached-1.4.17
cp -R memcached-1.4.17.orig memcached-1.4.17
cd memcached-1.4.17
./configure
make -j 16
cd ..

# set up nginx
rm -rf nginx-1.5.12
cp -R nginx-1.5.12.orig nginx-1.5.12
cd nginx-1.5.12
./configure --prefix=/tmp/nginx/
make -j 16
mkdir -p /tmp/nginx/logs
mkdir -p /tmp/nginx/html
cp -R conf /tmp/nginx/
cp ../lighttpd-1.4.36.orig/tests/docroot/www/index.html /tmp/nginx/html
cd ..

# set up redis
rm -rf redis-3.0.3
cp -R redis-3.0.3.orig redis-3.0.3
cd redis-3.0.3
make -j 16
cd ..

# set up apache
rm -rf apache_1.3.29
cp -R apache_1.3.29.orig apache_1.3.29
cd apache_1.3.29
bash ./configure --prefix=/tmp/apache/ --exec-prefix=/tmp/apache/
sed -i 's/getline/apache_getline/' src/support/htdigest.c
sed -i 's/getline/apache_getline/' src/support/htpasswd.c
sed -i 's/getline/apache_getline/' src/support/logresolve.c
make -j 16
mkdir -p /tmp/apache/htdocs/
mkdir -p /tmp/apache/logs/
cp -R conf /tmp/apache/
cp ../apache_1.3.29.orig/htdocs/manual/logs.html /tmp/apache/htdocs/index.html
cd ..

# set up thttpd
rm -rf thttpd-2.26
cp -R thttpd-2.26.orig thttpd-2.26
cd thttpd-2.26
./configure
make -j 16
cd ..

