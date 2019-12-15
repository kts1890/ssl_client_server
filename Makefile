all: ssl_client ssl_server

ssl_client: ssl_client.cpp
	g++ -Wall -L/usr/lib -lssl -std=c++11 -o ssl_client ssl_client.cpp -pthread -std=gnu++11 -fpermissive -Wwrite-strings

echo_server: ssl_server.cpp
	g++ -Wall -o ssl_server ssl_server.cpp -L/usr/lib -lssl -lcrypto -std+gnu++11 -fpermissive -Wwrite-strings

clean:
	rm ssl_server
	rm ssl_client
