#include <stdio.h>

#include <stdlib.h>

#include <string.h>

#include <unistd.h>

#include <arpa/inet.h>

#include <netinet/in.h>

#include <sys/socket.h>

#include <thread>

#include <errno.h> 

#include <malloc.h> 

#include <resolv.h> 

#include <netdb.h> 

#include <openssl/ssl.h> 

#include <openssl/err.h> 

void usage() {

	printf("syntax : ssl_client <host> <port>\n");

	printf("sample : ssl_client 127.0.0.1 1234\n");

}

int OpenConnection(const char *hostname, int port)

{

	int sd;

	struct hostent *host;

	struct sockaddr_in addr;

 

	if ((host = gethostbyname(hostname)) == NULL)

	{

		perror(hostname);

		abort();

	}

	sd = socket(PF_INET, SOCK_STREAM, 0);

	bzero(&addr, sizeof(addr));

	addr.sin_family = AF_INET;

	addr.sin_port = htons(port);

	addr.sin_addr.s_addr = *(long*)(host->h_addr);

	if (connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0)

	{

		close(sd);

		perror(hostname);

		abort();

	}

	return sd;

}

 

SSL_CTX* InitCTX(void)

{

	const SSL_METHOD *method;

	SSL_CTX *ctx;

 

	OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */

	SSL_load_error_strings();   /* Bring in and register error messages */

	method = TLSv1_2_client_method();  /* Create new client-method instance */

	ctx = SSL_CTX_new(method);   /* Create new context */

	if (ctx == NULL)

	{

		ERR_print_errors_fp(stderr);

		abort();

	}

	return ctx;

}

 

void ShowCerts(SSL* ssl)

{

	X509 *cert;

	char *line;

 

	cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */

	if (cert != NULL)

	{

		printf("Server certificates:\n");

		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);

		printf("Subject: %s\n", line);

		free(line);       /* free the malloc'ed string */

		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);

		printf("Issuer: %s\n", line);

		free(line);       /* free the malloc'ed string */

		X509_free(cert);     /* free the malloc'ed certificate copy */

	}

	else

		printf("Info: No client certificates configured.\n");

}

 

void recv_from_server(int sock) {

	while (true) {

		char message[1024];

		int len = recv(sock, message, 1023, 0);

		if (len <= 0) {

			perror("recv failed");

			break;

		}

		message[len] = 0;

		printf("server send : %s\n", message);

	}

}

 

 

 

int main(int argc, char *argv[]) {

	SSL_CTX *ctx;

	int server;

	SSL *ssl;

	char message[1024];

	char acClientRequest[1024] = { 0 };

	int bytes;

	char *hostname, *portnum;

	if (argc != 3){

		usage();

		return -1;

	}

	SSL_library_init();

	hostname = argv[1];

	portnum = argv[2];

	ctx = InitCTX();

	server = OpenConnection(hostname, atoi(portnum));

	ssl = SSL_new(ctx);      /* create new SSL connection state */

	SSL_set_fd(ssl, server);    /* attach the socket descriptor */

	if (SSL_connect(ssl) == -1)   /* perform the connection */

		ERR_print_errors_fp(stderr);

	else {

		std::thread t_recv = std::thread(recv_from_server, ssl);

		t_recv.detach();

		while (1) {

			fputs("Input message(Q to quit): ", stdout);

			fgets(message, 1024, stdin);

			if (!strcmp(message, "q\n") || !strcmp(message, "Q\n"))

				break;

			if (SSL_write(ssl, message, strlen(message)) <= 0) {

				perror("send fail");

				break;

			}

		}

		SSL_free(ssl);

	}

	close(server);

	SSL_CTX_free(ctx);

	return 0;

}

