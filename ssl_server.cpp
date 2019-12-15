#include <stdio.h>

#include <stdlib.h>

#include <string.h>

#include <sys/types.h>

#include <sys/socket.h>

#include <arpa/inet.h>

#include <netinet/in.h>

#include <unistd.h>

#include <vector>

#include <set>

#include <mutex>

#include <thread>

#include <errno.h> 

#include <malloc.h> 

#include <resolv.h> 

#include "openssl/ssl.h" 

#include "openssl/err.h" 

 

using namespace std;

 

void thrfunc(int sock);

 

void thrfunc_b(int sock, set<int>* accp_sock, mutex* mut);

 

char message[1024];

 

set<SSL> accp_sock;

 

void usage() {

 

	printf("syntax : echo_server <port> [-b]\n");

 

	printf("sample : echo_server 1234 -b\n");

 

}

 

void error_handling(char *message) {

 

	fputs(message, stderr);

 

	fputc('\n', stderr);

 

	exit(1);

 

}

// Create the SSL socket and intialize the socket address structure 

int OpenListener(int port)

{

	int sd;

	struct sockaddr_in addr;

 

	sd = socket(PF_INET, SOCK_STREAM, 0);

	bzero(&addr, sizeof(addr));

	addr.sin_family = AF_INET;

	addr.sin_port = htons(port);

	addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0)

	{

		perror("can't bind port");

		abort();

	}

	if (listen(sd, 10) != 0)

	{

		perror("Can't configure listening port");

		abort();

	}

	return sd;

}

 

int isRoot()

{

	if (getuid() != 0)

	{

		return 0;

	}

	else

	{

		return 1;

	}

 

}

SSL_CTX* InitServerCTX(void)

{

	SSL_METHOD *method;

	SSL_CTX *ctx;

 

	OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */

	SSL_load_error_strings();   /* load all error messages */

	method = TLSv1_2_server_method();  /* create new server-method instance */

	ctx = SSL_CTX_new(method);   /* create new context from method */

	if (ctx == NULL)

	{

		ERR_print_errors_fp(stderr);

		abort();

	}

	return ctx;

}

 

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)

{

	/* set the local certificate from CertFile */

	if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0)

	{

		ERR_print_errors_fp(stderr);

		abort();

	}

	/* set the private key from KeyFile (may be the same as CertFile) */

	if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)

	{

		ERR_print_errors_fp(stderr);

		abort();

	}

	/* verify private key */

	if (!SSL_CTX_check_private_key(ctx))

	{

		fprintf(stderr, "Private key does not match the public certificate\n");

		abort();

	}

}

 

void ShowCerts(SSL* ssl)

{

	X509 *cert;

	char *line;

 

	cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */

	if (cert != NULL)

	{

		printf("Server certificates:\n");

		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);

		printf("Subject: %s\n", line);

		free(line);

		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);

		printf("Issuer: %s\n", line);

		free(line);

		X509_free(cert);

	}

	else

		printf("No certificates.\n");

}

 

int listen_sock;

 

 

 

int main(int argc, char* argv[]) {

	SSL_CTX *ctx;

	int server;

	char *portnum;

	bool is_broadcast = false;

	if (!isRoot()) //Only root user have the permsion to run the server

	{

		printf("This program must be run as root/sudo user!!");

		exit(0);

	}

	if (!(argc == 2 || (argc == 3 && argv[2][0] == '-' && argv[2][1] == 'b'))) {

		usage();

		return -1;

 

	}

	SSL_library_init();

	portnum = argv[1];

	ctx = InitServerCTX();        /* initialize SSL */

	LoadCertificates(ctx, "mycert.pem", "mycert.pem"); /* load certs */

	server = OpenListener(atoi(portnum));    /* create server socket */

 

	mutex mut;

	vector<thread> thr;

 

	if (argc == 3) {

		int thdNum = 0;

		while (1) {

			struct sockaddr_in addr;

			socklen_t len = sizeof(addr);

			SSL *ssl;

			int client = accept(server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */

			printf("Connection: %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

			ssl = SSL_new(ctx);              /* get new SSL state with context */

			SSL_set_fd(ssl, client);      /* set connection socket to SSL state */

 

			if (SSL_accept(ssl) == -1)     /* do SSL-protocol accept */

				ERR_print_errors_fp(stderr);

			else {

				mut.lock();

				accp_sock.insert(ssl);

				thr.emplace_back(thread(thrfunc_b, ssl, &accp_sock, &mut));

				thr.back().detach();

				mut.unlock();

			}

		}

 

	}

 

	else {

 

		while (1) {

			struct sockaddr_in addr;

			socklen_t len = sizeof(addr);

			SSL *ssl;

			int client = accept(server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */

			printf("Connection: %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

			ssl = SSL_new(ctx);              /* get new SSL state with context */

			SSL_set_fd(ssl, client);      /* set connection socket to SSL state */

 

			if (SSL_accept(ssl) == -1)     /* do SSL-protocol accept */

				ERR_print_errors_fp(stderr);

			else {

				thr.emplace_back(thread(thrfunc, ssl));

				thr.back().detach();

			}

		}

 

	}

 

	close(server);

	SSL_CTX_free(ctx);         /* release context */

	return 0;

 

}

 

 

 

void thrfunc_b(SSL sock, set<SSL>* accp_sock, mutex* mut) {

 

	while (1) {

 

		int len = SSL_read(sock, message, 1023);

 

		if (len <= 0) {

 

			perror("recv fail");

 

			break;

 

		}

 

		mut->lock();

 

		message[len] = 0;

 

		printf("client send  = %s\n", message);

 

		for (auto it = accp_sock->begin(); it != accp_sock->end(); it++) {

 

			if (SSL_write(*it, message, strlen(message), 0) <= 0) {

 

				perror("send failed");

 

				it = accp_sock->erase(it);

 

				continue;

 

			}

 

		}

 

		mut->unlock();

 

 

 

		if (accp_sock->find(sock) == accp_sock->end()) break;

 

	}

 

 

 

}

 

 

 

void thrfunc(SSL *ssl) {

 

	while (true) {

 

		int len = SSL_read(ssl, message, 1023);

 

		if (len <= 0) {

 

			perror("recv fail");

 

			break;

 

		}

 

		message[len] = 0;

 

		printf("client send  = %s\n", message);

 

		if (SSL_write(ssl, message, strlen(message)) <= 0) {

 

			perror("send fail");

 

			break;

 

		}

 

	}

 

}

