#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>

#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CA_DIR "ca_client"
#define BUFF_SIZE 2000 

struct sockaddr_in peerAddr;

int createTunDevice() {
   int tunfd;
   struct ifreq ifr;
   memset(&ifr, 0, sizeof(ifr));

   ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  

   tunfd = open("/dev/net/tun", O_RDWR);
   ioctl(tunfd, TUNSETIFF, &ifr);       

   return tunfd;
}

void tunSelected(int tunfd, int sockfd, SSL* ssl){
    int  len;
    char buff[BUFF_SIZE];

    printf("Got a packet from TUN\n");

    bzero(buff, BUFF_SIZE);
    len = read(tunfd, buff, BUFF_SIZE);
    sendto(sockfd, buff, len, 0, (struct sockaddr *) &peerAddr,
                    sizeof(peerAddr));
    //SSL_write(ssl, buff, len);
}

void socketSelected (int tunfd, int sockfd, SSL* ssl){
    int  len;
    char buff[BUFF_SIZE];

    printf("Got a packet from the tunnel\n");

    bzero(buff, BUFF_SIZE);
    len = recvfrom(sockfd, buff, BUFF_SIZE, 0, NULL, NULL);
    //len = SSL_read (ssl, buff, sizeof(buff));
    write(tunfd, buff, len);

}


int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    char  buf[300];

    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
    printf("subject= %s\n", buf);

    if (preverify_ok == 1) {
       printf("Verification passed.\n");
    } else {
       int err = X509_STORE_CTX_get_error(x509_ctx);
       printf("Verification failed: %s.\n",
                    X509_verify_cert_error_string(err));
    }
}

SSL* setupTLSClient(const char* hostname)
{
    // OpenSSL library initialization 
    
   SSL_library_init();
   SSL_load_error_strings();
   SSLeay_add_ssl_algorithms();

   SSL_METHOD *meth;
   SSL_CTX* ctx;
   SSL* ssl;

   //meth = (SSL_METHOD *)TLSv1_2_method();
   meth = (SSL_METHOD *)TLS_client_method();
   ctx = SSL_CTX_new(meth);

   SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
   if(SSL_CTX_load_verify_locations(ctx,NULL, CA_DIR) < 1){
	printf("Error setting the verify locations. \n");
	exit(0);
   }
   ssl = SSL_new (ctx);

   X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl); 
   X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);

   return ssl;
}

char *hostname_ip_check(const char *hostname) {
	struct addrinfo hints, *result;
	char *ip_addr;
	
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET; // AF_INET means IPv4 only addresses
	int error = getaddrinfo(hostname, NULL, &hints, &result);
	if (error) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
		exit(1);
	}
	
	// The result may contain a list of IP address; we take the first one.
	struct sockaddr_in* ip = (struct sockaddr_in *) result->ai_addr;
	//printf("IP Address: %s\n", (char *)inet_ntoa(ip->sin_addr));
	ip_addr = (char *)inet_ntoa(ip->sin_addr);
	freeaddrinfo(result);
	
	return ip_addr;
}

int setupTCPClient(const char* hostname, int port)
{
   struct sockaddr_in server_addr;

   // Get the IP address from hostname
   //struct hostent* hp = gethostbyname(hostname);
   printf("Connecting to host ip: %s\n",hostname_ip_check(hostname));

   // Create a TCP socket
   int sockfd= socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

   // Fill in the destination information (IP, port #, and family)
   memset (&server_addr, '\0', sizeof(server_addr));
   //memcpy(&(server_addr.sin_addr.s_addr), hp->h_addr, hp->h_length);
   server_addr.sin_addr.s_addr = inet_addr (hostname_ip_check(hostname)); 
   server_addr.sin_port   = htons (port);
   server_addr.sin_family = AF_INET;

   // Connect to the destination
   connect(sockfd, (struct sockaddr*) &server_addr,
           sizeof(server_addr));

   return sockfd;
}


int main(int argc, char *argv[])
{
   char *hostname = "www.google.com";
   int port = 443;

   if (argc > 1) hostname = argv[1];
   if (argc > 2) port = atoi(argv[2]);

   /*----------------TLS initialization ----------------*/
   SSL *ssl   = setupTLSClient(hostname);
   
   /*----------------Create a tun interface ----------------*/
   int tunfd = createTunDevice();

   /*----------------Create a TCP connection ---------------*/
   int sockfd = setupTCPClient(hostname, port);

   /*----------------TLS handshake ---------------------*/
   SSL_set_fd(ssl, sockfd);
   int err = SSL_connect(ssl); CHK_SSL(err);
   printf("SSL connection is successful\n");
   printf ("SSL connection using %s\n", SSL_get_cipher(ssl));

   /*----------------Send/Receive data --------------------*/
   //char buf[9000];
   char sendBuf[200];
   sprintf(sendBuf, "GET / HTTP/1.1\nHost: %s\n\n", hostname);
   SSL_write(ssl, sendBuf, strlen(sendBuf));

   /*int len;
   do {
     len = SSL_read (ssl, buf, sizeof(buf) - 1);
     buf[len] = '\0';
     printf("%s\n",buf);
   } while (len > 0); */

   // Enter the main loop
   while (1) {
     fd_set readFDSet;

     FD_ZERO(&readFDSet);
     FD_SET(sockfd, &readFDSet);
     FD_SET(tunfd, &readFDSet);
     select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

     if (FD_ISSET(tunfd,  &readFDSet)) tunSelected(tunfd, sockfd, ssl);
     if (FD_ISSET(sockfd, &readFDSet)) socketSelected(tunfd, sockfd, ssl);
  }
}
