#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <crypt.h>
#include <termios.h>

#define BUFF_SIZE 2000
/* define HOME to be dir for key and cert files... */
#define HOME	"./cert_server/"

/* Make these what you want for cert & key files */
#define CERTF	HOME"client.crt"
#define KEYF	HOME"client.key"
#define CACERT	HOME"ca.crt"

#define CHK_NULL(x)	if ((x)==NULL) exit (1)
#define CHK_SSL(err)	if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }

struct addrinfo hints, * result;

//����dest��Ŀ���ַ���
//�ɹ�����0�����򷵻أ�1
int getpasswd(char* dest)
{
	struct termios oldflags, newflags;
	//�����ն�Ϊ������ģʽ
	tcgetattr(fileno(stdin), &oldflags);   //fileno(stdin)��ñ�׼������ļ������� 
	newflags = oldflags;
	newflags.c_lflag &= ~ECHO;  //ECHO ��ʾ��ʾ�����ַ�  ~ECHO���ǲ���ʾ��
	newflags.c_lflag |= ECHONL;  //���ICANONͬʱ���ã���ʹECHOû��������Ȼ��ʾ���з�
	if (tcsetattr(fileno(stdin), TCSANOW, &newflags) != 0)  //����stdin Ϊ newflags
	{
		perror("tcsetattr");
		return -1;
	}
	//��ȡ���Լ��̵�����
	scanf("%s", dest);

	//�ָ�ԭ�����ն�����
	if (tcsetattr(fileno(stdin), TCSANOW, &oldflags) != 0)
	{
		perror("tcsetattr");
		return -1;
	}
	return 0;
}

int verify_callback(int preverify_ok, X509_STORE_CTX* x509_ctx)
{
	char buf[300];

	X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);

	X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
	printf("subject= %s\n", buf);

	if (preverify_ok == 1) {
		printf("Verification passed.\n");
	}
	else {
		int err = X509_STORE_CTX_get_error(x509_ctx);

		printf("Verification failed: %s.\n", X509_verify_cert_error_string(err));
	}
}

SSL* setupTLSClient(const char* hostname)
{
	// Step 0: OpenSSL library initialization 
	// This step is no longer needed as of version 1.1.0.
	SSL_library_init();
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();

	SSL_METHOD* meth;
	SSL_CTX* ctx;
	SSL* ssl;

	meth = SSLv23_client_method();
	ctx = SSL_CTX_new(meth);

	//�ƶ�֤����֤��ʽ�ĺ���
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_load_verify_locations(ctx, CACERT, NULL);


	//�ͻ��˿��Բ���Ҫ����֤�� ��������֤�û����ͨ��shadow
	/*
	//ΪSSL�Ự�����û�֤��ĺ���
	if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(-2);
	}

	//ΪSSL�Ự�����û�˽Կ�ĺ���
	if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(-3);
	}

	//�ڽ�֤���˽Կ���ص�SSL�Ự����֮�󣬾Ϳ��Ե�������ĺ�������֤˽Կ��֤���Ƿ������
	if (!SSL_CTX_check_private_key(ctx)) {
		printf("Private key does not match the certificate public keyn");
		exit(-4);
	}*/
	ssl = SSL_new(ctx);

	X509_VERIFY_PARAM* vpm = SSL_get0_param(ssl);

	X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);

	return ssl;
}

int setupTCPClient(const char* hostname, int port)
{
	hints.ai_family = AF_INET; // AF_INET means IPv4 only addresses
	int error = getaddrinfo(hostname, NULL, &hints, &result);
	if (error) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
		exit(1);
	}
	// The result may contain a list of IP address; we take the first one.
	struct sockaddr_in* ip = (struct sockaddr_in*)result->ai_addr;
	//printf("IP Address: %s\n", (char*)inet_ntoa(ip->sin_addr));
	//freeaddrinfo(result);
	const char* ipp = (const char*)inet_ntoa(ip->sin_addr);
	struct sockaddr_in server_addr;
	/*
	// Get the IP address from hostname
	struct hostent *hp = gethostbyname(hostname);
	*/

	// Create a TCP socket
	int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	// Fill in the destination information (IP, port #, and family)
	memset(&server_addr, '\0', sizeof(server_addr));
	//memcpy(&(server_addr.sin_addr.s_addr), hp->h_addr, hp->h_length);
	server_addr.sin_addr.s_addr = inet_addr(ipp);
	server_addr.sin_port = htons(port);
	server_addr.sin_family = AF_INET;

	// Connect to the destination
	connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr));

	return sockfd;
}

// int to string û��c���е�itoa
int my_itoa(int val, char* buf)
{
	const unsigned int radix = 10;
	char* p;
	unsigned int a; //every digit
	int len;
	char* b; //start of the digit char
	char temp;
	unsigned int u;
	p = buf;

	if (val < 0)
	{
		*p++ = '-';
		val = 0 - val;
	}
	u = (unsigned int)val;
	b = p;
	do
	{
		a = u % radix;
		u /= radix;
		*p++ = a + '0';
	} while (u > 0);
	len = (int)(p - buf);
	*p-- = 0;
	//swap
	do
	{
		temp = *p;
		*p = *b;
		*b = temp;
		--p;
		++b;
	} while (b < p);

	return len;
}

int createTunDevice(unsigned int ip)  //���ڿͻ��� ����tun0 ���Ƕ�Ӧ��ip��ͬ
{
	int tunfd;
	struct ifreq ifr;
	int ret;

	memset(&ifr, 0, sizeof(ifr));

	/* Flags : IFF_TUN   - TUN�豸
	*          IFF_TAP   - TAP�豸
	*          IFF_NO_PI - ����Ҫ�ṩ������Ϣ
	*/
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	tunfd = open("/dev/net/tun", O_RDWR); //�ɶ���д
	if (tunfd == -1) {
		printf("Open /dev/net/tun failed! (%d: %s)\n", errno, strerror(errno));
		return -1;
	}
	ret = ioctl(tunfd, TUNSETIFF, &ifr); //����tunfd�˿�
	if (ret == -1) {
		printf("Setup TUN interface by ioctl failed! (%d: %s)\n", errno, strerror(errno));
		return -1;
	}

	//����ָ��
	char instr[100];
	memset(instr, 0, sizeof(instr));
	strcpy(instr, "sudo ifconfig tun0 192.168.53.");
	int len = strlen(instr);
	char tmp[10];
	memset(tmp, 0, sizeof(tmp));
	my_itoa(ip, tmp);  //���޷�������ת��Ϊ�ַ���
	for (int i = 0; i < strlen(tmp); i++) {
		instr[len++] = tmp[i];
	}
	strcat(instr, "/31 up");

	//·��ת��
	const char* instruction2 = "route add -net 192.168.60.0/24 tun0";
	system(instr);
	system(instruction2);

	printf("Setup TUN interface success!\n");
	return tunfd;
}


void tunSelected(int tunfd, SSL* ssl, int sock)
{
	int len;
	char buff[BUFF_SIZE];
	struct sockaddr_in connetsock1, connetsock2;
	int connetsock_len1 = sizeof(connetsock1);
	int connetsock_len2 = sizeof(connetsock2);
	getsockname(sock, (struct sockaddr*)&connetsock1, &connetsock_len1);
	getpeername(sock, (struct sockaddr*)&connetsock2, &connetsock_len2);

	printf("%s:%d ---> ", inet_ntoa(connetsock2.sin_addr), ntohs(connetsock2.sin_port));
	printf("%s:%d : Got a packet from Tun\n", inet_ntoa(connetsock1.sin_addr), ntohs(connetsock1.sin_port));

	bzero(buff, BUFF_SIZE);
	len = read(tunfd, buff, BUFF_SIZE);
	//sendto(sockfd, buff, len, 0, (struct sockaddr*)&peerAddr, sizeof(peerAddr));

	//ʹ��ssl�ļ��ܷ���
	SSL_write(ssl, buff, len);
}

void socketSelected(int tunfd, SSL* ssl, int sock)
{
	int len;
	char buff[BUFF_SIZE];
	struct sockaddr_in connetsock1, connetsock2;
	int connetsock_len1 = sizeof(connetsock1);
	int connetsock_len2 = sizeof(connetsock2);
	getsockname(sock, (struct sockaddr*)&connetsock1, &connetsock_len1);
	getpeername(sock, (struct sockaddr*)&connetsock2, &connetsock_len2);

	printf("%s:%d ---> ", inet_ntoa(connetsock2.sin_addr), ntohs(connetsock2.sin_port));
	printf("%s:%d : Got a packet from Tunnel\n", inet_ntoa(connetsock1.sin_addr), ntohs(connetsock1.sin_port));

	bzero(buff, BUFF_SIZE);
	len = SSL_read(ssl, buff, sizeof(buff) - 1);
	if (len == 0) {
		printf("Connection closed!\n");
		exit(0);
	}
	buff[len] = '\0';
	write(tunfd, buff, len);

}


int main(int argc, char* argv[])
{
	char* hostname = "yahoo.com";
	int port = 443;

	if (argc > 1)
		hostname = argv[1];
	if (argc > 2)
		port = atoi(argv[2]);

	/*----------------TLS initialization ----------------*/
	SSL* ssl = setupTLSClient(hostname);

	/*----------------Create a TCP connection ---------------*/
	int sockfd = setupTCPClient(hostname, port);


	/*----------------TLS handshake ---------------------*/
	SSL_set_fd(ssl, sockfd);
	CHK_NULL(ssl);
	int err = SSL_connect(ssl);

	CHK_SSL(err);
	printf("SSL connection is successful\n");
	printf("SSL connection using %s\n", SSL_get_cipher(ssl));

	/*
	�ͻ��������Լ����û���������  ��SSL����ܺ��͸�������
	���������ܺ���жԱ� ����ɹ���ô�ܼ���ִ��
	�����֤ʧ�� ��ô����˷���һ���ض��İ���ʾ���� �ͻ���ʶ��Ȼ�����
	*/
	printf("Please enter your Username and Password\n");
	char Username[100], Passwd[100];
	printf("UserName:");
	scanf("%s", Username);
	printf("Password:");
	getpasswd(Passwd);

	/*send username and password to server*/
	SSL_write(ssl, Username, strlen(Username));
	SSL_write(ssl, Passwd, strlen(Passwd));
	char buff[BUFF_SIZE];

	/*read the reply from server and do sth according to it*/
	int len = SSL_read(ssl, buff, sizeof(buff) - 1);
	buff[len] = '\0';
	if (strcmp(buff, "Yes")) { //��֤ʧ��
		printf("Client authentication failed!");  //�ͻ��˵���֤ʧ��
		int r = SSL_shutdown(ssl);
		//error handling here if r < 0 
		if (!r)
		{
			SSL_shutdown(ssl);
		}
		SSL_free(ssl);
		return 0;  //��֤����ֱ�ӽ���
	}
	else {
		printf("Verified successfully!\n");
	}

	//�������������������Ӧ��·��
	memset(buff, 0, sizeof(buff));
	SSL_read(ssl, buff, sizeof(buff) - 1);
	unsigned int ip;
	memcpy(&ip, buff, 4);

	/*create Tun0*/
	daemon(1, 1);
	int tunfd;
	tunfd = createTunDevice(ip);  //��createTunDevice �����������ָ�� ֱ��������Ӧ��·�ɺ�tun0


	while (1) {
		/*----------------Send/Receive data --------------------*/
		/*int select(int maxfdp1, fd_set * readset, fd_set * writeset, fd_set * exceptset, struct timeval* timeout);*/
		fd_set readFDSet;  //�����ļ���������

		FD_ZERO(&readFDSet);   //���
		FD_SET(sockfd, &readFDSet);
		FD_SET(tunfd, &readFDSet);
		select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);  //����socket��tun�Ķ��仯


		//�����⵽tun0������� ��ô��SSLת��������ݱ���
		if (FD_ISSET(tunfd, &readFDSet)) {
			tunSelected(tunfd, ssl, sockfd);
		}
		if (FD_ISSET(sockfd, &readFDSet)) {
			socketSelected(tunfd, ssl, sockfd);
		}
	}

}