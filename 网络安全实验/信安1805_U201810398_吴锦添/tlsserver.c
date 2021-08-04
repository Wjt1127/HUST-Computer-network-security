/*
����vpnserver�ٸ�
Ŀǰ���̣� ���ǹܵ��޷�ͨ�� ����ûɶ����TAT ���Բ��ü�¼
������ͣ�
.....
������ᣡ
����������˹رջ����������빦��
������˿ͻ��˹ر� ��Ӧ������ӽ��̵Ľ�ʬ�������� ʹ��signal ���һ���ص��������в����� wait
*/


#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <shadow.h>
#include <crypt.h>
#include <signal.h>
#include <sys/wait.h>



#define BUFF_SIZE 2000
/* define HOME to be dir for key and cert files... */
#define HOME	"./cert_server/"

/* Make these what you want for cert & key files */
#define CERTF	HOME"server.crt"
#define KEYF	HOME"server.key"
#define CACERT	HOME"ca.crt"

#define CHK_NULL(x)	if ((x)==NULL) exit (1)
#define CHK_ERR(err,s)	if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err)	if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

struct tunnle {
	//unsigned int No;    //the number of tun
	unsigned int S_ip;  //server tun ip = No
	unsigned int C_ip;  //client tun ip=No+1;
	int tunfd;			//tunfd
}Tunnel[256]; //���ڴ洢��Ӧ�������Ϣ

int flag[256];  //��־λ ��ʾ�ĸ�ip���� ����ip�ķ����ǳɶԽ��е� һ�η���server tun��client tun 

int setupTCPServer();	// Defined in Listing 19.10
void processRequest(SSL* ssl, int sock, int tunfd, int Cip);	// Defined in Listing 19.12


void func_waitpid(int signo)

{
	pid_t pid;
	int stat;
	pid = wait(&stat);
	if (WIFEXITED(stat)) {    //�ж��ӽ����Ƿ��������˳�
		int Cip = WEXITSTATUS(stat);
		flag[Cip - 1] = flag[Cip] = 0;
		printf("\033[22;31m����IPΪ��192.168.53.%d�ɹ�����\n", Cip - 1);
		printf("����IP��192.168.53.%d�ɹ�����\n", Cip); //�����ɫ����
		printf("\033[22;39m");//�ָ���ɫ
	}
	return;
}


int login(char* user, char* passwd)
{
	struct spwd* pw;
	char* epasswd;
	pw = (struct spwd*)getspnam(user);
	if (pw == NULL) {
		return 0;
	}
	printf("Login name: %s\n", pw->sp_namp);
	printf("Encypted Passwd : %s\n", pw->sp_pwdp);
	epasswd = crypt(passwd, pw->sp_pwdp);
	if (strcmp(epasswd, pw->sp_pwdp)) {
		return 0;
	}
	return 1;
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

//�����÷���˵�ipΪ192.168.53.2 ��4 ��6 ��8 �ȵ�   ��Ӧ�ͻ��˵�Ϊ3 5 7 9
int createTunDevice(int ip)  //��ÿ���ӽ��̷���tun ÿ��tun��Ӧһ���ͻ������Σ��������������һ���ͻ��˵�����ip��Ӧ
{
	int tunfd;
	struct ifreq ifr;
	int ret;

	memset(&ifr, 0, sizeof(ifr));

	/* Flags : IFF_TUN   - TUN�豸
	*         IFF_TAP   - TAP�豸
	*         IFF_NO_PI - ����Ҫ�ṩ������Ϣ
	*/
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	tunfd = open("/dev/net/tun", O_RDWR);
	if (tunfd == -1) {
		printf("Open /dev/net/tun failed! (%d: %s)\n", errno, strerror(errno));
		return -1;
	}
	ret = ioctl(tunfd, TUNSETIFF, &ifr);
	if (ret == -1) {
		printf("Setup TUN interface by ioctl failed! (%d: %s)\n", errno, strerror(errno));
		return -1;
	}

	//recover ip
	int Sip = ip * 2 + 2;

	//����ָ��
	char instr[100], instruction2[100];
	memset(instr, 0, sizeof(instr));
	memset(instruction2, 0, sizeof(instruction2));
	strcpy(instr, "sudo ifconfig tun");  //set up the tun
	//strcpy(instruction2, "route add -net 192.168.60.0/24 tun");  //add the routes
	int len = strlen(instr);
	//int len2 = strlen(instruction2);
	char tmp[10];
	memset(tmp, 0, sizeof(tmp));
	my_itoa(ip, tmp);  //���޷�������ת��Ϊ�ַ���
	for (int i = 0; i < strlen(tmp); i++) {
		instr[len++] = tmp[i];
		//instruction2[len2++] = tmp[i];
	}
	strcat(instr, " 192.168.53.");
	len = strlen(instr);
	memset(tmp, 0, sizeof(tmp));
	my_itoa(Sip, tmp);
	for (int i = 0; i < strlen(tmp); i++) {
		instr[len++] = tmp[i];
	}
	strcat(instr, "/31 up");

	//exec the instruction	
	system(instr);
	//system(instruction2);

	printf("Setup TUN%d interface success!\n", ip);

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

void socketSelected(int tunfd, SSL* ssl, int sock, int Cip)
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
		printf("One connection closed!\n");

		printf("Closed connection:\nserver address: %s:%d\n", inet_ntoa(connetsock1.sin_addr), ntohs(connetsock1.sin_port));
		printf("client address: %s:%d\n", inet_ntoa(connetsock2.sin_addr), ntohs(connetsock2.sin_port));

		exit(Cip);
	}
	buff[len] = '\0';

	write(tunfd, buff, len);

}


int main()
{
	SSL_METHOD* meth;
	SSL_CTX* ctx;
	SSL* ssl;
	int err;
	flag[0] = flag[1] = flag[254] = flag[255] = 1;   //������ip���ɷ���

	//daemon(1, 1);  ����������� SSL_CTX_use_PrivateKey_file  ǰ�Ῠ��

	// Step 0: OpenSSL library initialization
	// This step is no longer needed as of version 1.1.0.
	SSL_library_init();
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();

	// Step 1: SSL context initialization
	meth = SSLv23_server_method();
	ctx = SSL_CTX_new(meth);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, verify_callback);
	//SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_load_verify_locations(ctx, CACERT, NULL);

	// Step 2: Set up the server certificate and private key
	if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(3);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(4);
	}

	/* ���˽Կ�Ƿ���ȷ */
	if (!SSL_CTX_check_private_key(ctx)) {
		fprintf(stderr, "Private key does not match the certificate public key\n");
		exit(5);
	}

	daemon(1, 1);

	/*int FD[256][2], flag[256]; //FD��ά�������ڴ洢��Ӧ����ip�ܵ���fd[2]   flag�������ڱ�־�ĸ�ip�Ƿ����
	memset(flag, 0, sizeof(flag));  //0 ��ʾ����   1��ʾ������
	flag[0] = flag[1] = flag[255] = 1;  //0��255��   1����������������
	for (int i = 0; i < 256; i++) {
		pipe(FD[i]);
	}*/
	struct sockaddr_in sa_client;
	size_t client_len = sizeof(struct sockaddr_in);
	int listen_sock = setupTCPServer();

	fprintf(stderr, "listen_sock = %d\n", listen_sock);

	while (1) {
		// Step 3: Create a new SSL structure for a connection
		ssl = SSL_new(ctx);  //ÿ������ ��Ϊ���ܽ��̱�ɱ ��Ҫ���´���

		//select one in listen_sock queue if empty wait
		int sock = accept(listen_sock, (struct sockaddr*)&sa_client, &client_len);

		fprintf(stderr, "sock = %d\n", sock);
		if (sock == -1) {
			fprintf(stderr, "Accept TCP connect failed! (%d: %s)\n", errno, strerror(errno));
			continue;
		}

		// deal with defunct process
		signal(SIGCHLD, &func_waitpid);

		unsigned int ip;
		//get an avaliable ip for connection
		for (int i = 1; i < 127; i++) {
			if (!flag[2 * i]) {//avaliable
				ip = 2 * i;  //ip for server
				//client ip is ip+1
				flag[2 * i] = flag[2 * i + 1] = 1; //used
				break;
			}
		}

		if (fork() == 0) {	// The child process
			SSL_set_fd(ssl, sock);
			int err = SSL_accept(ssl);

			fprintf(stderr, "SSL_accept return %d\n", err);
			CHK_SSL(err);
			printf("SSL connection established!\n");

			char username[100], passwd[100];
			memset(username, 0, sizeof(username));
			memset(passwd, 0, sizeof(passwd));

			/*Read the username and password*/
			int userlen = SSL_read(ssl, username, sizeof(username));
			int passlen = SSL_read(ssl, passwd, sizeof(passwd));
			if (login(username, passwd)) {//����Ϊ1 ��ô˵����֤�ɹ�
				printf("Verified successfully!\n");
				//create the tun
				int tunfd;
				tunfd = createTunDevice((ip - 2) / 2);

				char buff[100];
				strcpy(buff, "Yes");
				buff[3] = '\0';
				SSL_write(ssl, buff, 3);

				//��֤���ӵ�ʱ�򻹲��ᾭ���������� ֱ��ͨ��ssl�㽻��
				//����˷�����������ip ���͸��ͻ��� �ͻ������ɶ�Ӧ����������ip �������Ӧ��·��
				unsigned int Cip = ip + 1;
				memset(buff, 0, sizeof(buff));
				memcpy(buff, &Cip, sizeof(int));
				SSL_write(ssl, buff, 4);
				printf("\033[22;31m�������˵�tun%d��IPΪ��192.168.53.%d\n", (ip - 2) / 2, ip);
				printf("����ͻ�������IP��192.168.53.%d\n", Cip); //�����ɫ����
				printf("\033[22;39m");//�ָ���ɫ

				//print the information
				struct sockaddr_in connetsock1, connetsock2;
				int connetsock_len1 = sizeof(connetsock1);
				int connetsock_len2 = sizeof(connetsock2);
				getsockname(sock, (struct sockaddr*)&connetsock1, &connetsock_len1);
				getpeername(sock, (struct sockaddr*)&connetsock2, &connetsock_len2);
				printf("New connection:\nserver address: %s:%d\n", inet_ntoa(connetsock1.sin_addr), ntohs(connetsock1.sin_port));
				printf("client address: %s:%d\n", inet_ntoa(connetsock2.sin_addr), ntohs(connetsock2.sin_port));

				//��֤�ɹ���ִ��
				processRequest(ssl, sock, tunfd, Cip);
			}
			else { //send fail packet to client and close the ssl 
				char buff[100];
				buff[0] = 'N';
				buff[1] = 'o';
				buff[2] = '\0';
				SSL_write(ssl, buff, 2);
				printf("Client authentication failed!\n");
				int r = SSL_shutdown(ssl);

				//retrieve the ip
				flag[ip] = flag[ip + 1] = 0;
				//error handling here if r < 0 
				if (!r)
				{
					SSL_shutdown(ssl);
				}
				SSL_free(ssl);
				close(sock);
				//end child process
				exit(0);

				//kill the child process don't need to wait
				//pid_t id=getpid();
				//kill(id,SIGKILL);
			}

		}
		else {	// The parent process
			close(sock);
			//waitpid(-1, NULL, WNOHANG);//������
			continue;
		}
	}
}

int setupTCPServer()  //��4433�Ŷ˿ڽ���listen
{
	struct sockaddr_in sa_server;
	int listen_sock;

	listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	CHK_ERR(listen_sock, "socket");
	memset(&sa_server, '\0', sizeof(sa_server));
	sa_server.sin_family = AF_INET;
	sa_server.sin_addr.s_addr = INADDR_ANY;
	sa_server.sin_port = htons(4433);//������������4433�˿ڽ�������
	int err = bind(listen_sock, (struct sockaddr*)&sa_server, sizeof(sa_server));

	CHK_ERR(err, "bind");
	err = listen(listen_sock, 10); // change 5 to 10
	CHK_ERR(err, "listen");
	return listen_sock;
}

void processRequest(SSL* ssl, int sock, int tunfd, int Cip)
{
	while (1) {
		/*int select(int maxfdp1, fd_set * readset, fd_set * writeset, fd_set * exceptset, struct timeval* timeout);*/
		fd_set readFDSet;  //�����ļ���������

		FD_ZERO(&readFDSet);   //���
		FD_SET(sock, &readFDSet);
		FD_SET(tunfd, &readFDSet);
		select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);  //����socket��tun�Ķ��仯

		//�����⵽tun������� ��ô��SSLת��������ݱ���
		if (FD_ISSET(tunfd, &readFDSet)) {
			tunSelected(tunfd, ssl, sock);

		}
		if (FD_ISSET(sock, &readFDSet)) {
			socketSelected(tunfd, ssl, sock, Cip);  //�����Ӧ��ip�Ͷ˿�
		}
	}
}
