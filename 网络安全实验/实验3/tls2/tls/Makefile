all: 
	gcc -o tlsclient tlsclient.c -lssl -lcrypto 
	gcc -o tlsserver tlsserver.c -lssl -lcrypto -lcrypt

clean: 
	rm -f tlsclient tlsserver 
	rm -f *~

