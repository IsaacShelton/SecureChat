
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "tweetnacl.h"

int main(int argc, char *argv[]){
	int fd;
	ssize_t rc;
	unsigned char pk[crypto_box_PUBLICKEYBYTES];
	unsigned char sk[crypto_box_SECRETKEYBYTES];

	if (argc != 3) {
		fprintf(stderr, "Usage: %s PUBFILE SECFILE\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	/* Generate a new key pair. */
	crypto_box_keypair(pk, sk);

	/* Write public key. */
	fd = open(argv[1], O_CREAT | O_WRONLY, 0600);
	if (-1 == fd) {
		perror("Open pk failed");
		exit(EXIT_FAILURE);
	}

	rc = write(fd, pk, crypto_box_PUBLICKEYBYTES);
	if (rc != crypto_box_PUBLICKEYBYTES) {
		perror("Write of pk failed");
		exit(EXIT_FAILURE);
	}

	close(fd);

	/* Write private key. */
	fd = open(argv[2], O_CREAT | O_WRONLY, 0600);
	if (-1 == fd) {
		perror("Open sk failed");
		exit(EXIT_FAILURE);
	}

	rc = write(fd, sk, crypto_box_SECRETKEYBYTES);
	if (rc != crypto_box_SECRETKEYBYTES) {
		perror("Write of sk failed");
		exit(EXIT_FAILURE);
	}

	close(fd);
}

