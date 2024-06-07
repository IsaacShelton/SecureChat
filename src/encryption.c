
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "logf.h"
#include "tweetnacl.h"
#include "encryption.h"

int read_encrypted_message_container(int fd, encrypted_message_container_t *out_box){
    // Returns -1 if failed to read a whole container, or 0 on success

    size_t num_read = 0;
    memset(out_box, 0, sizeof *out_box);

    while(num_read < ENCRYPTED_MESSAGE_CONTAINER_SIZE){
        char c = 0;
        ssize_t size = read(fd, &c, sizeof c);

        if(size <= 0){
            if(size < 0){
                logf("read_encrypted_message_container read failed - ");
                perror("read");
                fflush(stderr);
            } else {
                logf("read_encrypted_message_container read failed for fd=%d - ", fd);
                perror("read");
                logf("warning: read_encrypted_message_container got EOF\n");
            }

            logf("warning: failed to read encrypted message container\n");
            return -1;
        }

        out_box->raw_bytes[num_read++] = c;
    }

    return 0;
}

void write_encrypted_message_container(int fd, encrypted_message_container_t *box){
    if(write(fd, box->raw_bytes, ENCRYPTED_MESSAGE_CONTAINER_SIZE) != ENCRYPTED_MESSAGE_CONTAINER_SIZE){
        logf("write_encrypted_message_container did not write entire container\n");
        exit(EXIT_FAILURE);
    }
}

void read_public_key(int fd, unsigned char out_public_key[crypto_box_PUBLICKEYBYTES]){
	int rc = read(fd, out_public_key, crypto_box_PUBLICKEYBYTES);
	if (rc != crypto_box_PUBLICKEYBYTES) {
		perror("read of public key failed");
		exit(EXIT_FAILURE);
	}
}

void read_public_key_from_file_or_panic(const char *filename, unsigned char out_public_key[crypto_box_PUBLICKEYBYTES]){
	int fd = open(filename, O_RDONLY);

	if(fd == -1){
		perror("open public key failed");
		exit(EXIT_FAILURE);
	}

    read_secret_key(fd, out_public_key);
    close(fd);
}

void write_public_key(int fd, unsigned char public_key[crypto_box_PUBLICKEYBYTES]){
    /* Open and read public key. */

	int rc = write(fd, public_key, crypto_box_PUBLICKEYBYTES);
	if (rc != crypto_box_PUBLICKEYBYTES) {
		perror("write of public key failed");
		exit(EXIT_FAILURE);
	}
}

void read_secret_key(int fd, unsigned char out_secret_key[crypto_box_SECRETKEYBYTES]){
	int rc = read(fd, out_secret_key, crypto_box_SECRETKEYBYTES);
	if (rc != crypto_box_SECRETKEYBYTES) {
		perror("read of secret key failed");
		exit(EXIT_FAILURE);
	}
}

void read_secret_key_from_file_or_panic(const char *filename, unsigned char out_secret_key[crypto_box_SECRETKEYBYTES]){
	int fd = open(filename, O_RDONLY);

	if(fd == -1){
		perror("open secret key failed");
		exit(EXIT_FAILURE);
	}

    read_secret_key(fd, out_secret_key);
    close(fd);
}

void write_secret_key(int fd, unsigned char secret_key[crypto_box_SECRETKEYBYTES]){
	int rc = write(fd, secret_key, crypto_box_SECRETKEYBYTES);
	if (rc != crypto_box_SECRETKEYBYTES) {
		perror("write of secret key failed");
		exit(EXIT_FAILURE);
	}
}
