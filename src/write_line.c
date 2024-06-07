
#include <assert.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#include "logf.h"
#include "read_line.h"
#include "write_line.h"
#include "tweetnacl.h"
#include "encryption.h"

static int encrypt_content(
    unsigned char public_key[crypto_box_PUBLICKEYBYTES],
    unsigned char secret_key[crypto_box_SECRETKEYBYTES],
    const char *content,
    encrypted_message_container_t *out_box
){
    // Return -1 on error, or 0 on success

    static_assert(
        sizeof(*out_box) == ENCRYPTED_MESSAGE_CONTAINER_SIZE,
        "expected message container to be specific size"
    );

    // Ensure nothing leaks through into buffer
    memset(out_box, 0, sizeof *out_box);

	unsigned char *buf = out_box->raw_bytes;
	unsigned char *nonce_start = buf;
	unsigned char message[crypto_box_ZEROBYTES + ENCRYPTED_MESSAGE_CONTENT_CAPACITY];
	unsigned char *cipher_text = buf + crypto_box_NONCEBYTES;

    // Generate nonce
	randombytes(nonce_start, crypto_box_NONCEBYTES);

    size_t content_length = strlen(content);

    if(content_length + 1 > ENCRYPTED_MESSAGE_CONTENT_CAPACITY){
        // Message too long, not supported
        return -1;
    }

    memset(message, 0, sizeof message);
    memcpy(message + crypto_box_ZEROBYTES, content, content_length + 1);

	if(crypto_box(cipher_text, message, sizeof message, nonce_start, public_key, secret_key) != 0){
        // Failed to encrypt
        logf("warning: crypto_box failed\n");
        return -1;
	}

    // Result is in `out_box`
    return 0;
}

void write_line_unencrypted(int fd, const char *line){
    ssize_t line_length = strlen(line);

    for(ssize_t i = 0; i < line_length; i++){
        assert(line[i] != '\n');
    }

    if(write(fd, line, line_length) != line_length || write(fd, "\n", sizeof(char)) != 1){
        logf("write_line_unencrypted failed for fd=%d - ", fd);
        perror("write");
        fflush(stderr);
        exit(EXIT_FAILURE);
    }
}

void write_line_encrypted(
    int fd,
	unsigned char recipient_public_key[crypto_box_PUBLICKEYBYTES],
    unsigned char sender_secret_key[crypto_box_SECRETKEYBYTES],
    const char *content
){
    encrypted_message_container_t box = {};

    if(encrypt_content(recipient_public_key, sender_secret_key, content, &box) != 0){
        // Ignore failed to send message
        logf("warning: failed to encrypt for write_line_encrypted - ignoring message\n");
        return;
    }

    write_encrypted_message_container(fd, &box);
}

