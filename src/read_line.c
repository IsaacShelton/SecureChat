
#include <assert.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "logf.h"
#include "read_line.h"
#include "encryption.h"
#include "tweetnacl.h"

int decrypt_content(
    encrypted_message_container_t *encrypted_message_container,
	unsigned char public_key[crypto_box_PUBLICKEYBYTES],
    unsigned char secret_key[crypto_box_SECRETKEYBYTES],
    char out_decrypted[ENCRYPTED_MESSAGE_CONTENT_CAPACITY]
){
    // Returns -1 on failure, or 0 on success

	unsigned char *box = encrypted_message_container->raw_bytes;
	unsigned char *nonce_start = box;
	unsigned char *cipher_text_start = box + crypto_box_NONCEBYTES;
	unsigned char result_buffer[crypto_box_ZEROBYTES + ENCRYPTED_MESSAGE_CONTENT_CAPACITY];

    size_t cipher_text_length = ENCRYPTED_MESSAGE_CONTAINER_SIZE - crypto_box_NONCEBYTES;
	memset(cipher_text_start, 0, crypto_box_BOXZEROBYTES);

    int rc = crypto_box_open(result_buffer, cipher_text_start, cipher_text_length, nonce_start, public_key, secret_key);
    if(rc != 0){
        logf("warning: crypto_box_open failed (rc = %d)\n", rc);
        return -1;
    }

    memcpy(out_decrypted, (char*) result_buffer + crypto_box_ZEROBYTES, ENCRYPTED_MESSAGE_CONTENT_CAPACITY);
    return 0;
}

int read_line_unencrypted(int connfd, char out_line[BUFSIZ]){
    // Receives a line, and stores it in `out_line` (excluding '\n' character)
    // Returns number of characters read (excluding newline), otherwise -1 on error

    memset(out_line, 0, BUFSIZ);
    size_t length = 0;

    for(;;){
        char c = '\0';
        ssize_t size = read(connfd, &c, sizeof c);

        if(size < 0 || length >= BUFSIZ){
            return -1;
        }

        if(size == 0 || c == '\n'){
            out_line[length] = '\0';
            return length;
        } else {
            out_line[length++] = c;
        }
    }

    // (unreachable)
    assert(false && "unreachable");
}

int read_line_encrypted(
    int connfd,
	unsigned char sender_public_key[crypto_box_PUBLICKEYBYTES],
    unsigned char recipient_secret_key[crypto_box_SECRETKEYBYTES],
    char out_line[ENCRYPTED_MESSAGE_CONTENT_CAPACITY]
){
    // Receives a line, and stores it in `out_line` (excluding '\n' character)
    // Returns -1 on error, or 0 on success

    memset(out_line, 0, ENCRYPTED_MESSAGE_CONTENT_CAPACITY);

    encrypted_message_container_t box = {};
    if(read_encrypted_message_container(connfd, &box) != 0){
        logf("warning: failed to read encrypted message container\n");
        return -1;
    }

    if(decrypt_content(&box, sender_public_key, recipient_secret_key, out_line) != 0){
        logf("warning: failed to decrypt\n");
        return -1;
    }

    return strlen(out_line);
}

