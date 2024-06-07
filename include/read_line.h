
#ifndef ISAAC_READ_LINE_H_INCLUDED
#define ISAAC_READ_LINE_H_INCLUDED

#include <stdio.h>
#include "tweetnacl.h"
#include "encryption.h"

int decrypt_content(
    encrypted_message_container_t *encrypted_message_container,
	unsigned char public_key[crypto_box_PUBLICKEYBYTES],
    unsigned char secret_key[crypto_box_SECRETKEYBYTES],
    char out_decrypted[ENCRYPTED_MESSAGE_CONTENT_CAPACITY]
);

int read_line_unencrypted(int connfd, char out_line[BUFSIZ]);

int read_line_encrypted(
    int connfd,
	unsigned char sender_public_key[crypto_box_PUBLICKEYBYTES],
    unsigned char recipient_secret_key[crypto_box_SECRETKEYBYTES],
    char out_line[ENCRYPTED_MESSAGE_CONTENT_CAPACITY]
);

#endif // ISAAC_READ_LINE_H_INCLUDED
