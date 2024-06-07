
#ifndef ISAAC_ENCRYPTION_H_INCLUDED
#define ISAAC_ENCRYPTION_H_INCLUDED

#include "tweetnacl.h"

#define ENCRYPTED_MESSAGE_CONTENT_CAPACITY 4096
#define ENCRYPTED_MESSAGE_CONTAINER_SIZE (crypto_box_NONCEBYTES + crypto_box_ZEROBYTES + ENCRYPTED_MESSAGE_CONTENT_CAPACITY)

typedef struct {
    unsigned char raw_bytes[ENCRYPTED_MESSAGE_CONTAINER_SIZE];
} __attribute__((packed)) encrypted_message_container_t;

int read_encrypted_message_container(int fd, encrypted_message_container_t *out_box);
void write_encrypted_message_container(int fd, encrypted_message_container_t *box);

void read_public_key(int fd, unsigned char out_public_key[crypto_box_PUBLICKEYBYTES]);
void read_public_key_from_file_or_panic(const char *filename, unsigned char out_public_key[crypto_box_PUBLICKEYBYTES]);
void write_public_key(int fd, unsigned char public_key[crypto_box_PUBLICKEYBYTES]);

void read_secret_key(int fd, unsigned char out_secret_key[crypto_box_SECRETKEYBYTES]);
void read_secret_key_from_file_or_panic(const char *filename, unsigned char out_secret_key[crypto_box_SECRETKEYBYTES]);
void write_secret_key(int fd, unsigned char secret_key[crypto_box_SECRETKEYBYTES]);

#endif // ISAAC_ENCRYPTION_H_INCLUDED
