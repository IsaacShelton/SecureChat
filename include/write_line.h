
#ifndef ISAAC_WRITE_LINE_H_INCLUDED
#define ISAAC_WRITE_LINE_H_INCLUDED

#include <stdio.h>
#include "tweetnacl.h"

void write_line_unencrypted(int fd, const char *line);

void write_line_encrypted(
    int fd,
	unsigned char recipient_public_key[crypto_box_PUBLICKEYBYTES],
    unsigned char sender_secret_key[crypto_box_SECRETKEYBYTES],
    const char *content
);

#endif // ISAAC_WRITE_LINE_H_INCLUDED
