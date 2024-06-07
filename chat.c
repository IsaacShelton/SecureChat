
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>

#include "logf.h"
#include "encryption.h"
#include "read_line.h"
#include "tweetnacl.h"
#include "write_line.h"
#include "strings.h"

const char *PROGRAM_NAME = "chat";

static void show_usage(const char *program_name){
    fprintf(stderr, "usage: %s [-h] [-u USER] HOST PORT\n", program_name);
}

int main(int argc, char *argv[]){
    int opt, exitcode = EXIT_FAILURE;
    char *user = NULL;
    int rc, fd = -1;
    struct addrinfo hints = { .ai_socktype = SOCK_STREAM };
    struct addrinfo *info = NULL, *p;

    while((opt = getopt(argc, argv, "hu:")) != -1){
        switch (opt) {
        case 'h':
            show_usage(argv[0]);
            exitcode = EXIT_SUCCESS;
            goto done;
        case 'u':
            free(user);
            user = strdup(optarg);
            break;
        default:
            fprintf(stderr, "%s: invalid option -- '%c'\n", argv[0], opt);
            show_usage(argv[0]);
            goto done;
        }
    }

    if(!(optind < argc)){
        show_usage(argv[0]);
        goto done;
    }

    const char *host = argv[optind++];

    if(!(optind < argc)){
        show_usage(argv[0]);
        goto done;
    }
    
    const char *port_string = argv[optind++];
    int port = atoi(port_string);

    if(port < 1 || port > 65535){
        fprintf(stderr, "Invalid PORT, must be in range [1, 65535]\n");
        goto done;
    }

    if(optind < argc){
        fprintf(stderr, "Unrecognized argument '%s'\n", argv[optind]);
        goto done;
    }

    if(argc < 3){
        printf("usage: %s ADDRESS PORT\n", argv[0]);
        return 1;
    }

    /* Lookup host. */
    rc = getaddrinfo(host, port_string, &hints, &info);
    if (0 != rc) {
        logf("error looking up address: %s\n", gai_strerror(rc));
        goto done;
    }

    /* Connect to host; first option that works wins. */
    for (p = info; p; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, 0);
        if(-1 == fd){
            continue;
        }

        rc = connect(fd, p->ai_addr, p->ai_addrlen);
        if(rc > -1){
            break;
        } else {
            close(fd);
            fd = -1;
        }
    }

    if (-1 == fd || -1 == rc) {
        logf("could not connect - ");
        perror("could not connect");
        goto done;
    }

    unsigned char client_public_key[crypto_box_PUBLICKEYBYTES];
    read_public_key_from_file_or_panic("client.pub", client_public_key);

    unsigned char client_secret_key[crypto_box_SECRETKEYBYTES];
    read_secret_key_from_file_or_panic("client.sec", client_secret_key);

    unsigned char server_public_key[crypto_box_PUBLICKEYBYTES];
    read_public_key_from_file_or_panic("server.pub", server_public_key);

    write_public_key(fd, client_public_key);

    while(true){
        char message[BUFSIZ];

        if(read_line_unencrypted(fileno(stdin), message) < 0){
            // Failed to read message
            break;
        }

        logf("Sending `%s`\n", message);
        write_line_encrypted(fd, server_public_key, client_secret_key, message);

        if(!(string_starts_with(message, "auth ") || string_starts_with(message, "exit"))){
            char line[ENCRYPTED_MESSAGE_CONTENT_CAPACITY];
            if(read_line_encrypted(fd, server_public_key, client_secret_key, line) == -1){
                logf("failed to read back encrypted line\n");
                break;
            }

            size_t line_length = strlen(line);

            // Replace '\r' with '\n' (used by recall command)
            for(size_t i = 0; i < line_length; i++){
                if(line[i] == '\r'){
                    line[i] = '\n';
                }
            }

            // Don't print empty responses
            if(line_length != 0){
                printf("%s\n", line);
            }
        }

        if(string_starts_with(message, "exit")){
            break;
        }
    }

    logf("exiting...\n");
    exitcode = EXIT_SUCCESS;

done:
    if(fd != -1){
        close(fd);
    }

    free(user);
    return exitcode;
}

