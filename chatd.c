
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include <pwd.h>

#include "include/encryption.h"
#include "include/read_line.h"
#include "include/tweetnacl.h"
#include "logf.h"
#include "strings.h"
#include "read_line.h"
#include "write_line.h"
#include "encryption.h"
#include "parser-defs.h"
#include "parser.generated.h"

static const int CONNFD = 4, CHATPRIV_WRITEFD = 6, CHATPRIV_READFD = 7;

const char *PROGRAM_NAME = "chatd";

static void show_usage(const char *program_name){
    fprintf(stderr, "usage: %s [-h]\n", program_name);
}

// Similar to `strcat`, but will return -1 if would overflow the result buffer
static int string_append(char *buffer, size_t buffer_size, const char *message){
    size_t message_length = strlen(message);
    size_t buffer_length = strlen(buffer);

    if(buffer_length + message_length + 1 >= buffer_size){
        return -1;
    }

    memcpy(&buffer[buffer_length], message, message_length + 1);

    assert(0 <= (int) message_length && message_length < INT_MAX);
    return message_length;
}

// Similar to `strcat`, but will safely forget earlier characters in the case of overflow
// With prefix buffer with `...` if scrolled when `with_ellipses` is true.
static void string_append_scrolling(
    char *buffer,
    size_t buffer_size,
    const char *message,
    bool with_ellipses
){
    assert(buffer_size > 0);

    size_t message_length = strlen(message);
    size_t buffer_length = strlen(buffer);

    // Message cannot fit even in its entirity
    if(message_length + 1 > buffer_size){
        // Use last part of message, this will take the last (buffer_size - 1) characters and NUL byte
        memcpy(buffer, &message[message_length - (buffer_size - 1)], buffer_size);

        if(with_ellipses){
            // This is safe since it will never overwrite the NUL terminator
            // because our string is longer than 3 characters
            memcpy(buffer, "...", 3);
        }
        return;
    }

    // Message can fit fully, but might require scrolling

    // The amount to keep is the content capacity of the buffer minus the length of the new message
    size_t keep_amount = (buffer_size - 1) - message_length;

    // Don't keep more than the existing characters
    if(keep_amount > buffer_length){
        keep_amount = buffer_length;
    }

    // Move the amount to keep to the front of the buffer
    memmove(buffer, &buffer[buffer_length - keep_amount], keep_amount);

    // Copy message (along with null terminator) to after the kept characters
    memcpy(&buffer[keep_amount], message, message_length + 1);

    if(with_ellipses && keep_amount != buffer_length){
        // This is safe since it will never overwrite the NUL terminator
        // because our string is longer than 3 characters
        memcpy(buffer, "...", 3);
    }
}

static void recall(
    struct chat_cmd *cmd,
    const char *current_room,
    unsigned char client_public_key[crypto_box_PUBLICKEYBYTES],
    unsigned char server_secret_key[crypto_box_SECRETKEYBYTES]
){
    DIR *directory = NULL;
    int file_fd = -1;
    const char *room_name = NULL;

    if(strlen(cmd->arg1) != 0){
        room_name = cmd->arg1;
    } else if(current_room != NULL){
        room_name = current_room;
    } else {
        write_line_encrypted(CONNFD, client_public_key, server_secret_key, "recall requires room name");
        goto done;
    }

    directory = opendir(room_name);
    if(directory == NULL){
        write_line_encrypted(CONNFD, client_public_key, server_secret_key, "you don't have permission to recall that room");
        goto done;
    }

    char buffer[ENCRYPTED_MESSAGE_CONTENT_CAPACITY];
    memset(buffer, 0, sizeof buffer);

    struct dirent *entry;

    while((entry = readdir(directory)) != NULL){
        const char *raw_filename = entry->d_name;

        // Ignore non-files
        if(entry->d_type != DT_REG){
            continue;
        }

        char filename[BUFSIZ];
        memset(filename, 0, sizeof filename);

        if(string_append(filename, sizeof filename, room_name) == -1
        || string_append(filename, sizeof filename, "/") == -1
        || string_append(filename, sizeof filename, raw_filename) == -1
        ){
            logf("failed to create path to message during recall\n");
            goto failed;
        }

        logf("recalling message from file `%s`\n", filename);

        struct stat info;
        if(stat(filename, &info) != 0){
            logf("failed to get information about message file\n");
            goto failed;
        }

        struct passwd *owner_info = getpwuid(info.st_uid);
        if(owner_info == NULL){
            logf("failed to get owner of message file\n");
            goto failed;
        }

        file_fd = open(filename, O_RDONLY);
        if(file_fd == -1){
            logf("failed to open message file\n");
            goto failed;
        }

        char message[BUFSIZ];
        memset(message, 0, sizeof message);

        if(read_line_unencrypted(file_fd, message) == -1){
            logf("failed to read message file\n");
            goto failed;
        }

        close(file_fd);
        file_fd = -1;

        char line[BUFSIZ + 256];
        memset(line, 0, sizeof line);

        if(string_append(line, sizeof line, filename) == -1
        || string_append(line, sizeof line, " ") == -1
        || string_append(line, sizeof line, owner_info->pw_name) == -1
        || string_append(line, sizeof line, " ") == -1
        || string_append(line, sizeof line, message) == -1
        ){
            logf("failed to concatenate message information for line\n");
            goto failed;
        }

        // Ensure no newlines in read message
        size_t message_length = strlen(message);
        for(size_t i = 0; i < message_length; i++){
            if(message[i] == '\n'){
                logf("failed to recall a message, as it included a newline\n");
                goto failed;
            }
        }

        // Append to scrolling result buffer

        // Add '\r' to signal newline between messages
        if(strlen(buffer) != 0){
            string_append_scrolling(buffer, sizeof buffer, "\r", true);
        }

        // Add message
        string_append_scrolling(buffer, sizeof buffer, raw_filename, true);
        string_append_scrolling(buffer, sizeof buffer, " ", true);
        string_append_scrolling(buffer, sizeof buffer, owner_info->pw_name, true);
        string_append_scrolling(buffer, sizeof buffer, " ", true);
        string_append_scrolling(buffer, sizeof buffer, message, true);
    }

    write_line_encrypted(CONNFD, client_public_key, server_secret_key, buffer);
    goto done;

failed:
    write_line_encrypted(CONNFD, client_public_key, server_secret_key, "failed to recall room information");

done:
    if(file_fd != -1){
        close(file_fd);
    }
    if(directory != NULL){
        closedir(directory);
    }
}

int main(int argc, char *argv[]){
    int opt, exitcode = EXIT_FAILURE;
    char *current_room = NULL;

    while((opt = getopt(argc, argv, "h")) != -1){
        switch (opt) {
        case 'h':
            show_usage(argv[0]);
            exitcode = EXIT_SUCCESS;
            goto done;
        default:
            fprintf(stderr, "%s: invalid option -- '%c'\n", argv[0], opt);
            show_usage(argv[0]);
            goto done;
        }
    }

    if(optind < argc){
        show_usage(argv[0]);
        goto done;
    }

    // Ensure the file descriptors that we expect to exist do exist
    assert((fcntl(CONNFD, F_GETFD) != -1 || errno != EBADF) && "CONNFD is valid");
    assert((fcntl(CHATPRIV_READFD, F_GETFD) != -1 || errno != EBADF) && "CHATPRIV_READFD is valid");
    assert((fcntl(CHATPRIV_WRITEFD, F_GETFD) != -1 || errno != EBADF) && "CHATPRIV_WRITEFD is valid");

    logf("reading keys from files...\n");

    char buffer[ENCRYPTED_MESSAGE_CONTENT_CAPACITY];

    unsigned char client_public_key[crypto_box_PUBLICKEYBYTES];
    read_public_key_from_file_or_panic("client.pub", client_public_key);

    unsigned char server_secret_key[crypto_box_SECRETKEYBYTES];
    read_secret_key_from_file_or_panic("server.sec", server_secret_key);

    logf("keys obtained...\n");

    for(;;){
        logf("waiting for encrypted line...\n");

        if(read_line_encrypted(CONNFD, client_public_key, server_secret_key, buffer) >= 0){
            logf("got encrypted line `%s`\n", buffer);

            struct chat_cmd cmd;
            if(chat_parse(buffer, &cmd) != 0){
                // Ignore bad command
                logf("warning: bad command\n");
                write_line_encrypted(CONNFD, client_public_key, server_secret_key, "invalid command");
                continue;
            }

            switch(cmd.id){
            case CHAT_CMD_EXIT:
                logf("running EXIT\n");
                write_line_unencrypted(CHATPRIV_WRITEFD, buffer);
                goto success;
            case CHAT_CMD_ECHO:
                logf("running ECHO\n");
                assert(strlen(cmd.arg1) <= ENCRYPTED_MESSAGE_CONTENT_CAPACITY);
                write_line_encrypted(CONNFD, client_public_key, server_secret_key, cmd.arg1);
                logf("done processing ECHO\n");
                break;
            case CHAT_CMD_ENTER:
                if(current_room != NULL){
                    free(current_room);
                    current_room = NULL;
                }

                current_room = strdup(cmd.arg1);
                write_line_encrypted(CONNFD, client_public_key, server_secret_key, current_room != NULL ? "" : "failed to enter room");
                break;
            case CHAT_CMD_LEAVE:
                free(current_room);
                current_room = NULL;

                write_line_encrypted(CONNFD, client_public_key, server_secret_key, "");
                break;
            case CHAT_CMD_DEEP_ECHO:
            case CHAT_CMD_CREATE:
            case CHAT_CMD_DESTROY:
            case CHAT_CMD_INVITE: {
                    logf("sending privileged to chatpriv...\n");
                    write_line_unencrypted(CHATPRIV_WRITEFD, buffer);
                    logf("reading response from chatpriv...\n");

                    char response[BUFSIZ];
                    int response_length = read_line_unencrypted(CHATPRIV_READFD, response);

                    if(response_length < 0){
                        // Bad response
                        logf("warning: got bad response from chatpriv for privileged command\n");
                        goto success;
                    }

                    logf("writing back privileged response to user...\n");
                    write_line_encrypted(CONNFD, client_public_key, server_secret_key, response);
                }
                break;
            case CHAT_CMD_SAY: {
                    time_t raw_time;
                    if(time(&raw_time) == (time_t) -1){
                        logf("warning: failed to get current time\n");
                        goto success;
                    }

                    struct tm *time_info = localtime(&raw_time);
                    if(time_info == NULL){
                        logf("warning: failed to translate current time\n");
                        goto success;
                    }
                    
                    char buffer[256];
                    if(strftime(buffer, sizeof buffer, "%Y-%m-%d+%T", time_info) <= 0){
                        logf("warning: failed to format time for message\n");
                        goto success;
                    }

                    const char *room_name = NULL, *message = NULL;

                    if(strlen(cmd.arg2) == 0 && current_room != NULL){
                        // say <message>
                        room_name = current_room;
                        message = cmd.arg1;
                    } else if(strlen(cmd.arg1) != 0 && strlen(cmd.arg2) != 0){
                        // say <room> <message>
                        room_name = cmd.arg1;
                        message = cmd.arg2;
                    } else {
                        write_line_encrypted(CONNFD, client_public_key, server_secret_key, "say requires room name");
                        break;
                    }

                    char path[ENCRYPTED_MESSAGE_CONTENT_CAPACITY + 256];
                    memset(path, 0, sizeof path);

                    if(string_append(path, sizeof path, room_name) == -1
                    || string_append(path, sizeof path, "/") == -1
                    || string_append(path, sizeof path, buffer) == -1
                    ){
                        logf("warning: could not concatenate parts into path, too long\n");
                        goto success;
                    }

                    int file = open(path, O_WRONLY | O_CREAT | O_EXCL, 0640);

                    if(file == -1){
                        write_line_encrypted(CONNFD, client_public_key, server_secret_key, "you don't have access to this room or someone else sent a message at the same time, try again");
                        break;
                    }

                    ssize_t message_length = strlen(message);
                    if(write(file, message, message_length) != message_length){
                        logf("warning: failed to write message content\n");
                    }

                    close(file);
                    write_line_encrypted(CONNFD, client_public_key, server_secret_key, "");
                }
                break;
            case CHAT_CMD_UNSAY: {
                    const char *room_name = cmd.arg1;

                    char serialized_time[256];
                    if(strftime(serialized_time, sizeof serialized_time, "%Y-%m-%d+%T", &cmd.tm_whole) <= 0){
                        logf("warning: failed to format time for message\n");
                        goto success;
                    }

                    char path[BUFSIZ];
                    memset(path, 0, sizeof path);

                    if(string_append(path, sizeof path, room_name) == -1
                    || string_append(path, sizeof path, "/") == -1
                    || string_append(path, sizeof path, serialized_time) == -1){
                        logf("warning: failed to create path to message file to unlink\n");
                        goto success;
                    }

                    if(unlink(path) == -1){
                        write_line_encrypted(CONNFD, client_public_key, server_secret_key, "you don't have permission to unsay that message");
                        break;
                    }

                    write_line_encrypted(CONNFD, client_public_key, server_secret_key, "");
                }
                break;
            case CHAT_CMD_RECALL:
                recall(&cmd, current_room, client_public_key, server_secret_key);
                break;
            default:
                // Ignore bad command
                logf("warning: bad command\n");
                write_line_encrypted(CONNFD, client_public_key, server_secret_key, "unknown command");
            }
        } else {
            logf("exiting... due to failure to read encrypted line\n");
            break;
        }
    }

success:
    exitcode = EXIT_SUCCESS;

done:
    free(current_room);
    close(CONNFD);
    return exitcode;
}

