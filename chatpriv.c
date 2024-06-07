
#define _GNU_SOURCE
#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <shadow.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>
#include <poll.h>
#include <fcntl.h>
#include <grp.h>

#include "auth_command.h"
#include "strings.h"
#include "tweetnacl.h"
#include "read_line.h"
#include "write_line.h"
#include "encryption.h"
#include "logf.h"
#include "parser.generated.h"

static void show_usage(const char *program_name){
    fprintf(stderr, "usage: %s [-h] PORT\n", program_name);
}

static int listen_and_serve(short port);

typedef enum {
    CLIENT_STATE_INVALID,
    CLIENT_STATE_AWAITING_PUBLIC_KEY,
    CLIENT_STATE_AWAITING_AUTH,
    CLIENT_STATE_AWAITING_CHATD_INTERACTION,
} client_state_t;

#define CLIENT_BUFFER_SIZE 8192

typedef struct {
    client_state_t state;
    unsigned char public_key[crypto_box_PUBLICKEYBYTES];
    int chatd_write_fd;
    char buffer[CLIENT_BUFFER_SIZE];
    size_t buffer_length;
    char username[USERNAME_BUFFER_SIZE];
} client_t;

#define POLL_FDS_CAPACITY 2048
static struct pollfd poll_fds[POLL_FDS_CAPACITY];
static client_t associated_client_info[POLL_FDS_CAPACITY];
static size_t num_poll_fds = 0;

static int try_add_poll_fd(int fd, client_t optional_associated_client_info){
    if(num_poll_fds >= POLL_FDS_CAPACITY){
        return -1;
    }

    associated_client_info[num_poll_fds] = optional_associated_client_info;

    poll_fds[num_poll_fds] = (struct pollfd){
        .fd = fd,
        .events = POLLIN,
    };

    num_poll_fds++;
    return 0;
}

static void remove_poll_fd_index(int index){
    memmove(&poll_fds[index], &poll_fds[index + 1], (num_poll_fds - index - 1) * sizeof *poll_fds);
    memmove(&associated_client_info[index], &associated_client_info[index + 1], (num_poll_fds - index - 1) * sizeof *associated_client_info);
    num_poll_fds--;
}

const char *PROGRAM_NAME = "chatpriv";

int main(int argc, char *argv[]){
    int opt, exitcode = EXIT_FAILURE;

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

    if(!(optind < argc)){
        show_usage(argv[0]);
        goto done;
    }

    int port = atoi(argv[optind++]);

    if(port < 1 || port > 65535){
        show_usage(argv[0]);
        goto done;
    }

    if(optind < argc){
        show_usage(argv[0]);
        goto done;
    }

    exitcode = listen_and_serve(port);

done:
    return exitcode;
}

static bool credentials_are_valid(const char *username, const char *password){
    int rc = lckpwdf();
    if(rc == -1){
        perror("failed to lock /etc/shadow");
        return false;
    }

    bool valid = false;

    FILE *shadow = fopen("/etc/shadow", "r");
    if(shadow == NULL){
        perror("could not open /etc/shadow");
        goto done;
    }

    struct spwd *rec = NULL;

    while((rec = fgetspent(shadow)) != NULL){
        if(strcmp(rec->sp_namp, username) == 0){
            char *hash = crypt(password, rec->sp_pwdp);
            valid = strcmp(rec->sp_pwdp, hash) == 0;
            goto done;
        }
    }

done:
    if(!valid){
        fprintf(stderr, "auth of %s failed\n", username);
    }

    if(shadow != NULL){
        fclose(shadow);
    }

    ulckpwdf();

    return valid;
}

static void authenticate(
    const char *auth_command_text,
    int client_index,
    int sockfd
){
    int *connfd = &poll_fds[client_index].fd;
    client_t *client = &associated_client_info[client_index];

    logf("parsing auth command...\n");
    auth_command_t auth_command = parse_auth_command(auth_command_text);

    if(!is_auth_command_valid(&auth_command)){
        logf("failed to parse auth command\n");
        return;
    }

    logf("checking if credentials are valid...\n");
    if(!credentials_are_valid(auth_command.username, auth_command.password)){
        logf("invalid credentials\n");
        return;
    }

    struct passwd *pw = getpwnam(auth_command.username);
    if(pw == NULL){
        // User no longer exists
        logf("user no longer exists\n");
        return;
    }

    int upstream[2], downstream[2];

    // Remember username this user logged in as
    static_assert(
        sizeof client->username == USERNAME_BUFFER_SIZE,
        "client_t username must be exactly USERNAME_BUFFER_SIZE bytes"
    );
    static_assert(
        sizeof auth_command.username == USERNAME_BUFFER_SIZE,
        "auth_command username must be exactly USERNAME_BUFFER_SIZE bytes"
    );
    memcpy(client->username, auth_command.username, USERNAME_BUFFER_SIZE);

    // Create child to parent pipe
    if(pipe(upstream) != 0){
        perror("pipe");
        return;
    }

    // Create parent to child pipe
    if(pipe(downstream) != 0){
        perror("pipe");
        close(upstream[0]);
        close(upstream[1]);
        return;
    }

    uid_t chatter_uid = pw->pw_uid;
    pid_t p = fork();

    if(p == -1){
        // Error
        close(upstream[0]);
        close(upstream[1]);
        close(downstream[0]);
        close(downstream[1]);

        perror("fork");
        exit(EXIT_FAILURE);
    } else if(p == 0){
        // Child

        // Close poll fds
        for(size_t i = 0; i < num_poll_fds; i++){
            if(i != (size_t) client_index){
                struct pollfd *poll_fd = &poll_fds[i];

                if(poll_fd->fd != sockfd){
                    close(poll_fd->fd);
                    poll_fd->fd = -1;

                    client_t *client = &associated_client_info[i];
                    if(client->chatd_write_fd != -1){
                        close(client->chatd_write_fd);
                        client->chatd_write_fd = -1;
                    }
                }
            }
        }

        close(upstream[0]);
        close(downstream[1]);
        close(sockfd);
        sockfd = -1;

        const int CONNFD = 4, CHATPRIV_WRITEFD = 6, CHATPRIV_READFD = 7;

        // We must rearrange file descriptors to match what chatd expects.
        // NOTE: Order matters here, we must 'dup2' the lower fds first
        // so we don't override them with later 'dup2' calls.
        {
            logf("duping %d to %d [CONNFD]\n", *connfd, CONNFD);
            assert(dup2(*connfd, CONNFD) == CONNFD);

            logf("duping %d to %d [CHATPRIV_WRITEFD]\n", upstream[1], CHATPRIV_WRITEFD);
            assert(dup2(upstream[1], CHATPRIV_WRITEFD) == CHATPRIV_WRITEFD);

            logf("duping %d to %d [CHATPRIV_READFD]\n", downstream[0], CHATPRIV_READFD);
            assert(dup2(downstream[0], CHATPRIV_READFD) == CHATPRIV_READFD);
        }

        initgroups(pw->pw_name, pw->pw_gid);

        if(setresuid(chatter_uid, chatter_uid, chatter_uid) != 0){
            perror("setreuid");
            exit(EXIT_FAILURE);
        }

        uid_t r_uid = -1, e_uid = -1, s_uid = -1;
        if(getresuid(&r_uid, &e_uid, &s_uid) != 0){
            perror("getresuid");
            exit(EXIT_FAILURE);
        }

        if(r_uid != chatter_uid || e_uid != chatter_uid || s_uid != chatter_uid){
            logf("failed to change privileges to chatter\n");
            exit(EXIT_FAILURE);
        }

        // Ensure the file descriptors that chatd expects to exist do exist
        assert((fcntl(CONNFD, F_GETFD) != -1 || errno != EBADF) && "CONNFD is valid");
        assert((fcntl(CHATPRIV_READFD, F_GETFD) != -1 || errno != EBADF) && "CHATPRIV_READFD is valid");
        assert((fcntl(CHATPRIV_WRITEFD, F_GETFD) != -1 || errno != EBADF) && "CHATPRIV_WRITEFD is valid");

        logf("spawning chatd...\n");

        execlp("./chatd", "./chatd", (const char*) NULL);
        perror("execlp");
        exit(EXIT_FAILURE);
    } else {
        // Parent

        close(upstream[1]);
        close(downstream[0]);
        close(*connfd);
        *connfd = -1;

        int chatd_writefd = downstream[1], chatd_readfd = upstream[0];

        *connfd = chatd_readfd;
        client->chatd_write_fd = chatd_writefd;
        client->state = CLIENT_STATE_AWAITING_CHATD_INTERACTION;

        logf("successfully authenticated client...\n");
    }
}

static void accepted_connection(int connfd){
    client_t client = (client_t){
        .state = CLIENT_STATE_AWAITING_PUBLIC_KEY,
        .public_key = {},
        .chatd_write_fd = -1,
        .buffer = {},
        .buffer_length = 0,
        .username = {},
    };

    if(try_add_poll_fd(connfd, client) == -1){
        // Failed to accept into poll fds
        if(connfd != -1){
            close(connfd);
            connfd = -1;
        }
    }
}

static void kick_client(int index){
    struct pollfd *poll_fd = &poll_fds[index];
    client_t *client = &associated_client_info[index];

    if(poll_fd->fd != -1){
        close(poll_fd->fd);
        poll_fd->fd = -1;
    }

    if(client->state != CLIENT_STATE_INVALID && client->chatd_write_fd != -1){
        close(client->chatd_write_fd);
        client->chatd_write_fd = -1;
    }

    remove_poll_fd_index(index);
}

static int create_group(const char *group_name, const char *initial_user){
    pid_t pid = fork();

    if(pid == -1){
        perror("fork");
        return -1;
    } else if(pid == 0){
        // Child
        execl("/usr/sbin/groupadd", "/usr/sbin/groupadd", group_name, "-U", initial_user, NULL);
        perror("execlp");
        exit(EXIT_FAILURE);
    } else {
        // Parent
        int status = -1;
        if(waitpid(pid, &status, 0) == -1){
            logf("waitpid for groupadd failed\n");
            return -1;
        }

        int exit_code = 1;
        if(WIFEXITED(status)){
            exit_code = WEXITSTATUS(status);
        }

        return exit_code;
    }
}

static int add_user_to_group(const char *group_name, const char *username){
    pid_t pid = fork();

    if(pid == -1){
        perror("fork");
        return -1;
    } else if(pid == 0){
        // Child
        execl("/usr/sbin/usermod", "/usr/sbin/usermod", "-a", "-G", group_name, username, NULL);
        perror("execlp");
        exit(EXIT_FAILURE);
    } else {
        // Parent
        int status = -1;
        if(waitpid(pid, &status, 0) == -1){
            logf("waitpid for usermod failed\n");
            return -1;
        }

        int exit_code = 1;
        if(WIFEXITED(status)){
            exit_code = WEXITSTATUS(status);
        }

        return exit_code;
    }
}

static int delete_group(const char *group_name){
    pid_t pid = fork();

    if(pid == -1){
        perror("fork");
        return -1;
    } else if(pid == 0){
        // Child
        execl("/usr/sbin/groupdel", "/usr/sbin/groupdel", group_name, NULL);
        perror("execlp");
        exit(EXIT_FAILURE);
    } else {
        // Parent
        int status = -1;
        if(waitpid(pid, &status, 0) == -1){
            logf("waitpid for groupdel failed\n");
            return -1;
        }

        int exit_code = 1;
        if(WIFEXITED(status)){
            exit_code = WEXITSTATUS(status);
        }

        return exit_code;
    }
}

static bool user_owns_directory(const char *username, const char *directory){
    struct stat stat_info = {};

    if(stat(directory, &stat_info) != 0){
        logf("warning: user_owns_directory failed to call stat, denying...\n");
        return false;
    }

    struct passwd *user_info = getpwnam(username);

    if(user_info == NULL){
        logf("warning: user_owns_directory failed to get user info via getpwnam, denying...\n");
        return false;
    }

    return user_info->pw_uid == stat_info.st_uid;
}

static void run_privileged_command(client_t *client, struct chat_cmd *cmd, int i){
    switch(cmd->id){
    case CHAT_CMD_DEEP_ECHO:
        logf("got deep-echo\n");
        write_line_unencrypted(client->chatd_write_fd, cmd->arg1);
        break;
    case CHAT_CMD_CREATE:
        logf("got create\n");
        logf("creating new directory for chat room `%s`\n", cmd->arg1);

        mode_t old_mask = umask(S_IRWXO);
        
        // NOTE: This path is pre-validated by parser
        if(mkdir(cmd->arg1, S_ISGID | S_ISVTX | S_IRWXU | S_IRWXG) != 0){
            perror("mkdir");
            write_line_unencrypted(client->chatd_write_fd, "failed to create room");
            break;
        }

        umask(old_mask);

        logf("creating new group `%s`\n", cmd->arg1);

        // NOTE: This group name is pre-validated by the parser
        if(create_group(cmd->arg1, client->username) != 0){
            write_line_unencrypted(client->chatd_write_fd, "failed to create group");
            break;
        }

        logf("getting uid of user and gid of new group\n");
        struct passwd *user_info = getpwnam(client->username);
        struct group *group_info = getgrnam(cmd->arg1);

        if(user_info == NULL || group_info == NULL){
            write_line_unencrypted(client->chatd_write_fd, "failed to get uid and gid");
            break;
        }

        gid_t gid = group_info->gr_gid;
        uid_t uid = user_info->pw_uid;

        logf("setting user/group owner of new directory\n");

        // NOTE: The directory name is pre-validated by the parser
        if(chown(cmd->arg1, uid, gid) != 0){
            write_line_unencrypted(client->chatd_write_fd, "failed to create chown");
            break;
        }
        
        logf("validating new room permissions\n");

        struct stat stat_info = {};

        // note: the directory name is pre-validated by the parser
        if(stat(cmd->arg1, &stat_info) != 0){
            write_line_unencrypted(client->chatd_write_fd, "failed to stat the new directory");
            break;
        }

        if(stat_info.st_uid != uid || stat_info.st_gid != gid){
            write_line_unencrypted(client->chatd_write_fd, "permissions of directory did not change as expected");
            break;
        }

        logf("created room\n");
        write_line_unencrypted(client->chatd_write_fd, "");
        break;
    case CHAT_CMD_INVITE: {
            logf("got invite\n");

            const char *room_name = cmd->arg1;
            const char *user_to_invite = cmd->arg2;

            logf("checking invite permissions\n");

            if(!user_owns_directory(client->username, room_name)){
                write_line_unencrypted(client->chatd_write_fd, "cannot invite user to room that isn't yours");
                break;
            }

            logf("adding invited user to group\n");

            if(add_user_to_group(room_name, user_to_invite) != 0){
                write_line_unencrypted(client->chatd_write_fd, "failed to invite user to room");
                break;
            }

            logf("invited user to room\n");
            write_line_unencrypted(client->chatd_write_fd, "");
        }
        break;
    case CHAT_CMD_DESTROY: {
            logf("got destroy\n");

            const char *room_name = cmd->arg1;

            logf("checking room permissions\n");

            if(!user_owns_directory(client->username, room_name)){
                write_line_unencrypted(client->chatd_write_fd, "cannot destroy room that isn't yours");
                break;
            }

            if(rmdir(room_name) != 0){
                write_line_unencrypted(client->chatd_write_fd, "failed to destroy room");
                break;
            }

            if(delete_group(room_name) != 0){
                write_line_unencrypted(client->chatd_write_fd, "failed to delete group");
                break;
            }

            write_line_unencrypted(client->chatd_write_fd, "");
        }
        break;
    case CHAT_CMD_EXIT:
        logf("got EXIT\n");
        kick_client(i);
        return;
    default:
        // Ignore unrecognized command
        break;
    }
}

static void handle_client_event(
    int i,
    int connfd,
    int sockfd,
    unsigned char server_secret_key[crypto_box_SECRETKEYBYTES]
){
    // Normal client connection
    client_t *client = &associated_client_info[i];

    // If buffer is full, kick client
    if(client->buffer_length >= CLIENT_BUFFER_SIZE){
        kick_client(i);
        return;
    }

    // Read byte
    char most_recent_char = '\0';
    if(read(connfd, &most_recent_char, sizeof most_recent_char) != 1){
        kick_client(i);
        return;
    }

    // Append byte
    client->buffer[client->buffer_length++] = most_recent_char;

    // Handle state
    switch(client->state){
    case CLIENT_STATE_INVALID: {
            logf("invalid client state for fd=%d\n", connfd);
            assert(false && "unreachable client state");
        }
        break;
    case CLIENT_STATE_AWAITING_PUBLIC_KEY: {
            static_assert(crypto_box_PUBLICKEYBYTES <= CLIENT_BUFFER_SIZE, "public keys must be able to fit in client buffers");

            if(client->buffer_length == crypto_box_PUBLICKEYBYTES){
                logf("successfully read client public key\n");
                memcpy(client->public_key, client->buffer, crypto_box_PUBLICKEYBYTES);
                client->buffer_length = 0;
                client->state = CLIENT_STATE_AWAITING_AUTH;
            }
        }
        break;
    case CLIENT_STATE_AWAITING_AUTH: {
            static_assert(
                ENCRYPTED_MESSAGE_CONTAINER_SIZE <= CLIENT_BUFFER_SIZE,
                "encrypted message containers must be able to fit in client buffers"
            );

            static_assert(
                ENCRYPTED_MESSAGE_CONTAINER_SIZE == sizeof(encrypted_message_container_t),
                "encrypted message containers must be exactly ENCRYPTED_MESSAGE_CONTAINER_SIZE bytes"
            );

            if(client->buffer_length == ENCRYPTED_MESSAGE_CONTAINER_SIZE){
                encrypted_message_container_t container;
                memcpy(&container, client->buffer, ENCRYPTED_MESSAGE_CONTAINER_SIZE);
                client->buffer_length = 0;

                char decrypted[ENCRYPTED_MESSAGE_CONTENT_CAPACITY];
                if(decrypt_content(&container, client->public_key, server_secret_key, decrypted) != 0){
                    kick_client(i);
                    return;
                }
                
                logf("got encrypted line: %s\n", decrypted);
                logf("authenticating...\n");
                authenticate(decrypted, i, sockfd);
            }
        }
        break;
    case CLIENT_STATE_AWAITING_CHATD_INTERACTION: {
            if(most_recent_char == '\n'){
                client->buffer[client->buffer_length - 1] = '\0';
                client->buffer_length = 0;

                struct chat_cmd cmd;
                if(chat_parse(client->buffer, &cmd) != 0){
                    logf("got bad command: `%s`, exiting...\n", client->buffer);
                    kick_client(i);
                    return;
                }

                run_privileged_command(client, &cmd, i);
            }
        }
        break;
    }
}

static int listen_and_serve(short port){
    int exitcode = EXIT_FAILURE;
    struct sockaddr_in addr = { 0 };
    int sockfd = -1, yes = 1, rc;
    errno = 0;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd == -1){
        perror("error creating listening socket");
        goto done;
    }

    rc = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
    if(rc == -1){
        perror("error setting socket option");
        goto done;
    }

    addr.sin_port = htons(port);
    addr.sin_family = PF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;

    rc = bind(sockfd, (struct sockaddr*) &addr, sizeof addr);
    if(rc == -1){
        perror("error binding listening socket to port");
        goto done;
    }

    rc = listen(sockfd, 0);
    if(rc == -1){
        perror("failed to listen");
        goto done;
    }

    unsigned char server_public_key[crypto_box_PUBLICKEYBYTES];
    read_public_key_from_file_or_panic("server.pub", server_public_key);

    unsigned char server_secret_key[crypto_box_SECRETKEYBYTES];
    read_secret_key_from_file_or_panic("server.sec", server_secret_key);

    // The connection listener fd doesn't have any client state, so we'll use an invalid one
    assert(
        try_add_poll_fd(
            sockfd,
            (client_t){
                .state = CLIENT_STATE_INVALID,
                .chatd_write_fd = -1,
            }
        ) == 0
    );

    for(;;){
        if(poll(poll_fds, num_poll_fds * sizeof *poll_fds, -1) == -1){
            perror("error polling");
            goto done;
        }

        // NOTE: If any clients are kicked, we may delay reading from ready clients
        // until the next iteration.
        // NOTE: The listener fd will always be handled if ready.
        for(size_t i = 0; i < num_poll_fds; i++){
            struct pollfd *poll_fd = &poll_fds[i];

            // Ensure fd is ready
            if(!(poll_fd->revents & POLLIN)){
                continue;
            }

            if(poll_fd->fd == sockfd){
                int connfd = accept(sockfd, NULL, NULL);
                if(connfd == -1){
                    perror("failed to accept");
                    goto done;
                }

                accepted_connection(connfd);
            } else {
                handle_client_event(i, poll_fd->fd, sockfd, server_secret_key);
            }
        }
    }

done:
    if(sockfd != -1){
        close(sockfd);
    }

    return exitcode;
} 

