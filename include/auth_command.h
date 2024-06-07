
#ifndef ISAAC_AUTH_COMMAND_H_INCLUDED
#define ISAAC_AUTH_COMMAND_H_INCLUDED

#include <stdbool.h>

#define USERNAME_BUFFER_SIZE 64
#define PASSWORD_BUFFER_SIZE 256

typedef struct {
    char username[USERNAME_BUFFER_SIZE];
    char password[PASSWORD_BUFFER_SIZE];
} auth_command_t;

auth_command_t parse_auth_command(const char *buffer);

bool is_auth_command_valid(auth_command_t *command);

#endif // ISAAC_AUTH_COMMAND_H_INCLUDED

