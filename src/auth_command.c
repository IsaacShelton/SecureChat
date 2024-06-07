
#include <string.h>
#include <stdbool.h>

#include "auth_command.h"
#include "logf.h"
#include "../parser.generated.h"

auth_command_t parse_auth_command(const char *full_buffer){
    auth_command_t command;
    memset(&command, 0, sizeof command);

    struct chat_cmd cmd;
    memset(&cmd, 0, sizeof cmd);

    int err_lineno = chat_parse(full_buffer, &cmd);
    if(err_lineno != 0){
        logf(
            "warning: chat_parse failed (on line %d: %s)\n",
            err_lineno,
            chat_err_msg()
        );
        goto error;
    }

    if(cmd.id != CHAT_CMD_AUTH){
        logf("warning: parse_auth_command got non-auth command\n");
        goto error;
    }

    if(strlen(cmd.arg1) >= USERNAME_BUFFER_SIZE){
        logf("warning: parse_auth_command got username that is too long\n");
        goto error;
    }

    if(strlen(cmd.arg2) >= PASSWORD_BUFFER_SIZE){
        logf("warning: parse_auth_command got password that is too long\n");
        goto error;
    }

    // Valid auth command
    memset(&command, 0, sizeof command);
    strncpy(command.username, cmd.arg1, USERNAME_BUFFER_SIZE - 1);
    strncpy(command.password, cmd.arg2, PASSWORD_BUFFER_SIZE - 1);
    return command;

error:
    memset(&command, 0, sizeof command);
    return command;
}

bool is_auth_command_valid(auth_command_t *command){
    return command->username[0] != '\0';
}

