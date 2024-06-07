#ifndef PARSER_DEFS_H
#define PARSER_DEFS_H

#define __USE_XOPEN 1
#define _GNU_SOURCE
#include <time.h>
#include <stdio.h>

typedef enum {
    CHAT_CMD_INVALID,
    CHAT_CMD_AUTH,
    CHAT_CMD_ECHO,
    CHAT_CMD_DEEP_ECHO,
    CHAT_CMD_CREATE,
    CHAT_CMD_INVITE,
    CHAT_CMD_ENTER,
    CHAT_CMD_LEAVE,
    CHAT_CMD_SAY,
    CHAT_CMD_RECALL,
    CHAT_CMD_UNSAY,
    CHAT_CMD_DESTROY,
    CHAT_CMD_EXIT,
    CHAT_CMD_MAX,
} chat_cmd_id;

struct chat_cmd {
    chat_cmd_id id;
    char arg1[BUFSIZ + 1];
    char arg2[BUFSIZ + 1];
    struct tm tm_whole;
    int tm_frac; /* Unfortunately `struct tm` cannot store fractional seconds */
};

int chat_parse(const char *text, struct chat_cmd *cmd);
int chat_err_lineno(void);
const char *chat_err_msg(void);
struct chat_cmd chat_cmd(void);

#endif
