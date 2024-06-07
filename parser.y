%{
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "parser-defs.h"

extern int yylineno;
extern int yylex();

static int _chat_err_lineno = 0;
static const char *_chat_err_msg = NULL;
static struct chat_cmd _chat_cmd = {0};

void yyerror(const char *);

#define C1(left, right1) \
    memset(&left, 0, sizeof(left)); \
    left.id = right1; \

#define C2(left, right1, right2) \
    memset(&left, 0, sizeof(left)); \
    left.id = right1; \
    strncpy(left.arg1, right2, sizeof(left.arg1) - 1); \

#define C3(left, right1, right2, right3) \
    memset(&left, 0, sizeof(left)); \
    left.id = right1; \
    strncpy(left.arg1, right2, sizeof(left.arg1) - 1); \
    strncpy(left.arg2, right3, sizeof(left.arg2) - 1);

#define CTIMESTAMP(left, right1, right2, right3, right4) { \
    memset(&left, 0, sizeof(left)); \
    left.id = right1; \
    strncpy(left.arg1, right2, sizeof(left.arg1) - 1); \
    left.tm_whole = right3.whole; \
    left.tm_whole.tm_hour = right4.whole.tm_hour; \
    left.tm_whole.tm_min = right4.whole.tm_min; \
    left.tm_whole.tm_sec = right4.whole.tm_sec; \
    left.tm_frac = right4.fraction; \
}

%}

%code requires {
#include "parser-defs.h"
}

%union {
    chat_cmd_id id;
    char arg[1024 + 1];
    struct {
        struct tm whole;
        int fraction;
    } timestamp;
    struct chat_cmd cmd;
}

%token TOK_CMD_AUTH
%token TOK_CMD_CREATE
%token TOK_CMD_DEEP_ECHO
%token TOK_CMD_DESTROY
%token TOK_CMD_ECHO
%token TOK_CMD_ENTER
%token TOK_CMD_EXIT
%token TOK_CMD_INVITE
%token TOK_CMD_LEAVE
%token TOK_CMD_RECALL
%token TOK_CMD_SAY
%token TOK_CMD_UNSAY
%token TOK_ERROR
%token TOK_NEWLINE
%token TOK_PASSORMSG
%token TOK_ROOM
%token TOK_DATE
%token TOK_TIME
%token TOK_USERNAME

%type <id>  TOK_CMD_AUTH
            TOK_CMD_CREATE
            TOK_CMD_DEEP_ECHO
            TOK_CMD_DESTROY
            TOK_CMD_ECHO
            TOK_CMD_ENTER
            TOK_CMD_EXIT
            TOK_CMD_INVITE
            TOK_CMD_LEAVE
            TOK_CMD_RECALL
            TOK_CMD_SAY
            TOK_CMD_UNSAY

%type <arg> TOK_NEWLINE
            TOK_PASSORMSG
            TOK_ROOM
            TOK_USERNAME

%type <timestamp> TOK_DATE
                  TOK_TIME

%type <cmd> command
            line

%%

input:
    %empty | line ;

line:
    command { _chat_cmd = $$; } ;

command:
    TOK_CMD_AUTH TOK_USERNAME TOK_PASSORMSG { C3($$, $1, $2, $3) } |
    TOK_CMD_AUTH TOK_ROOM TOK_ROOM { C3($$, $1, $2, $3) } |
    TOK_CMD_ECHO TOK_PASSORMSG { C2($$, $1, $2) } |
    TOK_CMD_ECHO TOK_ROOM { C2($$, $1, $2) } |
    TOK_CMD_DEEP_ECHO TOK_PASSORMSG { C2($$, $1, $2) } |
    TOK_CMD_DEEP_ECHO TOK_ROOM { C2($$, $1, $2) } |
    TOK_CMD_CREATE TOK_ROOM { C2($$, $1, $2) } |
    TOK_CMD_CREATE TOK_USERNAME { C2($$, $1, $2) } |
    TOK_CMD_INVITE TOK_USERNAME TOK_ROOM { C3($$, $1, $2, $3) } |
    TOK_CMD_INVITE TOK_ROOM TOK_ROOM { C3($$, $1, $2, $3) } |
    TOK_CMD_ENTER TOK_ROOM { C2($$, $1, $2) } |
    TOK_CMD_ENTER TOK_USERNAME { C2($$, $1, $2) } |
    TOK_CMD_LEAVE { C1($$, $1) } |
    TOK_CMD_SAY TOK_ROOM TOK_PASSORMSG { C3($$, $1, $2, $3) } |
    TOK_CMD_SAY TOK_ROOM TOK_ROOM { C3($$, $1, $2, $3) } |
    TOK_CMD_SAY TOK_ROOM { C2($$, $1, $2) } |
    TOK_CMD_SAY TOK_USERNAME { C2($$, $1, $2) } |
    TOK_CMD_SAY TOK_PASSORMSG { C2($$, $1, $2) } |
    TOK_CMD_RECALL TOK_ROOM { C2($$, $1, $2) } |
    TOK_CMD_RECALL TOK_USERNAME { C2($$, $1, $2) } |
    TOK_CMD_UNSAY TOK_ROOM TOK_DATE TOK_TIME { CTIMESTAMP($$, $1, $2, $3, $4) } |
    TOK_CMD_UNSAY TOK_USERNAME TOK_DATE TOK_TIME { CTIMESTAMP($$, $1, $2, $3, $4) } |
    TOK_CMD_DESTROY TOK_ROOM { C2($$, $1, $2) } |
    TOK_CMD_EXIT { C1($$, $1) } ;
%%

void yyerror(const char *s){
    _chat_err_lineno = yylineno;
    _chat_err_msg = s;
}

int chat_err_lineno(void){
    int lineno = _chat_err_lineno;
    _chat_err_lineno = 0;
    return lineno;
}

const char *chat_err_msg(void){
    const char *msg = _chat_err_msg;
    _chat_err_msg = NULL;
    return msg;
}

struct chat_cmd chat_cmd(void){
    return _chat_cmd;
}
