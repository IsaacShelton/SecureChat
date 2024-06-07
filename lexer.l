%{
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "parser.generated.h"
%}

%option yylineno
%option noyywrap

WHITESPACE   [[:blank:]]
ROOM         ([a-zA-Z0-9_\-])*
DATE         [0-9]{4}\-((0[1-9])|(1[0-2]))\-((0[1-9])|([12][0-9])|3[0-1])
TIME         (([01][0-9])|2([0-3])):([0-5][0-9]):([0-5][0-9])(\.[0-9]*)?
USERNAME     [a-z_]([a-z0-9_-]{0,31}|[a-z0-9_-]{0,30}\$)
PASSORMSG    ([[:graph:]])*
QUOPASSORMSG (\"([[:print:]])*\")*

%%

auth           { yylval.id = CHAT_CMD_AUTH; return TOK_CMD_AUTH; }
echo           { yylval.id = CHAT_CMD_ECHO; return TOK_CMD_ECHO; }
deep-echo      { yylval.id = CHAT_CMD_DEEP_ECHO; return TOK_CMD_DEEP_ECHO; }
create         { yylval.id = CHAT_CMD_CREATE; return TOK_CMD_CREATE; }
invite         { yylval.id = CHAT_CMD_INVITE; return TOK_CMD_INVITE; }
enter          { yylval.id = CHAT_CMD_ENTER; return TOK_CMD_ENTER; }
leave          { yylval.id = CHAT_CMD_LEAVE; return TOK_CMD_LEAVE; }
say            { yylval.id = CHAT_CMD_SAY; return TOK_CMD_SAY; }
recall         { yylval.id = CHAT_CMD_RECALL; return TOK_CMD_RECALL; }
unsay          { yylval.id = CHAT_CMD_UNSAY; return TOK_CMD_UNSAY; }
destroy        { yylval.id = CHAT_CMD_DESTROY; return TOK_CMD_DESTROY; }
exit           { yylval.id = CHAT_CMD_EXIT; return TOK_CMD_EXIT; }
{DATE}         {
                   char *p = strptime(yytext, "%Y-%m-%d", &yylval.timestamp.whole);
                   assert(p);

                   return TOK_DATE;
               }
{TIME}         {
                   char *point = strptime(yytext, "%T", &yylval.timestamp.whole);
                   assert(point);

                   if('\0' != *point){
                       int rc = sscanf(point + 1, "%d", &yylval.timestamp.fraction);
                       assert('.' == *point);
                       assert(1 == rc);
                   }

                   return TOK_TIME;
               }
{ROOM}         { strncpy(yylval.arg, yytext, sizeof(yylval.arg) - 1); return TOK_ROOM; }
{USERNAME}     { strncpy(yylval.arg, yytext, sizeof(yylval.arg) - 1); return TOK_USERNAME; }
{PASSORMSG}    { strncpy(yylval.arg, yytext, sizeof(yylval.arg) - 1); return TOK_PASSORMSG; }
{QUOPASSORMSG} {
                   /* Drop quote, then treat as TOK_PASSORMSG. */
                   strncpy(yylval.arg, yytext + 1, sizeof(yylval.arg) - 1);
                   yylval.arg[strlen(yylval.arg) - 1] = '\0';
                   return TOK_PASSORMSG;
               }
\n             { strncpy(yylval.arg, yytext, sizeof(yylval.arg) - 1); return TOK_NEWLINE; }
{WHITESPACE}   ; /* Consume but ignore white space. */
.              { strncpy(yylval.arg, yytext, sizeof(yylval.arg) - 1); return TOK_ERROR; }

%%

int chat_parse(const char *text, struct chat_cmd *cmd){
    yy_scan_string(text);
    yylineno = 1;
    yyparse();
    yy_delete_buffer(YY_CURRENT_BUFFER);
    *cmd = chat_cmd();
    return chat_err_lineno();
}
