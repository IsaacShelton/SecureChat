#include <stdio.h>
#include <string.h>

#include "parser.generated.h"

#define T1(c, expected1) \
rc = chat_parse(c, &cmd); \
if (rc != 0) { \
	fprintf(stderr, "line %d: %s\n", chat_err_lineno(), chat_err_msg()); \
} else if (cmd.id != expected1) { \
	fprintf(stderr, "failed to parse %s (%d != %d)\n", c, cmd.id, expected1); \
} else { \
	fprintf(stderr, "ok\n"); \
}

#define T2(c, expected1, expected2) \
rc = chat_parse(c, &cmd); \
if (rc != 0) { \
	fprintf(stderr, "line %d: %s\n", chat_err_lineno(), chat_err_msg()); \
} else if (cmd.id != expected1) { \
	fprintf(stderr, "failed to parse %s (%d != %d)\n", c, cmd.id, expected1); \
} else if (strcmp(cmd.arg1, expected2)) { \
	fprintf(stderr, "failed to parse %s (%s != %s)\n", c, cmd.arg1, expected2); \
} else { \
	fprintf(stderr, "ok\n"); \
}

#define T3(c, expected1, expected2, expected3) \
rc = chat_parse(c, &cmd); \
if (rc != 0) { \
	fprintf(stderr, "line %d: %s\n", chat_err_lineno(), chat_err_msg()); \
} else if (cmd.id != expected1) { \
	fprintf(stderr, "failed to parse %s (%d != %d)\n", c, cmd.id, expected1); \
} else if (strcmp(cmd.arg1, expected2)) { \
	fprintf(stderr, "failed to parse %s (%s != %s)\n", c, cmd.arg1, expected2); \
} else if (strcmp(cmd.arg2, expected3)) { \
	fprintf(stderr, "failed to parse %s (%s != %s)\n", c, cmd.arg2, expected3); \
} else { \
	fprintf(stderr, "ok\n"); \
}

#define TTIMESTAMP(c, expected1, expected2, ts, frac) { \
	char s[sizeof("0000-00-00 00:00:00")]; \
	rc = chat_parse(c, &cmd); \
	strftime(s, sizeof(s), "%Y-%m-%d %T", &cmd.tm_whole); \
	if (rc != 0) { \
		fprintf(stderr, "line %d: %s\n", chat_err_lineno(), chat_err_msg()); \
	} else if (cmd.id != expected1) { \
		fprintf(stderr, "failed to parse %s (%d != %d)\n", c, cmd.id, expected1); \
	} else if (strcmp(cmd.arg1, expected2)) { \
		fprintf(stderr, "failed to parse %s (%s != %s)\n", c, cmd.arg1, expected2); \
	} else if (strcmp(s, ts)) { \
		fprintf(stderr, "failed to parse %s (%s != %s)\n", c, s, ts); \
	} else if (cmd.tm_frac != frac) { \
		fprintf(stderr, "failed to parse %s (%d != %d)\n", c, cmd.tm_frac, frac); \
	} else { \
		fprintf(stderr, "ok\n"); \
	} \
}

#define TFAIL(c) \
rc = chat_parse(c, &cmd); \
if (rc == 0) { \
	fprintf(stderr, "syntax error undetected\n"); \
} else { \
	fprintf(stderr, "ok\n"); \
}

int main(void)
{
	int rc;
	struct chat_cmd cmd;

	T1("", CHAT_CMD_INVALID);
	T1("\n", CHAT_CMD_INVALID);
	T3("auth student password\n", CHAT_CMD_AUTH, "student", "password");
	T2("echo message\n", CHAT_CMD_ECHO, "message");
	T2("deep-echo message\n", CHAT_CMD_DEEP_ECHO, "message");
	T2("create room\n", CHAT_CMD_CREATE, "room");
	T3("invite username room\n", CHAT_CMD_INVITE, "username", "room");
	T2("enter room\n", CHAT_CMD_ENTER, "room");
	T2("leave room\n", CHAT_CMD_LEAVE, "room");
	T3("say room message\n", CHAT_CMD_SAY, "room", "message");
	T3("say room \"long message\"\n", CHAT_CMD_SAY, "room", "long message");
	T2("recall room\n", CHAT_CMD_RECALL, "room");
	TTIMESTAMP("unsay room 2022-04-06 15:08:59\n", CHAT_CMD_UNSAY, "room", "2022-04-06 15:08:59", 0);
	TTIMESTAMP("unsay room 2022-04-06 15:08:59.1\n", CHAT_CMD_UNSAY, "room", "2022-04-06 15:08:59", 1);
	TTIMESTAMP("unsay room 2022-04-06 15:08:59.123456789\n", CHAT_CMD_UNSAY, "room", "2022-04-06 15:08:59", 123456789);
	T2("destroy room\n", CHAT_CMD_DESTROY, "room");
	T1("exit\n", CHAT_CMD_EXIT);

	TFAIL("bad-command\n");
	TFAIL("echo foo bar\n");                     // Missing quotes
	TFAIL("unsay room 2002-02\n");
	TFAIL("unsay room 2022-13-06 15:08:59.1\n"); // Invalid month
	TFAIL("unsay room 2022-04-32 15:08:59.1\n"); // Invalid day
	TFAIL("unsay room 2022-04-06 24:08:59.1\n"); // Invalid hour
	TFAIL("unsay room 2022-04-06 15:60:59.1\n"); // Invalid minute
	TFAIL("unsay room 2022-04-06 15:08:60.1\n"); // Invalid second
}
