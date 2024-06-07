
LEX=lex
BISON=bison
CFLAGS=-Iinclude -fanalyzer -Wall -Wextra -g
INCLUDE=include
SRC_DIR=src
OBJ_DIR=obj
SOURCES=$(wildcard $(SRC_DIR)/*.c)
OBJECTS=$(SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

UNIT_TEST_SRC_DIR=unit_tests
UNIT_TEST_SOURCES=$(wildcard $(UNIT_TEST_SRC_DIR)/*.c)
UNIT_TEST_BINARIES=$(UNIT_TEST_SOURCES:$(UNIT_TEST_SRC_DIR)/%.c=$(OBJ_DIR)/unit_tests/%)

LEX_ARTIFACTS=lexer.generated.c
BISON_ARTIFACTS=parser.generated.c parser.generated.h
LEXER_OBJECT=$(OBJ_DIR)/lexer.generated.o
PARSER_OBJECT=$(OBJ_DIR)/parser.generated.o

ifeq ($(shell ldd /bin/echo | grep 'musl' | head -1 | cut -d ' ' -f1),)
# CFLAGS+= -DENABLE_LOGGING
CRYPT_LIBS=-lcrypt
else
CRYPT_LIBS=
endif

LDFLAGS=-g

# TODO: Only include objects into binaries they are required in

all: test-nc keygen chat chatpriv chatd test-parser

test: $(OBJECTS) $(UNIT_TEST_BINARIES)
	$(OBJ_DIR)/unit_tests/test_auth_command $(LDFLAGS)

$(UNIT_TEST_BINARIES): $(OBJ_DIR)/unit_tests/% : $(UNIT_TEST_SRC_DIR)/%.c output-directories
	$(CC) $< $(OBJECTS) -o $@ $(CFLAGS)

chat: $(OBJ_DIR)/chat.o $(OBJECTS) $(PARSER_OBJECT) $(LEXER_OBJECT)
	$(CC) $^ -o $@ -fwhole-program $(LDFLAGS)

chatpriv: $(OBJ_DIR)/chatpriv.o $(OBJECTS) $(PARSER_OBJECT) $(LEXER_OBJECT)
	$(CC) $^ -o $@ $(CRYPT_LIBS) -fwhole-program $(LDFLAGS)

chatd: $(OBJ_DIR)/chatd.o $(OBJECTS)
	$(CC) $^ -o $@ -fwhole-program $(LDFLAGS) $(PARSER_OBJECT) $(LEXER_OBJECT)

keygen: keygen.o $(OBJ_DIR)/tweetnacl.o
	$(CC) $^ -o $@ -Wall $(LDFLAGS)

test-nc: test-nc.c
	$(CC) $^ -o $@ -Wall $(LDFLAGS)

test-parser: test-parser.c $(PARSER_OBJECT) $(LEXER_OBJECT)
	$(CC) $^ -o $@ -Wall $(LDFLAGS)

$(OBJECTS): $(OBJ_DIR)/%.o : $(SRC_DIR)/%.c output-directories $(BISON_ARTIFACTS) $(LEX_ARTIFACTS)
	$(CC) -c $< -o $@ $(CFLAGS)

$(OBJ_DIR)/keygen.o: keygen.c output-directories
	$(CC) -c $< -o $@ $(CFLAGS)

$(OBJ_DIR)/chatd.o: chatd.c output-directories
	$(CC) -c $< -o $@ $(CFLAGS)

$(OBJ_DIR)/chat.o: chat.c output-directories
	$(CC) -c $< -o $@ $(CFLAGS)

$(OBJ_DIR)/chatpriv.o: chatpriv.c output-directories
	$(CC) -c $< -o $@ $(CFLAGS)

$(LEXER_OBJECT): $(LEX_ARTIFACTS) $(BISON_ARTIFACTS)
	$(CC) -c $< -o $@ $(CFLAGS)

$(PARSER_OBJECT): $(BISON_ARTIFACTS)
	$(CC) -c $< -o $@ $(CFLAGS)

$(LEX_ARTIFACTS): lexer.l
	$(LEX) -o lexer.generated.c lexer.l

$(BISON_ARTIFACTS): $(LEX_ARTIFACTS) parser.y parser-defs.h
	$(BISON) -d -o parser.generated.c parser.y

output-directories:
	mkdir -p obj
	mkdir -p obj/unit_tests

clean:
	rm -f test-nc chat chatpriv chatd test-parser keygen
	rm -f *.generated.c *.generated.h *.o
	rm -rf obj

