
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "auth_command.h"

const char *PROGRAM_NAME = "test_auth_command";

int main(){
    {
        auth_command_t command = parse_auth_command("auth");
        assert(!is_auth_command_valid(&command));
    }

    {
        auth_command_t command = parse_auth_command("auth ");
        assert(!is_auth_command_valid(&command));
    }

    {
        auth_command_t command = parse_auth_command("auth username");
        assert(!is_auth_command_valid(&command));
    }

    {
        auth_command_t command = parse_auth_command("auth user&name password");
        assert(!is_auth_command_valid(&command));
    }

    {
        auth_command_t command = parse_auth_command("auth 543user&name password");
        assert(!is_auth_command_valid(&command));
    }
    
    {
        auth_command_t command = parse_auth_command("auth username password");
        assert(is_auth_command_valid(&command));
        assert(strcmp(command.username, "username") == 0);
        assert(strcmp(command.password, "password") == 0);
    }

    {
        auth_command_t command = parse_auth_command("auth usernameusernameusernameusername password");
        assert(is_auth_command_valid(&command));
        assert(strcmp(command.username, "usernameusernameusernameusername") == 0);
        assert(strcmp(command.password, "password") == 0);
    }

    {
        auth_command_t command = parse_auth_command("auth usernameusernameusernameusername passwordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswor");
        assert(is_auth_command_valid(&command));
        assert(strcmp(command.username, "usernameusernameusernameusername") == 0);
        assert(strcmp(command.password, "passwordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswor") == 0);
    }

    {
        auth_command_t command = parse_auth_command("auth usernameusernameusernameusername passwordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpassword");
        assert(!is_auth_command_valid(&command));
    }

    printf("[PASSED] %s\n", __FILE__);
    return 0;
}

