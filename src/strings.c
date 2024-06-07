
#include <string.h>

#include "strings.h"

const char *string_starts_with(const char *string, const char *prefix){
    // Returns rest of string if match, otherwise NULL
    size_t prefix_length = strlen(prefix);

    if(strlen(string) >= prefix_length && strncmp(string, prefix, prefix_length) == 0){
        return &string[prefix_length];
    } else {
        return NULL;
    }
}

bool string_equals(const char *string, const char *other){
    return strcmp(string, other) == 0;
}

