
#ifndef ISAAC_LOGF_INCLUDED
#define ISAAC_LOGF_INCLUDED

#include <stdio.h>

#ifdef ENABLE_LOGGING
    #pragma GCC diagnostic ignored "-Wformat-zero-length"

    #define logf(...) do { \
        fprintf(stderr, "[%s] ", PROGRAM_NAME); \
        fprintf(stderr, __VA_ARGS__); \
    } while(0);
#else
    #define logf(...)
#endif

extern const char *PROGRAM_NAME; // Defined per-program

#endif // ISAAC_LOGF_INCLUDED
