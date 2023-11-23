#include "common.h"
#include <pb-tools/error.h>
#include <stdarg.h>
#include <stdio.h>

int pb_test_debug(struct pb_context *ctx, int level, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    return PB_RESULT_OK;
}
