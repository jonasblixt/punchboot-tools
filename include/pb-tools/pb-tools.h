#ifndef PB_TOOLS_PB_TOOLS_H
#define PB_TOOLS_PB_TOOLS_H

#define STR_INDIR(s)           #s
#define STR(s)                 STR_INDIR(s)
#define PB_TOOLS_VERSION_MAJOR 1
#define PB_TOOLS_VERSION_MINOR 1
#define PB_TOOLS_VERSION_PATCH 0
#define PB_TOOLS_VERSION_STRING \
    STR(PB_TOOLS_VERSION_MAJOR) "." STR(PB_TOOLS_VERSION_MINOR) "." STR(PB_TOOLS_VERSION_PATCH)

#define PB_EXPORT __attribute__((visibility("default")))

const char *pb_api_version(void);

#endif
