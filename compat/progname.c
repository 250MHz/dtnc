// SPDX-FileCopyrightText: 2026 250MHz
//
// SPDX-License-Identifier: BSD-2-Clause

#include "compat.h"

#include <string.h>

static const char *progname = "unknown";

// Modified from FreeBSD's libc
void dtnc_setprogname(const char *name) {
#ifdef HAVE___PROGNAME
    (void)name;
    extern char *__progname;
    progname = __progname;
#else
    // SPDX-SnippetBegin
    // SPDX-License-Identifier: BSD-2-Clause
    // SPDX-SnippetCopyrightText: 1992-2026 The FreeBSD Project
    // SPDX-SnippetName: From lib/libc/gen/setprogname.c
    const char *p;

    if (name == NULL) {
        return;
    }

    p = strrchr(name, '/');
    if (p != NULL) {
        progname = p + 1;
    } else {
        progname = name;
    }
    // SPDX-SnippetEnd
#endif
}

const char *dtnc_getprogname(void) {
    return progname;
}
