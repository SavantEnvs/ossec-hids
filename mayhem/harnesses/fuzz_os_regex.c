/* libFuzzer harness for OSSEC's os_regex: OSRegex / OSMatch / OSRegex_Convert.
 * Input layout: byte 0 selects flags, the rest is "<pattern>\n<subject>". */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "os_regex.h"

/* Patterns come from trusted rule files, and OSRegex compiles them with PCRE2_NO_UTF_CHECK, so a
 * pattern that is not valid UTF-8 is invalid input. Subjects (log lines) stay arbitrary bytes. */
static int valid_utf8(const unsigned char *s)
{
    while (*s) {
        unsigned int cp;
        int extra;

        if (s[0] < 0x80) {
            cp = s[0]; extra = 0;
        } else if (s[0] >= 0xC2 && s[0] <= 0xDF) {
            cp = s[0] & 0x1F; extra = 1;
        } else if (s[0] >= 0xE0 && s[0] <= 0xEF) {
            cp = s[0] & 0x0F; extra = 2;
        } else if (s[0] >= 0xF0 && s[0] <= 0xF4) {
            cp = s[0] & 0x07; extra = 3;
        } else {
            return 0;
        }
        for (int i = 1; i <= extra; i++) {
            if ((s[i] & 0xC0) != 0x80) {
                return 0;
            }
            cp = (cp << 6) | (s[i] & 0x3F);
        }
        if ((extra == 2 && cp < 0x800) || (extra == 3 && (cp < 0x10000 || cp > 0x10FFFF)) ||
            (cp >= 0xD800 && cp <= 0xDFFF)) {
            return 0;
        }
        s += extra + 1;
    }
    return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *buf;
    char *pattern;
    char *subject;
    char *nl;
    int flags;

    if (size < 2) {
        return -1;
    }

    buf = (char *)malloc(size);
    if (buf == NULL) {
        return -1;
    }
    memcpy(buf, data + 1, size - 1);
    buf[size - 1] = '\0';

    /* An empty pattern is invalid input; OSRegex_Compile reads pattern[-1] for it. */
    if (buf[0] == '\0' || buf[0] == '\n') {
        free(buf);
        return -1;
    }

    flags = (data[0] & 1) ? OS_CASE_SENSITIVE : 0;

    pattern = buf;
    nl = strchr(buf, '\n');
    if (nl != NULL) {
        *nl = '\0';
        subject = nl + 1;
    } else {
        subject = (char *)"";
    }

    if (!valid_utf8((const unsigned char *)pattern)) {
        free(buf);
        return -1;
    }

    if (data[0] & 2) {
        OSRegex reg;
        memset(&reg, 0, sizeof(reg));
        if (OSRegex_Compile(pattern, &reg, flags | ((data[0] & 4) ? OS_RETURN_SUBSTRING : 0))) {
            OSRegex_Execute(subject, &reg);
            OSRegex_FreePattern(&reg);
        }
    } else if (data[0] & 8) {
        OSMatch reg;
        memset(&reg, 0, sizeof(reg));
        if (OSMatch_Compile(pattern, &reg, flags)) {
            OSMatch_Execute(subject, strlen(subject), &reg);
            OSMatch_FreePattern(&reg);
        }
    } else if (data[0] & 16) {
        char *converted = NULL;
        if (OSRegex_Convert(pattern, &converted, (data[0] & 32) ? OS_CONVERT_MATCH : OS_CONVERT_REGEX)) {
            free(converted);
        }
    } else {
        OS_Regex(pattern, subject);
        OS_Match2(pattern, subject);
        OS_WordMatch(pattern, subject);
    }

    free(buf);
    return 0;
}
