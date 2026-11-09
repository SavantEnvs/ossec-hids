/*
 * libFuzzer harness for GetAlertData (src/shared/read-alert.c), the parser behind
 * ossec-maild, ossec-csyslogd, ossec-agentlessd and ossec-execd for the text alerts.log.
 * The input is the content of an alerts.log; GetAlertData reads it from a FILE stream.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "shared.h"
#include "read-alert.h"

const char *__local_name = "fuzz_read_alert";

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FILE *fp;
    alert_data *al;

    if (size == 0) {
        return -1;
    }

    /* fmemopen() takes a non-const buffer but only reads it in "r" mode. */
    fp = fmemopen((void *)data, size, "r");
    if (!fp) {
        return 0;
    }

    while ((al = GetAlertData(0, fp)) != NULL) {
        FreeAlertData(al);
    }

    fclose(fp);
    return 0;
}
