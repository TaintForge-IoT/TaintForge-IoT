/* Same source, separate native build; differential oracle, not independent semantics. */
#include "record.h"
#include <string.h>

int tf_jsmn_oracle(const char *data, unsigned int size, unsigned char *output) {
    if (size > TF_MAX_INPUT) return -1;
    TfRecord record;
    memset(&record, 0, sizeof(record));
    tf_parse_record(data, size, &record);
    memcpy(output, &record, sizeof(record));
    return 0;
}
