#ifndef TF_JSMN_RECORD_H
#define TF_JSMN_RECORD_H

#define JSMN_STRICT
#include "jsmn.h"

typedef unsigned int tf_u32;
typedef int tf_i32;
#define TF_INPUT_PATH "/etc/dta-input"
#define TF_MAX_INPUT 4096U
#define TF_TOKEN_CAPACITY 32U
#define TF_RECORD_BYTES 544U

typedef struct {
    tf_u32 magic;
    tf_u32 version;
    tf_u32 input_size;
    tf_i32 result;
    tf_u32 parser_pos;
    tf_u32 token_count;
    tf_i32 token_super;
    tf_u32 token_capacity;
    jsmntok_t tokens[TF_TOKEN_CAPACITY];
} TfRecord;

_Static_assert(sizeof(tf_u32) == 4, "32-bit record fields required");
_Static_assert(sizeof(jsmntok_t) == 16, "Unmodified no-parent token layout required");
_Static_assert(sizeof(TfRecord) == TF_RECORD_BYTES, "Exact binary record layout required");

static void tf_parse_record(const char *data, tf_u32 size, TfRecord *record) {
    jsmn_parser parser;
    jsmn_init(&parser);
    record->result = jsmn_parse(&parser, data, size, record->tokens, TF_TOKEN_CAPACITY);
    record->magic = 0x314d534aU;
    record->version = 1;
    record->input_size = size;
    record->parser_pos = parser.pos;
    record->token_count = parser.toknext;
    record->token_super = parser.toksuper;
    record->token_capacity = TF_TOKEN_CAPACITY;
}
#endif
