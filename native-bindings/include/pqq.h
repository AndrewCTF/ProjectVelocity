#ifndef PQQ_H
#define PQQ_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** \file pqq.h
 *  @brief C bindings for the Velocity (PQ-QUIC) reference implementation.
 */

typedef void (*PqqReleaseCallback)(const uint8_t *ptr, size_t len, void *ctx);

typedef struct PqqOwnedSlice {
    const uint8_t *data;
    size_t len;
    PqqReleaseCallback release;
    void *release_ctx;
} PqqOwnedSlice;

typedef int32_t (*PqqHandlerCallback)(const uint8_t *request_ptr,
                                       size_t request_len,
                                       const char *handshake_json,
                                       PqqOwnedSlice *out_response,
                                       void *user_data);

void pqq_init(void);

int32_t pqq_start_server(const char *config_json);
int32_t pqq_set_handler(uint16_t port, PqqHandlerCallback callback, void *user_data);
int32_t pqq_clear_handler(uint16_t port);
int32_t pqq_stop_server(uint16_t port);

int32_t pqq_request(const char *method,
                    const char *url,
                    const char *body,
                    const char **out_response);

void pqq_string_free(const char *ptr);

int32_t pqq_easy_start_server(const char *config_json, PqqOwnedSlice *out_response);
int32_t pqq_easy_request(const char *config_json, PqqOwnedSlice *out_response);
void pqq_owned_slice_release(PqqOwnedSlice *slice);

#ifdef __cplusplus
}
#endif

#endif /* PQQ_H */
