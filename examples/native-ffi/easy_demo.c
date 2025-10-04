#include "pqq.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>

static const char *SERVER_CFG = "{\
  \"bind\":\"127.0.0.1:0\",\
  \"profile\":\"balanced\",\
  \"static_text\":\"Hello Velocity!\"\
}";

int main(void) {
    pqq_init();

    PqqOwnedSlice server_response = {0};
    if (pqq_easy_start_server(SERVER_CFG, &server_response) != 0) {
        fprintf(stderr, "Failed to start Velocity easy server\n");
        return 1;
    }

    printf("Server info: %s\n", (const char *)server_response.data);

    unsigned port = 0;
    char kem_b64[512] = {0};
    if (sscanf((const char *)server_response.data,
               "{\"status\":%*[^,],\"port\":%u,%*[^\"]\"kem_public_base64\":\"%511[^\"]",
               &port,
               kem_b64) != 2) {
        fprintf(stderr, "Failed to parse server response\n");
        pqq_owned_slice_release(&server_response);
        return 1;
    }

    char client_cfg[1024];
    snprintf(client_cfg,
             sizeof(client_cfg),
             "{\
  \"server_addr\":\"127.0.0.1:%u\",\
  \"hostname\":\"localhost\",\
  \"server_key_base64\":\"%s\",\
  \"path\":\"/\"\
}",
             port,
             kem_b64);

    PqqOwnedSlice client_response = {0};
    if (pqq_easy_request(client_cfg, &client_response) != 0) {
    fprintf(stderr, "Request failed\n");
        pqq_owned_slice_release(&server_response);
        return 1;
    }

    printf("Client response: %s\n", (const char *)client_response.data);

    pqq_owned_slice_release(&client_response);
    pqq_owned_slice_release(&server_response);
  pqq_stop_server((uint16_t)port);
    return 0;
}
