#pragma once

#include <ngtcp2/ngtcp2.h>

enum class ops {initial, recv_client_initial, recv_crypto_data, handshake_completed, do_hs_encrypt, do_hs_decrypt, do_encrypt, do_decrypt, do_hs_encrypt_pn,
               do_encrypt_pn, recv_stream_data, acked_crypto_offset, acked_stream_data_offset, stream_close, recv_retry, extend_max_stream_id, rand};

struct ngtcp2_internal_data {
    ngtcp2_conn *conn = nullptr;
    const ngtcp2_cid *dcid = nullptr;
    uint64_t stream_id = 0u;
    const ngtcp2_pkt_hd *hd = nullptr;
    uint16_t app_error_code = 0u;
    uint8_t fin = 0u;
    uint64_t offset = 0u;
    const ngtcp2_pkt_retry *retry = nullptr;
    const uint8_t *data = nullptr;
    size_t datalen = 0u;
    uint8_t *dest = nullptr;
    size_t destlen = 0u;
    const uint8_t *plaintext = nullptr;
    size_t plaintextlen = 0u;
    const uint8_t *ciphertext = nullptr;
    size_t ciphertextlen = 0;
    const uint8_t *key = nullptr;
    size_t keylen = 0u;
    const uint8_t *nonce = nullptr;
    size_t noncelen = 0u;
    const uint8_t *ad = nullptr;
    size_t adlen = 0u;
    uint64_t max_stream_id = 0u;
    void *user_data = nullptr;
    void *stream_user_data = nullptr;
};

constexpr auto operator"" _k(unsigned long long k) {
  return k * 1024ULL;
}

constexpr auto operator"" _m(unsigned long long m) {
  return m * 1024ULL * 1024ULL;
}
