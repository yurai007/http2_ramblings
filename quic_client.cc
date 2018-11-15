#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <ngtcp2/ngtcp2.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <cassert>

#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wunused-function"

namespace minimal_client {

static ngtcp2_conn *quic_connection = nullptr;
constexpr auto max_pktlen = NGTCP2_MAX_PKTLEN_IPV4;

int tls_handshake(bool initial) {
    return 0;
}

int client_initial(ngtcp2_conn *conn, void *user_data) {
    if (tls_handshake(true) != 0) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
}

int recv_crypto_data(ngtcp2_conn *conn, uint64_t offset, const uint8_t *data,
                     size_t datalen, void *user_data) {
    return 0;
}

int handshake_completed(ngtcp2_conn *conn, void *user_data) {
    return 0;
}

ssize_t do_hs_encrypt(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
                      const uint8_t *plaintext, size_t plaintextlen,
                      const uint8_t *key, size_t keylen, const uint8_t *nonce,
                      size_t noncelen, const uint8_t *ad, size_t adlen,
                      void *user_data) {
    return 0;
}

ssize_t do_hs_decrypt(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
                      const uint8_t *ciphertext, size_t ciphertextlen,
                      const uint8_t *key, size_t keylen, const uint8_t *nonce,
                      size_t noncelen, const uint8_t *ad, size_t adlen,
                      void *user_data) {
    return 0;
}

ssize_t do_encrypt(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
                   const uint8_t *plaintext, size_t plaintextlen,
                   const uint8_t *key, size_t keylen, const uint8_t *nonce,
                   size_t noncelen, const uint8_t *ad, size_t adlen,
                   void *user_data) {
    return 0;
}

ssize_t do_decrypt(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
                   const uint8_t *ciphertext, size_t ciphertextlen,
                   const uint8_t *key, size_t keylen, const uint8_t *nonce,
                   size_t noncelen, const uint8_t *ad, size_t adlen,
                   void *user_data) {
    return 0;
}

ssize_t do_hs_encrypt_pn(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
                         const uint8_t *plaintext, size_t plaintextlen,
                         const uint8_t *key, size_t keylen,
                         const uint8_t *nonce, size_t noncelen,
                         void *user_data) {
    return 0;
}

ssize_t do_encrypt_pn(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
                      const uint8_t *plaintext, size_t plaintextlen,
                      const uint8_t *key, size_t keylen, const uint8_t *nonce,
                      size_t noncelen, void *user_data) {
    return 0;
}

int recv_stream_data(ngtcp2_conn *conn, uint64_t stream_id, uint8_t fin,
                     uint64_t offset, const uint8_t *data, size_t datalen,
                     void *user_data, void *stream_user_data) {
    return 0;
}

int acked_crypto_offset(ngtcp2_conn *conn, uint64_t offset, size_t datalen, void *user_data) {
    return 0;
}

int acked_stream_data_offset(ngtcp2_conn *conn, uint64_t stream_id,
                             uint64_t offset, size_t datalen, void *user_data,
                             void *stream_user_data) {
    return 0;
}

int stream_close(ngtcp2_conn *conn, uint64_t stream_id, uint16_t app_error_code,
                 void *user_data, void *stream_user_data) {
    return 0;
}

int recv_retry(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd, const ngtcp2_pkt_retry *retry, void *user_data) {
    return 0;
}

int extend_max_stream_id(ngtcp2_conn *conn, uint64_t max_stream_id, void *user_data) {
    return 0;
}

static auto run_quic() {
    auto callbacks = ngtcp2_conn_callbacks{
        client_initial,
        nullptr,
        recv_crypto_data, handshake_completed,
        nullptr,
        do_hs_encrypt,    do_hs_decrypt,        do_encrypt,
        do_decrypt,       do_hs_encrypt_pn,     do_encrypt_pn,
        recv_stream_data, acked_crypto_offset,  acked_stream_data_offset,
        stream_close,
        nullptr,
        recv_retry, extend_max_stream_id,
    };

    ngtcp2_settings settings{};
    ngtcp2_cid scid{}, dcid{};
    auto version = 0u;
    auto rv = ngtcp2_conn_client_new(&quic_connection, &dcid, &scid, version, &callbacks, &settings, nullptr);
    assert(rv == 0);
}

static auto run_ssl_client() {
    using ssl_socket = boost::asio::ssl::stream<boost::asio::ip::tcp::socket>;
    boost::asio::io_service io_service;
    boost::asio::ssl::context context {boost::asio::ssl::context::sslv23};
    ssl_socket socket{io_service, context};
}

static auto run() {
    run_quic();
}

}

int main() {
    minimal_client::run();
    return 0;
}
