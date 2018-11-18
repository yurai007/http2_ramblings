#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <ngtcp2/ngtcp2.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <cassert>
#include <tuple>
#include <random>

#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wunused-function"

namespace minimal_client {

enum class ops {initial, recv_crypto_data, handshake_completed, do_hs_encrypt, do_hs_decrypt, do_encrypt, do_decrypt, do_hs_encrypt_pn,
               do_encrypt_pn, recv_stream_data, acked_crypto_offset, acked_stream_data_offset, stream_close, recv_retry, extend_max_stream_id};

struct ngtcp2_internal_data {
    ngtcp2_conn *conn;
    uint64_t offset;
    const uint8_t *data;
    size_t datalen;
    uint8_t *dest;
    size_t destlen;
    const uint8_t *plaintext;
    size_t plaintextlen;
    const uint8_t *ciphertext;
    size_t ciphertextlen;
    const uint8_t *key;
    size_t keylen;
    const uint8_t *nonce;
    size_t noncelen;
    const uint8_t *ad;
    size_t adlen;
    void *user_data;
};

class quic_session {
private:
    int tls_handshake(bool initial) {
        return 0;
    }

    template<ops operation>
    static auto consume(ngtcp2_internal_data && data) {
        if constexpr (operation == ops::initial) {
            auto session = static_cast<quic_session*>(data.user_data);
            if (session->tls_handshake(true) != 0) {
                return static_cast<int>(NGTCP2_ERR_CALLBACK_FAILURE);
            }
        } else if constexpr (operation == ops::recv_crypto_data) {

        } else if constexpr (operation == ops::handshake_completed) {

        } else if constexpr (operation == ops::do_hs_encrypt) {

        }
        return 0;
    }

    static ssize_t do_hs_decrypt(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
                          const uint8_t *ciphertext, size_t ciphertextlen,
                          const uint8_t *key, size_t keylen, const uint8_t *nonce,
                          size_t noncelen, const uint8_t *ad, size_t adlen,
                          void *user_data) {
        return 0;
    }

    static ssize_t do_encrypt(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
                       const uint8_t *plaintext, size_t plaintextlen,
                       const uint8_t *key, size_t keylen, const uint8_t *nonce,
                       size_t noncelen, const uint8_t *ad, size_t adlen,
                       void *user_data) {
        return 0;
    }

    static ssize_t do_decrypt(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
                       const uint8_t *ciphertext, size_t ciphertextlen,
                       const uint8_t *key, size_t keylen, const uint8_t *nonce,
                       size_t noncelen, const uint8_t *ad, size_t adlen,
                       void *user_data) {
        return 0;
    }

    static ssize_t do_hs_encrypt_pn(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
                             const uint8_t *plaintext, size_t plaintextlen,
                             const uint8_t *key, size_t keylen,
                             const uint8_t *nonce, size_t noncelen,
                             void *user_data) {
        return 0;
    }

    static ssize_t do_encrypt_pn(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
                          const uint8_t *plaintext, size_t plaintextlen,
                          const uint8_t *key, size_t keylen, const uint8_t *nonce,
                          size_t noncelen, void *user_data) {
        return 0;
    }

    static int recv_stream_data(ngtcp2_conn *conn, uint64_t stream_id, uint8_t fin,
                         uint64_t offset, const uint8_t *data, size_t datalen,
                         void *user_data, void *stream_user_data) {
        return 0;
    }

    static int acked_crypto_offset(ngtcp2_conn *conn, uint64_t offset, size_t datalen, void *user_data) {
        return 0;
    }

    static int acked_stream_data_offset(ngtcp2_conn *conn, uint64_t stream_id,
                                 uint64_t offset, size_t datalen, void *user_data,
                                 void *stream_user_data) {
        return 0;
    }

    static int stream_close(ngtcp2_conn *conn, uint64_t stream_id, uint16_t app_error_code,
                     void *user_data, void *stream_user_data) {
        return 0;
    }

    static int recv_retry(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd, const ngtcp2_pkt_retry *retry, void *user_data) {
        return 0;
    }

    static int extend_max_stream_id(ngtcp2_conn *conn, uint64_t max_stream_id, void *user_data) {
        return 0;
    }

    ngtcp2_conn *quic_connection = nullptr;
    constexpr static auto max_pktlen = NGTCP2_MAX_PKTLEN_IPV4;

public:
    void run() {
        auto callbacks = ngtcp2_conn_callbacks{
                [](auto conn, auto user_data){
                    ngtcp2_internal_data blob {};
                    blob.conn = conn;
                    blob.user_data = user_data;
                    return consume<ops::initial>(std::move(blob));
                },
            nullptr,
                [](auto conn, auto offset, auto data, auto datalen, auto user_data) {
                    ngtcp2_internal_data blob {};
                    blob.conn = conn;
                    blob.offset = offset;
                    blob.data = data;
                    blob.datalen = datalen;
                    blob.user_data = user_data;
                    return consume<ops::recv_crypto_data>(std::move(blob));
                },
                [](auto conn, auto user_data){
                    ngtcp2_internal_data blob {};
                    blob.conn = conn;
                    blob.user_data = user_data;
                    return consume<ops::handshake_completed>(std::move(blob));
                },
            nullptr,
                [](auto conn, auto dest, auto destlen, auto plaintext, auto plaintextlen,
                   auto key, auto keylen, auto nonce, auto noncelen, auto ad, auto adlen, auto user_data) {
                    ngtcp2_internal_data blob {};
                    blob.conn = conn;
                    blob.dest = dest;
                    blob.destlen = destlen;
                    blob.plaintext = plaintext;
                    blob.plaintextlen = plaintextlen;
                    blob.key = key;
                    blob.keylen = keylen;
                    blob.nonce = nonce;
                    blob.noncelen = noncelen;
                    blob.ad = ad;
                    blob.adlen = adlen;
                    blob.user_data = user_data;
                    return static_cast<ssize_t>(consume<ops::do_hs_encrypt>(std::move(blob)));
                },
            do_hs_decrypt,        do_encrypt,
            do_decrypt,       do_hs_encrypt_pn,     do_encrypt_pn,
            recv_stream_data, acked_crypto_offset,  acked_stream_data_offset,
            stream_close,
            nullptr,
            recv_retry, extend_max_stream_id,
        };

        auto randgen = []() {
            std::random_device rd;
            return std::mt19937(rd());
        };
        auto dis = std::uniform_int_distribution<uint8_t>(0, std::numeric_limits<uint8_t>::max());

        ngtcp2_cid scid;
        scid.datalen = NGTCP2_MAX_CIDLEN-1;
        std::generate(std::begin(scid.data), std::begin(scid.data) + scid.datalen, [&dis, &randgen]() { return dis(randgen); });
        ngtcp2_cid dcid;
        dcid.datalen = NGTCP2_MAX_CIDLEN;
        std::generate(std::begin(dcid.data), std::begin(dcid.data) + dcid.datalen, [&dis, &randgen]() { return dis(randgen); });

        ngtcp2_settings settings{};
        settings.log_printf = nullptr;
        //settings.initial_ts =
        settings.max_stream_data_bidi_local = 256*1024;
        settings.max_stream_data_bidi_remote = 256*1024;
        settings.max_stream_data_uni = 256*1024;
        settings.max_data = 1*1024*1024;
        settings.max_bidi_streams = 1;
        settings.max_uni_streams = 1;
        //settings.idle_timeout =
        settings.max_packet_size = NGTCP2_MAX_PKT_SIZE;
        settings.ack_delay_exponent = NGTCP2_DEFAULT_ACK_DELAY_EXPONENT;

        auto version = 0u;
        auto rv = ngtcp2_conn_client_new(&quic_connection, &dcid, &scid, version, &callbacks, &settings, this);
        assert(rv == 0);
    }
};

static auto run_ssl_client() {
    using ssl_socket = boost::asio::ssl::stream<boost::asio::ip::tcp::socket>;
    boost::asio::io_service io_service;
    boost::asio::ssl::context context {boost::asio::ssl::context::sslv23};
    ssl_socket socket{io_service, context};
}

static auto run() {
    quic_session{}.run();
}

}

int main() {
    minimal_client::run();
    return 0;
}
