
#include "quic_common.hh"
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <ngtcp2/ngtcp2.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <cassert>
#include <tuple>
#include <random>
#include <iostream>

#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wunused-function"

namespace minimal_client {

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

        } else if constexpr (operation == ops::do_hs_decrypt) {

        } else if constexpr (operation == ops::do_encrypt) {

        } else if constexpr (operation == ops::do_decrypt) {

        } else if constexpr (operation == ops::do_hs_encrypt_pn) {

        } else if constexpr (operation == ops::do_encrypt_pn) {

        } else if constexpr (operation == ops::recv_stream_data) {

        } else if constexpr (operation == ops::acked_crypto_offset) {

        } else if constexpr (operation == ops::acked_stream_data_offset) {

        } else if constexpr (operation == ops::stream_close) {

        } else if constexpr (operation == ops::recv_retry) {

        } else if constexpr (operation == ops::extend_max_stream_id) {

        }
        return 0;
    }

    ngtcp2_conn *quic_connection = nullptr;
    constexpr static auto max_pktlen = NGTCP2_MAX_PKTLEN_IPV4;

public:
    void run() {
        auto callbacks = ngtcp2_conn_callbacks{
                [](auto conn, auto user_data){
                    ngtcp2_internal_data blob { .conn = conn, .user_data = user_data};
                    return consume<ops::initial>(std::move(blob));
                },
            nullptr,
                [](auto conn, auto offset, auto data, auto datalen, auto user_data) {
                    ngtcp2_internal_data blob { .conn = conn, .offset = offset, .data = data, .datalen = datalen, .user_data = user_data};
                    return consume<ops::recv_crypto_data>(std::move(blob));
                },
                [](auto conn, auto user_data){
                    ngtcp2_internal_data blob { .conn = conn, .user_data = user_data};
                    return consume<ops::handshake_completed>(std::move(blob));
                },
            nullptr,
                [](auto conn, auto dest, auto destlen, auto plaintext, auto plaintextlen,
                   auto key, auto keylen, auto nonce, auto noncelen, auto ad, auto adlen, auto user_data) {
                    ngtcp2_internal_data blob { .conn = conn, .dest = dest, .destlen = destlen, .plaintext = plaintext,
                        .plaintextlen = plaintextlen, .key = key, .keylen = keylen, .nonce = nonce, .noncelen = noncelen, .ad = ad,
                        .adlen = adlen, .user_data = user_data};
                    return static_cast<ssize_t>(consume<ops::do_hs_encrypt>(std::move(blob)));
                },
                [](auto conn, auto dest, auto destlen, auto ciphertext, auto ciphertextlen,
                   auto key, auto keylen, auto nonce, auto noncelen, auto ad, auto adlen, auto user_data) {
                    ngtcp2_internal_data blob { .conn = conn, .dest = dest, .destlen = destlen, .ciphertext = ciphertext,
                        .ciphertextlen = ciphertextlen, .key = key, .keylen = keylen, .nonce = nonce, .noncelen = noncelen, .ad = ad,
                        .adlen = adlen, .user_data = user_data};
                    return static_cast<ssize_t>(consume<ops::do_hs_decrypt>(std::move(blob)));
                },
                [](auto conn, auto dest, auto destlen, auto plaintext, auto plaintextlen,
                   auto key, auto keylen, auto nonce, auto noncelen, auto ad, auto adlen, auto user_data) {
                    ngtcp2_internal_data blob { .conn = conn, .dest = dest, .destlen = destlen, .plaintext = plaintext,
                        .plaintextlen = plaintextlen, .key = key, .keylen = keylen, .nonce = nonce, .noncelen = noncelen, .ad = ad,
                        .adlen = adlen, .user_data = user_data};
                    return static_cast<ssize_t>(consume<ops::do_encrypt>(std::move(blob)));
                },
                [](auto conn, auto dest, auto destlen, auto ciphertext, auto ciphertextlen,
                   auto key, auto keylen, auto nonce, auto noncelen, auto ad, auto adlen, auto user_data) {
                    ngtcp2_internal_data blob { .conn = conn, .dest = dest, .destlen = destlen, .ciphertext = ciphertext,
                        .ciphertextlen = ciphertextlen, .key = key, .keylen = keylen, .nonce = nonce, .noncelen = noncelen, .ad = ad,
                        .adlen = adlen, .user_data = user_data};
                    return static_cast<ssize_t>(consume<ops::do_decrypt>(std::move(blob)));
                },
                [](auto conn, auto dest, auto destlen, auto plaintext, auto plaintextlen,
                   auto key, auto keylen, auto nonce, auto noncelen, auto user_data) {
                    ngtcp2_internal_data blob { .conn = conn, .dest = dest, .destlen = destlen, .plaintext = plaintext,
                        .plaintextlen = plaintextlen, .key = key, .keylen = keylen, .nonce = nonce, .noncelen = noncelen, .user_data = user_data};
                    return static_cast<ssize_t>(consume<ops::do_hs_encrypt_pn>(std::move(blob)));
                },
                [](auto conn, auto dest, auto destlen, auto plaintext, auto plaintextlen,
                   auto key, auto keylen, auto nonce, auto noncelen, auto user_data) {
                    ngtcp2_internal_data blob { .conn = conn, .dest = dest, .destlen = destlen, .plaintext = plaintext,
                        .plaintextlen = plaintextlen, .key = key, .keylen = keylen, .nonce = nonce, .noncelen = noncelen, .user_data = user_data};
                    return static_cast<ssize_t>(consume<ops::do_encrypt_pn>(std::move(blob)));
                },
                [](auto conn, auto stream_id, auto fin, auto offset, auto data, auto datalen, auto user_data, auto stream_user_data) {
                    ngtcp2_internal_data blob { .conn = conn, .stream_id = stream_id, .fin = fin, .offset = offset, .data = data, .datalen = datalen,
                        .user_data = user_data, .stream_user_data = stream_user_data};
                    return consume<ops::recv_stream_data>(std::move(blob));
                },
                [](auto conn, auto offset, auto datalen, auto user_data) {
                    ngtcp2_internal_data blob { .conn = conn, .offset = offset, .datalen = datalen, .user_data = user_data};
                    return consume<ops::acked_crypto_offset>(std::move(blob));
                },
                [](auto conn, auto stream_id, auto offset, auto datalen, auto user_data, auto stream_user_data) {
                    ngtcp2_internal_data blob { .conn = conn, .stream_id = stream_id, .offset = offset, .datalen = datalen,
                                .user_data = user_data, .stream_user_data = stream_user_data};
                    return consume<ops::acked_stream_data_offset>(std::move(blob));
                },
                [](auto conn, auto stream_id, auto app_error_code, auto user_data, auto stream_user_data) {
                    ngtcp2_internal_data blob { .conn = conn, .stream_id = stream_id, .app_error_code = app_error_code,
                                .user_data = user_data, .stream_user_data = stream_user_data};
                    return consume<ops::stream_close>(std::move(blob));
                },
            nullptr,
                [](auto conn, auto hd, auto retry, auto user_data) {
                    ngtcp2_internal_data blob { .conn = conn, .hd = hd, .retry = retry, .user_data = user_data};
                    return consume<ops::recv_retry>(std::move(blob));
                },
                [](auto conn, auto max_stream_id, auto user_data) {
                    ngtcp2_internal_data blob { .conn = conn, .max_stream_id = max_stream_id, .user_data = user_data};
                    return consume<ops::extend_max_stream_id>(std::move(blob));
                }
        };

        std::random_device rd;
        std::mt19937 randgen{rd()};
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
        settings.max_stream_data_bidi_local = 256_k;
        settings.max_stream_data_bidi_remote = 256_k;
        settings.max_stream_data_uni = 256_k;
        settings.max_data = 1_m;
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
    try {
        using ssl_socket = boost::asio::ssl::stream<boost::asio::ip::tcp::socket>;
        boost::asio::io_service io_service;
        boost::asio::ip::tcp::resolver resolver {io_service};
        boost::system::error_code error = boost::asio::error::host_not_found;
        auto iterator = resolver.resolve(boost::asio::ip::tcp::resolver::query("127.0.0.1", "5555",
                                                boost::asio::ip::tcp::resolver::query::canonical_name));

        boost::asio::ssl::context context {boost::asio::ssl::context::sslv23};
        context.load_verify_file("server.crt");
        ssl_socket socket{io_service, context};
        boost::asio::connect(socket.lowest_layer(), iterator, error);
        assert(!error);
        std::cout << "connected on TLS\n";

        socket.set_verify_mode(boost::asio::ssl::verify_peer);
        socket.set_verify_callback([](auto preverified, auto &ctx){
            std::array<char, 256> subject_name;
            auto cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
            X509_NAME_oneline(X509_get_subject_name(cert), subject_name.data(), subject_name.size());
            std::cout << "Verifying " << subject_name.data() << "\n";
            return preverified;
        });
    }
    catch (std::exception& e) {
        std::cout << "Exception: " << e.what() << "\n";
    }
}

static auto run() {
    quic_session{}.run();
}

}

int main() {
    minimal_client::run();
    minimal_client::run_ssl_client();
    return 0;
}
