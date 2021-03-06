﻿#include "quic_common.hh"
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <ngtcp2/ngtcp2.h>
#include <exception>
#include <iostream>
#include <string>
#include <array>
#include <tuple>
#include <random>

namespace minimal_server {

class ssl_server {
public:
    ssl_server(unsigned short port)
        : acceptor_(io_service_,
                    boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)),
          context_(boost::asio::ssl::context::sslv23) {
        context_.set_options(
                    boost::asio::ssl::context::default_workarounds
                    | boost::asio::ssl::context::no_sslv2
                    | boost::asio::ssl::context::single_dh_use);
        context_.set_password_callback([](auto, auto){ return "test"; });
        context_.use_certificate_chain_file("server.crt");
        context_.use_private_key_file("server.key", boost::asio::ssl::context::pem);
        context_.use_tmp_dh_file("dh1024.pem");

        start_accept();
    }

    std::future<void> start_accept() {
        sessions_.emplace_back(std::make_shared<quic_session>(io_service_, context_));
        co_await coroutines::async_accept(acceptor_, sessions_.back()->socket());
        sessions_.back()->start();
        start_accept();
    }

    void run() {
        io_service_.run();
    }

private:
    class quic_session {
        template<ops operation>
        static auto consume(ngtcp2_internal_data && data) {
            if constexpr (operation == ops::recv_client_initial) {
                auto session = static_cast<quic_session*>(data.user_data);
                if (session->recv_client_initial(data.dcid) != 0) {
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

    public:
        explicit quic_session(boost::asio::io_service& io_service, boost::asio::ssl::context& context)
            : socket_(io_service, context) {}

        std::future<void> process() {
            auto bytes = co_await coroutines::async_read_some(socket_, boost::asio::buffer(buffer_, 1024u));
            auto n = co_await coroutines::async_write(socket_, boost::asio::buffer(buffer_, bytes));
            process();
        }

        std::future<void> start() {
            std::cout << "accepted TLS\n";
            co_await coroutines::async_handshake(socket_);
            run();
            process();
        }

        void run() {
                auto callbacks = ngtcp2_conn_callbacks{
                    nullptr,
                        [](auto conn, auto dcid, auto user_data) {
                           ngtcp2_internal_data blob { .conn = conn, .dcid = dcid, .user_data = user_data};
                           return consume<ops::recv_client_initial>(std::move(blob));
                        },
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
                    nullptr,
                    nullptr,
                        [](auto conn, auto dest, auto destlen, auto, auto user_data){
                             ngtcp2_internal_data blob { .conn = conn, .dest = dest, .destlen = destlen, .user_data = user_data};
                             return consume<ops::rand>(std::move(blob));
                        }
                };

                constexpr auto NGTCP2_SV_SCIDLEN = 18u;
                ngtcp2_settings settings{};
                settings.log_printf = nullptr;
                //settings.initial_ts =
                settings.max_stream_data_bidi_local = 256_k;
                settings.max_stream_data_bidi_remote = 256_k;
                settings.max_stream_data_uni = 256_k;
                settings.max_data = 1_m;
                settings.max_bidi_streams = 100;
                settings.max_uni_streams = 0;
                //settings.idle_timeout =
                settings.max_packet_size = NGTCP2_MAX_PKT_SIZE;
                settings.ack_delay_exponent = NGTCP2_DEFAULT_ACK_DELAY_EXPONENT;
                settings.stateless_reset_token_present = 1;

                std::random_device rd;
                std::mt19937 randgen{rd()};
                auto dis = std::uniform_int_distribution<uint8_t>(0u, 255u);
                std::generate(std::begin(settings.stateless_reset_token), std::end(settings.stateless_reset_token),
                              [&dis, &randgen]() { return dis(randgen); });

                ngtcp2_cid scid;
                scid.datalen = NGTCP2_SV_SCIDLEN;
                std::generate(scid.data, scid.data + scid.datalen,
                              [&dis, &randgen]() { return dis(randgen); });

                ngtcp2_cid dummy_dcid;
                constexpr auto dummy_version = 0u;
                auto rv = ngtcp2_conn_server_new(&quic_connection, &dummy_dcid, &scid, dummy_version, &callbacks, &settings, this);
                assert(rv == 0);
        }

        using ssl_socket = boost::asio::ssl::stream<boost::asio::ip::tcp::socket>;
        ssl_socket::lowest_layer_type& socket() {
            return socket_.lowest_layer();
        }
   private:

        int recv_client_initial(const ngtcp2_cid *dcid) {
            return 0;
        }

        ssl_socket socket_;
        std::array<char, 1024u> buffer_;
        ngtcp2_conn *quic_connection = nullptr;
    };

    boost::asio::io_service io_service_;
    boost::asio::ip::tcp::acceptor acceptor_;
    boost::asio::ssl::context context_;
    std::vector<std::shared_ptr<quic_session>> sessions_;
};

static auto run_ssl_server() {
    try {
        ssl_server server{5555u};
        server.run();
    }
    catch (std::exception& e) {
        std::cout << "Exception: " << e.what() << "\n";
    }
}
}

int main() {
    minimal_server::run_ssl_server();
    return 0;
}
