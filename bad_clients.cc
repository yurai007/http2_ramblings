#include <boost/range/irange.hpp>
#include <boost/asio.hpp>
#include <cassert>
#include <variant>
#include <array>
#include <iostream>
#include "common.hh"

// TO DO 1: why no RST_STREAM in any scenario??
// TO DO 2: more illegal requests - ideas in #527
// TO DO 3: create_idle_streams
// TO DO 4: tests/nghttp2_session_test.c - options + more advanced API usage
// To DO 5: memory usage #1035 ?

enum class ops {on_send, on_recv, on_close, on_data_chunk_recv};
using nghttp2_blob = std::tuple<int32_t, const uint8_t *, size_t>;
using nghttp2_internal_data = std::variant<const nghttp2_frame*, int32_t, nghttp2_blob>;
using request = std::tuple<const char*, const char*, const char*, const char*, const char*, const char*>;

static nghttp2_session *session = nullptr;
static auto done = false;

static auto run_asio_client() {
    using boost::asio::ip::tcp;
    try {
        boost::asio::io_service io_service;
        tcp::resolver resolver {io_service};
        tcp::socket socket {io_service};
        boost::system::error_code error = boost::asio::error::host_not_found;
        auto endpoint = resolver.resolve(tcp::resolver::query("127.0.0.1", "3000",
                                                              tcp::resolver::query::canonical_name));
        socket.connect(*endpoint, error);
        assert(!error);
        std::cout << "established TCP\n";
        std::array<unsigned char, 128u> buffer;

        for (;;) {
            auto size = 0u;
            for (;;) {
                const uint8_t *data = nullptr;
                auto bytes = nghttp2_session_mem_send(session, &data);
                assert(bytes >= 0);
                if (bytes == 0) {
                    break;
                }
                assert(size + static_cast<unsigned>(bytes) <= 128u);
                std::copy_n(data, bytes, std::begin(buffer) + size);
                size += bytes;
            }
            auto send_bytes = boost::asio::write(socket, boost::asio::buffer(buffer, size), error);
            assert(send_bytes == size && !error);
            if (done)
                break;
            auto recieved_bytes = socket.read_some(boost::asio::buffer(buffer), error);
            assert(!error);
            auto rc = nghttp2_session_mem_recv(session, &buffer[0], recieved_bytes);
            // TO DO: server should send SETTINGS ACK for client ACK even in ok case!
            //assert(rc >= 0);
        }
    }
    catch (std::exception &)
    {
        assert(false);
    }
}

template<ops operation>
static auto consume_frame(nghttp2_internal_data && data) {
    if constexpr (operation == ops::on_send) {
        auto frame = std::get<const nghttp2_frame*>(data);
        dump_frame_type(static_cast<nghttp2_frame_type>(frame->hd.type));
        if (frame->hd.type == NGHTTP2_GOAWAY) {
            done = true;
        }
    } else if constexpr (operation == ops::on_recv) {
        auto frame = std::get<const nghttp2_frame*>(data);
        dump_frame_type(static_cast<nghttp2_frame_type>(frame->hd.type), "<----------------------------");
    } else if constexpr (operation == ops::on_data_chunk_recv) {
        auto [stream_id, rep, len] = std::get<nghttp2_blob>(data);
        std::cout << "response body: " << std::string(reinterpret_cast<const char*>(rep), len) << std::endl;
    } else {
        auto rv = nghttp2_session_terminate_session(session, NGHTTP2_NO_ERROR);
        assert(rv == 0);
    }
    return 0;
}

static auto do_cast(const char *ptr) {
    return const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(ptr));
}

template <size_t size>
static nghttp2_nv make_header(const char (&name)[size], const char *value) {
    return {(uint8_t *)name, do_cast(value), size - 1, strlen(value),
                NGHTTP2_NV_FLAG_NO_COPY_NAME};
}

namespace reqs {
static auto req_3() {
    constexpr request headers = {"GET", "/get", "https", "127.0.0.1:3000", "*/*", "nghttp2/" NGHTTP2_VERSION};
    std::array<nghttp2_nv, 3> nva = {make_header(":method", std::get<0>(headers)),
                                     make_header(":path", std::get<1>(headers)),
                                     make_header(":scheme", std::get<2>(headers))
                                    };

    return nghttp2_submit_request(session, nullptr, nva.data(),
                                       nva.size(), nullptr, nullptr);
}

static auto req_4() {
    constexpr request headers = {"GET", "/get", "https", "127.0.0.1:3000", "*/*", "nghttp2/" NGHTTP2_VERSION};
    std::array<nghttp2_nv, 4> nva = {make_header(":method", std::get<0>(headers)),
                                     make_header(":path", std::get<1>(headers)),
                                     make_header(":scheme", std::get<2>(headers)),
                                     make_header(":authority", std::get<3>(headers))
                                    };

    return nghttp2_submit_request(session, nullptr, nva.data(),
                                       nva.size(), nullptr, nullptr);
}

static auto req_5() {
    constexpr request headers = {"GET", "/get", "https", "127.0.0.1:3000", "*/*", "nghttp2/" NGHTTP2_VERSION};
    std::array<nghttp2_nv, 5> nva = {make_header(":method", std::get<0>(headers)),
                                     make_header(":path", std::get<1>(headers)),
                                     make_header(":scheme", std::get<2>(headers)),
                                     make_header(":authority", std::get<3>(headers)),
                                     make_header("accept", std::get<4>(headers)),
                                    };

    return nghttp2_submit_request(session, nullptr, nva.data(),
                                       nva.size(), nullptr, nullptr);
}

static auto req_malformed_method() {
    constexpr request headers = {"GET", "/get", "https", "127.0.0.1:3000", "*/*", "nghttp2/" NGHTTP2_VERSION};
    std::array<nghttp2_nv, 6> nva = {make_header("method", std::get<0>(headers)),
                                     make_header(":path", std::get<1>(headers)),
                                     make_header(":scheme", std::get<2>(headers)),
                                     make_header(":authority", std::get<3>(headers)),
                                     make_header("accept", std::get<4>(headers)),
                                     make_header("user-agent", std::get<5>(headers))
                                    };

    return nghttp2_submit_request(session, nullptr, nva.data(),
                                       nva.size(), nullptr, nullptr);
}

static auto req_bad_order() {
    constexpr request headers = {"GET", "/get", "https", "127.0.0.1:3000", "*/*", "nghttp2/" NGHTTP2_VERSION};
    std::array<nghttp2_nv, 6> nva = {make_header("accept", std::get<4>(headers)),
                                    make_header(":method", std::get<0>(headers)),
                                     make_header(":path", std::get<1>(headers)),
                                     make_header(":scheme", std::get<2>(headers)),
                                     make_header(":authority", std::get<3>(headers)),
                                     make_header("user-agent", std::get<5>(headers))
                                    };

    return nghttp2_submit_request(session, nullptr, nva.data(),
                                       nva.size(), nullptr, nullptr);
}

static auto req_ok() {
    constexpr request headers = {"GET", "/get", "https", "127.0.0.1:3000", "*/*", "nghttp2/" NGHTTP2_VERSION};
    std::array<nghttp2_nv, 6> nva = {make_header(":method", std::get<0>(headers)),
                                     make_header(":path", std::get<1>(headers)),
                                     make_header(":scheme", std::get<2>(headers)),
                                     make_header(":authority", std::get<3>(headers)),
                                     make_header("accept", std::get<4>(headers)),
                                     make_header("user-agent", std::get<5>(headers))
                                    };

    return nghttp2_submit_request(session, nullptr, nva.data(),
                                       nva.size(), nullptr, nullptr);
}

static auto req_malformed_method_value() {
    constexpr request headers = {"blabla", "/get", "https", "127.0.0.1:3000", "*/*", "nghttp2/" NGHTTP2_VERSION};
    std::array<nghttp2_nv, 6> nva = {make_header(":method", std::get<0>(headers)),
                                     make_header(":path", std::get<1>(headers)),
                                     make_header(":scheme", std::get<2>(headers)),
                                     make_header(":authority", std::get<3>(headers)),
                                     make_header("accept", std::get<4>(headers)),
                                     make_header("user-agent", std::get<5>(headers))
                                    };

    return nghttp2_submit_request(session, nullptr, nva.data(),
                                       nva.size(), nullptr, nullptr);
}

static auto req_malformed_accept_value() {
    constexpr request headers = {"blabla", "/get", "https", "127.0.0.1:3000", "er9t34j89t", "nghttp2/" NGHTTP2_VERSION};
    std::array<nghttp2_nv, 6> nva = {make_header(":method", std::get<0>(headers)),
                                     make_header(":path", std::get<1>(headers)),
                                     make_header(":scheme", std::get<2>(headers)),
                                     make_header(":authority", std::get<3>(headers)),
                                     make_header("accept", std::get<4>(headers)),
                                     make_header("user-agent", std::get<5>(headers))
                                    };

    return nghttp2_submit_request(session, nullptr, nva.data(),
                                       nva.size(), nullptr, nullptr);
}
}

static auto run() {
    nghttp2_session_callbacks *callbacks;
    auto rv = nghttp2_session_callbacks_new(&callbacks);
    assert(rv == 0);

    nghttp2_session_callbacks_set_on_frame_send_callback(callbacks,
        [](nghttp2_session *, const nghttp2_frame *frame, void *) {
            return consume_frame<ops::on_send>(frame);
    });

    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
        [](nghttp2_session*, const nghttp2_frame *frame, void *) {
            return consume_frame<ops::on_recv>(frame);
        });

    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks,
        [](nghttp2_session*, int32_t stream_id, uint32_t, void *) {
            return consume_frame<ops::on_close>(stream_id);
        });

    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks,
        [](nghttp2_session*, uint8_t, int32_t stream_id, const uint8_t *data, size_t len, void *) {
            return consume_frame<ops::on_data_chunk_recv>(std::make_tuple(stream_id, data, len));
        });

    nghttp2_session_callbacks_set_error_callback2(callbacks,
         [](nghttp2_session *, int lib_error_code, const char *msg, size_t, void *){
            std::cout << "error: "<< lib_error_code << " " << msg << std::endl;
            return static_cast<int>(NGHTTP2_ERR_CALLBACK_FAILURE);
        });

    rv = nghttp2_session_client_new(&session, callbacks, nullptr);
    nghttp2_session_callbacks_del(callbacks);
    assert (rv == 0 && session);
    rv = nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, nullptr, 0);
    assert(rv == 0);

    assert(reqs::req_ok() >= 0);
    assert(reqs::req_ok() >= 0);

    run_asio_client();
    nghttp2_session_del(session);
}

int main(int ac, char** av) {
    init_debug(ac, av);
    run();
    return 0;
}
