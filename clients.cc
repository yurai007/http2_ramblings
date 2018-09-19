#include <boost/range/irange.hpp>
#include <boost/asio.hpp>
#include <cassert>
#include <cstdio>
#include <ctime>
#include <variant>
#include <array>
#include <iostream>
#include "common.hh"
#include <lib/nghttp2_session.h>
#include <lib/nghttp2_callbacks.h>
#include <lib/nghttp2_frame.h>

// TO DO 1: why no RST_STREAM in any scenario??
// TO DO 2: more illegal requests - ideas in #527
// TO DO 3: create_idle_streams
// TO DO 4: tests/nghttp2_session_test.c - options + more advanced API usage
// To DO 5: memory usage #1035 ?

/*
namespace nghttp2_internal_unit_tests {

static auto test_nghttp2_session_recv_eof() {
    nghttp2_session_callbacks callbacks = {};
    callbacks.send_callback = [](auto, auto, auto len, auto, auto) {
        return static_cast<ssize_t>(len);
    };
    callbacks.recv_callback = [](auto, auto, auto, auto, auto) {
        return static_cast<ssize_t>(NGHTTP2_ERR_EOF);
    };

    nghttp2_session *session;
    nghttp2_session_client_new(&session, &callbacks, nullptr);
    // trigger callbacks
    assert(NGHTTP2_ERR_EOF == nghttp2_session_recv(session));
    nghttp2_session_del(session);
}

static auto test_nghttp2_session_recv_too_large_frame_length() {

    nghttp2_frame_hd hd;
    nghttp2_frame_hd_init(&hd, NGHTTP2_MAX_FRAME_SIZE_MIN + 1, NGHTTP2_HEADERS,
                          NGHTTP2_FLAG_NONE, 1);

    nghttp2_session *session;
    nghttp2_session_callbacks callbacks = {};
    // no callbacks
    nghttp2_session_server_new(&session, &callbacks, nullptr);

    std::array<uint8_t, NGHTTP2_FRAME_HDLEN> buf;
    // apply hpack to max_frame+1
    nghttp2_frame_pack_frame_hd(buf.data(), &hd);
    // pass hpack frame to nghttp2
    assert(buf.size() == nghttp2_session_mem_recv(session, buf.data(), buf.size()));
    // take generated response frame
    auto item = nghttp2_session_get_next_ob_item(session);

    assert(item != nullptr);
    assert(NGHTTP2_GOAWAY == item->frame.hd.type);

    nghttp2_session_del(session);
}

struct h2data {
    int frame_recv_cb_called {0};
    int invalid_frame_recv_cb_called {0};
    int stream_close_cb_called {0};
    int stream_close_error_code {0};
    uint8_t recv_frame_type;
    nghttp2_frame_hd recv_frame_hd;
};

static auto test_nghttp2_session_recv_unknown_frame() {
    nghttp2_frame_hd hd;
    nghttp2_frame_hd_init(&hd, 16000, 99, NGHTTP2_FLAG_NONE, 0);
    std::array<uint8_t, NGHTTP2_MAX_PAYLOADLEN> data;
    nghttp2_frame_pack_frame_hd(data.data(), &hd);
    auto datalen = NGHTTP2_FRAME_HDLEN + hd.length;

    nghttp2_session_callbacks callbacks;
    callbacks.on_frame_recv_callback = [](auto, auto frame, auto user_data){
            auto ud = reinterpret_cast<h2data*>(user_data);
            ++ud->frame_recv_cb_called;
            ud->recv_frame_type = frame->hd.type;
            ud->recv_frame_hd = frame->hd;
            return 0;
    };

    nghttp2_session *session;
    h2data userdata;
    nghttp2_session_server_new(&session, &callbacks, &userdata);

    // Unknown frame must be ignored
    auto rv = nghttp2_session_mem_recv(session, data.data(), datalen);
    assert(rv == static_cast<ssize_t>(datalen));
    assert(0 == userdata.frame_recv_cb_called);
    assert(nullptr == nghttp2_session_get_next_ob_item(session));
    nghttp2_session_del(session);
}

static auto open_sent_stream3(nghttp2_session *session, int32_t stream_id,
                              uint8_t flags,
                              nghttp2_priority_spec *pri_spec_in,
                              nghttp2_stream_state initial_state,
                              void *stream_user_data) {
    assert(nghttp2_session_is_my_stream_id(session, stream_id));
    auto stream = nghttp2_session_open_stream(session, stream_id, flags, pri_spec_in,
                                              initial_state, stream_user_data);
    session->last_sent_stream_id =
            std::max(session->last_sent_stream_id, stream_id);
    session->next_stream_id =
            std::max(session->next_stream_id, (uint32_t)stream_id + 2);
    return stream;
}

static auto open_sent_stream(nghttp2_session *session, int32_t stream_id) {
    nghttp2_priority_spec pri_spec;

    nghttp2_priority_spec_init(&pri_spec, 0, NGHTTP2_DEFAULT_WEIGHT, 0);
    return open_sent_stream3(session, stream_id, NGHTTP2_FLAG_NONE, &pri_spec,
                             NGHTTP2_STREAM_OPENED, nullptr);
}

static auto open_recv_stream3(nghttp2_session *session, int32_t stream_id,
                                  uint8_t flags,
                                  nghttp2_priority_spec *pri_spec_in,
                                  nghttp2_stream_state initial_state,
                                  void *stream_user_data) {
    assert(!nghttp2_session_is_my_stream_id(session, stream_id));
    auto stream = nghttp2_session_open_stream(session, stream_id, flags, pri_spec_in,
                                              initial_state, stream_user_data);
    session->last_recv_stream_id =
            std::max(session->last_recv_stream_id, stream_id);
    return stream;
}

static auto open_recv_stream(nghttp2_session *session, int32_t stream_id) {
    nghttp2_priority_spec pri_spec;

    nghttp2_priority_spec_init(&pri_spec, 0, NGHTTP2_DEFAULT_WEIGHT, 0);
    return open_recv_stream3(session, stream_id, NGHTTP2_FLAG_NONE, &pri_spec,
                             NGHTTP2_STREAM_OPENED, nullptr);
}

static auto test_nghttp2_session_on_goaway_received() {

    nghttp2_session_callbacks callbacks = {};
    callbacks.on_frame_recv_callback = [](auto, auto frame, auto user_data){
            auto ud = reinterpret_cast<h2data*>(user_data);
            ++ud->frame_recv_cb_called;
            ud->recv_frame_type = frame->hd.type;
            ud->recv_frame_hd = frame->hd;
            return 0;
    };
    callbacks.on_invalid_frame_recv_callback = [](auto, auto, auto, auto user_data){
            auto ud = reinterpret_cast<h2data*>(user_data);
            ++ud->invalid_frame_recv_cb_called;
            return 0;
    };
    callbacks.on_stream_close_callback = [](auto, auto, auto error_code, auto user_data){
            auto ud = reinterpret_cast<h2data*>(user_data);
            ++ud->stream_close_cb_called;
            ud->stream_close_error_code = error_code;
            return 0;
    };

    nghttp2_frame frame;
    auto mem = nghttp2_mem_default();
    h2data user_data;
    user_data.frame_recv_cb_called = 0;
    user_data.invalid_frame_recv_cb_called = 0;

    nghttp2_session *session;
    nghttp2_session_client_new(&session, &callbacks, &user_data);

    for (auto i : boost::irange(1,8)) {
        if (nghttp2_session_is_my_stream_id(session, i)) {
            open_sent_stream(session, i);
        } else {
            open_recv_stream(session, i);
        }
    }

    nghttp2_frame_goaway_init(&frame.goaway, 3, NGHTTP2_PROTOCOL_ERROR, nullptr, 0);

    user_data.stream_close_cb_called = 0;

    assert(0 == nghttp2_session_on_goaway_received(session, &frame));

    assert(1 == user_data.frame_recv_cb_called);
    assert(3 == session->remote_last_stream_id);
    // on_stream_close should be called for 2 times (stream 5 and 7)
    assert(2 == user_data.stream_close_cb_called);

    for (auto i : boost::irange(1,5)) {
        assert(nullptr != nghttp2_session_get_stream(session, i));
    }
    assert(nullptr == nghttp2_session_get_stream(session, 5));
    assert(nullptr != nghttp2_session_get_stream(session, 6));
    assert(nullptr == nghttp2_session_get_stream(session, 7));

    nghttp2_frame_goaway_free(&frame.goaway, mem);
    nghttp2_session_del(session);
}

static auto run() {
    test_nghttp2_session_recv_eof();
    test_nghttp2_session_recv_too_large_frame_length();
    test_nghttp2_session_recv_unknown_frame();
    test_nghttp2_session_on_goaway_received();
    std::cout << "ok\n";
}
}
*/
namespace bad_clients {

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

}

/*
 * callbacks must be present and at least on_frame_send callback must be set
 * 9B SETTINGS frame may be omitted
 */
namespace loopback_client {

#define TIMESPEC_NSEC(ts) ((ts)->tv_sec * 1000000000ULL + (ts)->tv_nsec)

static inline uint64_t realtime_now()
{
    struct timespec now_ts;
    clock_gettime(CLOCK_REALTIME, &now_ts);
    return TIMESPEC_NSEC(&now_ts);
}

static auto test() {
    using namespace bad_clients;

    nghttp2_session_callbacks *callbacks;
    auto rv = nghttp2_session_callbacks_new(&callbacks);
    assert(rv == 0);
    nghttp2_session_callbacks_set_on_frame_send_callback(callbacks, [](auto, auto, auto) { return 0; });
    rv = nghttp2_session_client_new(&session, callbacks, nullptr);
    nghttp2_session_callbacks_del(callbacks);
    assert (rv == 0 && session);
//    nghttp2_settings_entry ent{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 1000};
//    rv = nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, &ent, 1);
//    assert(rv == 0);
    rv = nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, nullptr, 0);
    assert(rv == 0);

    constexpr request headers = {"GET", "/get", "https", "127.0.0.1:3000", "*/*", "nghttp2/" NGHTTP2_VERSION};
    std::array<nghttp2_nv, 6> nva = {make_header(":method", std::get<0>(headers)),
                                     make_header(":path", std::get<1>(headers)),
                                     make_header(":scheme", std::get<2>(headers)),
                                     make_header(":authority", std::get<3>(headers)),
                                     make_header("accept", std::get<4>(headers)),
                                     make_header("user-agent", std::get<5>(headers))
                                    };

    constexpr static auto iterations = 100u;
    auto t0 = realtime_now();
    for (auto i = 0; i < iterations; i++) {
        auto stream_id = nghttp2_submit_request(session, nullptr, nva.data(),
                                           nva.size(), nullptr, nullptr);
        assert(stream_id >= 0);
        auto size = 0u;
        for (;;) {
            const uint8_t *data = nullptr;
            auto bytes = nghttp2_session_mem_send(session, &data);
            assert(bytes >= 0);
            if (bytes == 0) {
                break;
            } else if (debug) {
                dump_buffer(std::string(reinterpret_cast<const char*>(data), bytes));
                auto frame = &session->ob_syn.head->frame;
                if (frame) {
                    dump_frame_type(static_cast<nghttp2_frame_type>(frame->hd.type));
                }
            }
            size += bytes;
        }
        assert(size == 82 || size == 19);
    }
    auto t1 = realtime_now();
    auto time_ns = (t1 - t0)/iterations;
    return static_cast<long long int>(time_ns);
}

}

int main(int ac, char** av) {
    init_debug(ac, av);
    constexpr static auto iterations = 100000u;
    auto full_time = 0LL;
    for (auto i = 0; i < iterations; i++) {
        full_time += loopback_client::test();
    }
    std::cout <<  "avg time of single deflating = " << full_time / iterations << " ns.\n";
    //bad_clients::run();
    return 0;
}
