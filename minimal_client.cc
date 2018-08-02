#include <nghttp2/nghttp2.h>
#include <boost/range/irange.hpp>
#include <boost/program_options.hpp>
#include <boost/asio.hpp>
#include <cassert>
#include <variant>
#include <array>
#include <iostream>

// TO DO1: async Boost.Asio based on corutines OR boost asio (blocking) + Executor proposal?
// TO DO2: run_asio_client may be simplified by buffer removal

namespace bpo = boost::program_options;

enum class ops {on_send, on_recv, on_close, on_data_chunk_recv};
using nghttp2_blob = std::tuple<int32_t, const uint8_t *, size_t>;
using nghttp2_internal_data = std::variant<const nghttp2_frame*, int32_t, nghttp2_blob>;
using request = std::tuple<const char*, const char*, const char*, const char*, const char*, const char*>;

static nghttp2_session *session = nullptr;
constexpr request headers = {"GET", "/get", "https", "127.0.0.1:3000", "*/*", "nghttp2/" NGHTTP2_VERSION};
static auto done = false;
static auto debug = false;

static auto dump_frame_type(nghttp2_frame_type frame_type,
                     const char *direction = "---------------------------->") {
    if (!debug)
        return;
    switch(frame_type) {
    case NGHTTP2_RST_STREAM:
        std::cout << "[INFO] C " << direction << " S (RST_STREAM)\n";
        break;
    case NGHTTP2_SETTINGS:
        std::cout << "[INFO] C " << direction << " S (SETTINGS)\n";
        break;
    case NGHTTP2_HEADERS:
        std::cout << "[INFO] C " << direction << " S (HEADERS)\n";
        break;
    case NGHTTP2_WINDOW_UPDATE:
        std::cout << "[INFO] C " << direction << " S (WIN_UPDATE)\n";
        break;
    case  NGHTTP2_DATA:
        std::cout << "[INFO] C " << direction << " S (DATA)\n";
        break;
    case NGHTTP2_GOAWAY:
        std::cout << "[INFO] C " << direction << " S (GOAWAY)\n";
        break;
    case NGHTTP2_PUSH_PROMISE:
        std::cout << "[INFO] C " << direction << " S (PUSH_PROMISE)\n";
        break;
    default:
        break;
    }
}

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
            assert(rc >= 0);
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

    rv = nghttp2_session_client_new(&session, callbacks, nullptr);
    nghttp2_session_callbacks_del(callbacks);
    assert (rv == 0 && session);
    rv = nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, nullptr, 0);
    assert(rv == 0);

    std::array<nghttp2_nv, 6> nva = {make_header(":method", std::get<0>(headers)),
                                     make_header(":path", std::get<1>(headers)),
                                     make_header(":scheme", std::get<2>(headers)),
                                     make_header(":authority", std::get<3>(headers)),
                                     make_header("accept", std::get<4>(headers)),
                                     make_header("user-agent", std::get<5>(headers))
                                    };

    auto stream_id = nghttp2_submit_request(session, nullptr, nva.data(),
                                       nva.size(), nullptr, nullptr);
    assert(stream_id >= 0);

    run_asio_client();
    nghttp2_session_del(session);
}

int main(int ac, char** av) {
    auto desc = bpo::options_description("simple http/2 client");
    desc.add_options()("debug,d", bpo::value<bool>()->default_value(false), "debug");
    auto variables_map = bpo::variables_map();
    bpo::store(bpo::parse_command_line(ac, av, desc), variables_map);
    debug = variables_map["debug"].as<bool>();
    run();
    return 0;
}
