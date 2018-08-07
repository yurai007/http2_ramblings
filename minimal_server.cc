#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#include <boost/asio.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>
#include <iostream>
#include <variant>
#include <memory>
#include <cassert>
#include <array>
#include "common.hh"

enum class ops {on_send, on_recv, on_close, on_data_chunk_recv};
using nghttp2_blob = std::tuple<int32_t, const uint8_t *, size_t>;
using nghttp2_internal_data = std::variant<const nghttp2_frame*, int32_t, nghttp2_blob>;

static nghttp2_session *session = nullptr;

static auto run_asio_server() {
    using boost::asio::ip::tcp;

    class tcp_session : public std::enable_shared_from_this<tcp_session>
    {
    public:
        explicit tcp_session(tcp::socket socket): socket_(std::move(socket)) {}

        void run() {
            std::cout << "accepted TCP\n";
            auto self(shared_from_this());
            boost::asio::spawn(socket_.get_io_service(), [this, self](auto yield) {
                try {
                    std::array<unsigned char, 128u> buffer;
                    for (;;) {
                        auto recieved_bytes = socket_.async_read_some(boost::asio::buffer(buffer), yield);
                        auto rc = nghttp2_session_mem_recv(session, &buffer[0], recieved_bytes);
                        assert(rc >= 0);
                        boost::asio::async_write(socket_, boost::asio::buffer(buffer, recieved_bytes), yield);
                    }
                } catch (std::exception& e) {
                    socket_.close();
                    std::cerr << "exception: " << e.what() << "\n";
                }
            });
        }
    private:
        tcp::socket socket_;
    };

    boost::asio::io_service io_service;
    boost::asio::spawn(io_service, [&](auto yield) {
        tcp::acceptor acceptor(io_service, tcp::endpoint(tcp::v4(), 3000));
        boost::system::error_code ec;
        tcp::socket socket(io_service);
        acceptor.async_accept(socket, yield[ec]);
        assert(!ec);
        std::make_shared<tcp_session>(std::move(socket))->run();
    });

    io_service.run();
}

template<ops operation>
static auto consume_frame(nghttp2_internal_data && data) {
    if constexpr (operation == ops::on_send) {
        auto frame = std::get<const nghttp2_frame*>(data);
        dump_frame_type(static_cast<nghttp2_frame_type>(frame->hd.type));
    } else if constexpr (operation == ops::on_recv) {
        auto frame = std::get<const nghttp2_frame*>(data);
        dump_frame_type(static_cast<nghttp2_frame_type>(frame->hd.type), "---------------------------->");
        if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
            std::cout << "handle\n";
        }
    } else if constexpr (operation == ops::on_close) {
        std::cout << "close\n";
    }
    return 0;
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

    rv = nghttp2_session_server_new(&session, callbacks, nullptr);
    nghttp2_session_callbacks_del(callbacks);
    assert (rv == 0 && session);
    rv = nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, nullptr, 0);
    assert(rv == 0);
    try {
        run_asio_server();
    } catch (std::exception& e) {
        std::cerr << "exception: " << e.what() << "\n";
    }
}

int main(int ac, char** av) {
    init_debug(ac, av);
    run();
    return 0;
}
