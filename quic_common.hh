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

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <experimental/coroutine>
#include <future>

template <typename... Args>
struct std::experimental::coroutine_traits<std::future<void>, Args...> {
    struct promise_type {
        std::promise<void> p;
        auto get_return_object() { return p.get_future(); }
        std::experimental::suspend_never initial_suspend() { return {}; }
        std::experimental::suspend_never final_suspend() { return {}; }
        void set_exception(std::exception_ptr e) { p.set_exception(std::move(e)); }
        void unhandled_exception() { p.set_exception(std::current_exception()); }
        void return_void() { p.set_value(); }
    };
};

template <typename R, typename... Args>
struct std::experimental::coroutine_traits<std::future<R>, Args...> {
    struct promise_type {
        std::promise<R> p;
        auto get_return_object() { return p.get_future(); }
        std::experimental::suspend_never initial_suspend() { return {}; }
        std::experimental::suspend_never final_suspend() { return {}; }
        void set_exception(std::exception_ptr e) { p.set_exception(std::move(e)); }
        void unhandled_exception() { p.set_exception(std::current_exception()); }
        template <typename U> void return_value(U &&u) {
            p.set_value(std::forward<U>(u));
        }
    };
};

namespace coroutines {

template <typename Socket, typename BufferSeq>
auto async_read_some(Socket& socket, const BufferSeq &buffer) {
    struct [[nodiscard]] Awaitable {
        Socket& s;
        const BufferSeq & b;
        boost::system::error_code ec;
        size_t n;

        bool await_ready() { return false; }
        void await_suspend(std::experimental::coroutine_handle<> h) {
            s.async_read_some(b, [this, h](auto ec, auto n) mutable {
                this->ec = ec;
                this->n = n;
                h.resume();
            });
        }
        auto await_resume() {
            if (ec)
                throw std::system_error(ec);
            return n;
        }
    };
    return Awaitable{socket, buffer};
}

template <typename Socket, typename BufferSeq>
auto async_write(Socket& socket, const BufferSeq& buffer) {
    struct [[nodiscard]] Awaitable {
        Socket& s;
        const BufferSeq &b;
        boost::system::error_code ec;
        size_t n;

        bool await_ready() { return false; }
        void await_suspend(std::experimental::coroutine_handle<> h) {
            boost::asio::async_write(s, b, [this, h](auto ec, auto n) mutable {
                this->ec = ec;
                this->n = n;
                h.resume();
            });
        }
        auto await_resume() {
            if (ec)
                throw std::system_error(ec);
            return n;
        }
    };
    return Awaitable{socket, buffer};
}

template <typename Socket>
auto async_handshake(Socket& socket) {
    struct [[nodiscard]] Awaitable {
        Socket& s;
        boost::system::error_code ec;

        bool await_ready() { return false; }
        void await_suspend(std::experimental::coroutine_handle<> h) {
            s.async_handshake(boost::asio::ssl::stream_base::server, [this, h](auto ec) mutable {
                this->ec = ec;
                h.resume();
            });
        }
        void await_resume() {
            if (ec)
                throw std::system_error(ec);
        }
    };
    return Awaitable{socket};
}

template <typename Socket, typename Acceptor>
auto async_accept(Acceptor &acceptor, Socket& socket) {
    struct [[nodiscard]] Awaitable {
        Acceptor &a;
        Socket& s;
        boost::system::error_code ec;

        bool await_ready() { return false; }
        void await_suspend(std::experimental::coroutine_handle<> h) {
            a.async_accept(s, [this, h](auto ec) mutable {
                this->ec = ec;
                h.resume();
            });
        }
        void await_resume() {
            if (ec)
                throw std::system_error(ec);
        }
    };
    return Awaitable{acceptor, socket};
}

}
