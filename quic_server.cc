#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <ngtcp2/ngtcp2.h>
#include <exception>
#include <iostream>
#include <string>
#include <array>

namespace minimal_server {

static auto run() {

}

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

    void start_accept() {
        session_ = std::make_shared<tls_session>(io_service_, context_);
        acceptor_.async_accept(session_->socket(),
                               [this](auto error){
            if (!error) {
                session_->start();
            }
            this->start_accept();
        });
    }

    void run() {
        io_service_.run();
    }

private:

    class tls_session : public std::enable_shared_from_this<tls_session> {
    public:
        explicit tls_session(boost::asio::io_service& io_service, boost::asio::ssl::context& context)
            : socket_(io_service, context) {}

        void process(const boost::system::error_code& error) {
            if (!error) {
                socket_.async_read_some(boost::asio::buffer(buffer_, 1024u),
                                        [this](auto error, auto bytes_transferred){
                    if (!error) {
                        boost::asio::async_write(socket_,
                                                 boost::asio::buffer(buffer_, bytes_transferred),
                                                 [this](auto error, auto){
                            process(error);
                        });
                    }
                });
            }
        }

        void start() {
            std::cout << "accepted TLS\n";
            socket_.async_handshake(boost::asio::ssl::stream_base::server,
                                    [this](auto error){
                        this->process(error);
            });
        }

        using ssl_socket = boost::asio::ssl::stream<boost::asio::ip::tcp::socket>;
        ssl_socket::lowest_layer_type& socket() {
            return socket_.lowest_layer();
        }
    private:
        ssl_socket socket_;
        std::array<char, 1024u> buffer_;
    };

    boost::asio::io_service io_service_;
    boost::asio::ip::tcp::acceptor acceptor_;
    boost::asio::ssl::context context_;
    std::shared_ptr<tls_session> session_;
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
    minimal_server::run();
    minimal_server::run_ssl_server();
    return 0;
}
