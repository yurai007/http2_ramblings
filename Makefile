LDFLAGS += -lboost_system -lnghttp2 -lboost_program_options -lpthread

all: CC := g++
all: CXXFLAGS = -g -gz -Wall -W -Wextra -Wshadow -Wpedantic -Wformat-security -Walloca -Wduplicated-branches -std=c++2a -fconcepts
all: CXXFLAGS += -fstack-protector -fsanitize=address -fsanitize-recover=address -fsanitize=undefined -fsanitize-address-use-after-scope -fsanitize=signed-integer-overflow -fsanitize=vptr
all: minimal_client.cc clients.cc minimal_server.cc quic_client.cc
	$(CC) $(CXXFLAGS) minimal_client.cc -o client $(LDFLAGS)
	$(CC) $(CXXFLAGS) minimal_server.cc -o server -lboost_coroutine $(LDFLAGS)
	$(CC) -I/home/yurai/seastar/nghttp2 $(CXXFLAGS) clients.cc -o clients $(LDFLAGS)
	$(CC) -I/home/yurai/ngtcp2/lib/includes $(CXXFLAGS) quic_client.cc -o quic_client -lboost_system -L/home/yurai/ngtcp2/lib/.libs -lngtcp2 -lboost_program_options -lpthread -lssl -lcrypto
	$(CC) -I/home/yurai/ngtcp2/lib/includes $(CXXFLAGS) quic_server.cc -o quic_server -lboost_system -L/home/yurai/ngtcp2/lib/.libs -lngtcp2 -lboost_program_options -lpthread -lssl -lcrypto

clang: CC := clang++
clang: CXXFLAGS = -g -Weverything -Wno-c++98-compat -std=c++2a -fcoroutines-ts -Wno-c99-extensions -Wno-c++98-compat-pedantic -stdlib=libc++
#clang: CXXFLAGS += -fstack-protector -fsanitize=address -fsanitize-recover=address -fsanitize=undefined -fsanitize-address-use-after-scope -fsanitize=signed-integer-overflow -fsanitize=vptr
clang: quic_client.cc quic_server.cc
	$(CC) -I/home/yurai/ngtcp2/lib/includes $(CXXFLAGS) quic_client.cc -o quic_client -lboost_system -L/home/yurai/ngtcp2/lib/.libs -lngtcp2 -lboost_program_options -lpthread -lssl -lcrypto
	$(CC) -I/home/yurai/ngtcp2/lib/includes $(CXXFLAGS) quic_server.cc -o quic_server -lboost_system -L/home/yurai/ngtcp2/lib/.libs -lngtcp2 -lboost_program_options -lpthread -lssl -lcrypto

clean:
	@- $(RM) client server clients quic_client quic_server

distclean: clean

