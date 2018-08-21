LDFLAGS += -lboost_system -lnghttp2 -lboost_program_options -lpthread

all: CC := g++
all: CXXFLAGS = -Wall -W -Wextra -Wshadow -Wpedantic -Wformat-security -Walloca -Wduplicated-branches -g -std=c++2a -fconcepts
#all: CXXFLAGS += -fstack-protector -fsanitize=address -fsanitize-recover=address -fsanitize=undefined -fsanitize-address-use-after-scope -fsanitize=signed-integer-overflow -fsanitize=vptr
all: minimal_client.cc clients.cc minimal_server.cc
	$(CC) $(CXXFLAGS) minimal_client.cc -o client $(LDFLAGS)
	$(CC) -I/home/yurai/seastar/nghttp2 $(CXXFLAGS) clients.cc -o clients $(LDFLAGS)
	$(CC) $(CXXFLAGS) minimal_server.cc -o server -lboost_coroutine $(LDFLAGS)

clang: CC := clang++
clang: CXXFLAGS = -Weverything -Wno-c++98-compat -std=c++2a -g
clang: CXXFLAGS += -fstack-protector -fsanitize=address -fsanitize-recover=address -fsanitize=undefined -fsanitize-address-use-after-scope -fsanitize=signed-integer-overflow -fsanitize=vptr
clang: minimal_client.cc clients.cc minimal_server.cc
	$(CC) $(CXXFLAGS) minimal_client.cc -o client $(LDFLAGS)
	$(CC) $(CXXFLAGS) clients.cc -o clients $(LDFLAGS)
	$(CC) $(CXXFLAGS) minimal_server.cc -o server -lboost_coroutine $(LDFLAGS)


clean:
	@- $(RM) client server clients

distclean: clean

