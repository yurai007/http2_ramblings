#pragma once

#include <boost/program_options.hpp>
#include <nghttp2/nghttp2.h>
#include <iostream>

auto inline debug = false;

static auto init_debug(auto ac, auto av) {
    namespace bpo = boost::program_options;
    auto desc = bpo::options_description("simple http/2");
    desc.add_options()("debug,d", bpo::value<bool>()->default_value(false), "debug");
    auto variables_map = bpo::variables_map();
    bpo::store(bpo::parse_command_line(ac, av, desc), variables_map);
    debug = variables_map["debug"].as<bool>();
}

static auto dump_buffer(const std::string &buffer) {
    std::cout <<  buffer.size() << " B:     ";
    for (auto i = 0u; i < buffer.size(); i++)
        std::cout << (unsigned char)(buffer[i]);
    std::cout << "\n";
}

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
