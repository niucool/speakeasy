#include <cstdio>
#include <fstream>
#include <memory>
#include <string>
#include <vector>


inline std::vector<uint8_t> load_test_bin(const std::string& name) {
    {
        std::ifstream f("tests/bins/" + name, std::ios::binary);
        if (f.good()) return {std::istreambuf_iterator<char>(f), {}};
    }
    std::vector<uint8_t> data;
#ifndef _WINDOWS
    std::string cmd = "xz -d -c tests/bins/" + name + ".xz 2>/dev/null";
    auto* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return {};
    char buf[4096];
    while (size_t n = std::fread(buf, 1, sizeof(buf), pipe))
        data.insert(data.end(), buf, buf + n);
    pclose(pipe);
#endif
    return data;
}
