#include "rl78dec/loader.hpp"

#include <cstring>
#include <fstream>
#include <unordered_set>

namespace rl78dec {

bool is_fupd(const std::vector<uint8_t> &data) {
    if (data.size() < 0x14) return false;
    return std::memcmp(&data[0x10], "PTCH", 4) == 0 ||
           std::memcmp(&data[0x10], "BLNK", 4) == 0 ||
           std::memcmp(&data[0x10], "BASE", 4) == 0 ||
           std::memcmp(&data[0x10], "SYST", 4) == 0;
}

std::vector<uint8_t> load_fupd(const std::vector<uint8_t> &data) {
    bool is_patch = data.size() >= 0x14 && std::memcmp(&data[0x10], "PTCH", 4) == 0;
    uint32_t n_blocks = data.size() > 0x15 ? data[0x15] : 0;
    std::vector<uint8_t> image(0x60000u, 0);
    for (uint32_t i = 0; i < n_blocks; ++i) {
        size_t hdr_off = 0x20u + 8u * i;
        if (hdr_off + 6u > data.size()) break;
        uint32_t off   = data[hdr_off] | (data[hdr_off + 1] << 8);
        uint32_t size  = data[hdr_off + 2] | (data[hdr_off + 3] << 8);
        uint32_t flash = data[hdr_off + 4] | (data[hdr_off + 5] << 8);
        off = (off << 8) + (is_patch ? 0x400u : 0x110u);
        size <<= 8;
        flash <<= 8;
        if (is_patch && flash == 0) flash = 0x1000u;
        if (off >= data.size()) continue;
        size_t avail = std::min<size_t>(size, data.size() - off);
        if (flash + avail <= image.size()) {
            std::memcpy(&image[flash], &data[off], avail);
        }
    }
    return image;
}

std::vector<uint8_t> load_file(const std::string &path, std::string *out_error) {
    std::ifstream fp(path, std::ios::binary | std::ios::ate);
    if (!fp) {
        if (out_error) *out_error = "Cannot open file: " + path;
        return {};
    }
    auto sz = fp.tellg();
    fp.seekg(0, std::ios::beg);
    std::vector<uint8_t> data(static_cast<size_t>(sz));
    if (sz > 0 && !fp.read(reinterpret_cast<char *>(data.data()), sz)) {
        if (out_error) *out_error = "Failed reading file: " + path;
        return {};
    }
    if (is_fupd(data)) return load_fupd(data);
    return data;
}

std::vector<uint32_t> vector_entries(const std::vector<uint8_t> &image) {
    std::vector<uint32_t> out;
    std::unordered_set<uint32_t> seen;
    size_t limit = image.size() > 1 ? std::min<size_t>(VECTOR_TABLE_SIZE, image.size() - 1) : 0;
    for (size_t off = 0; off < limit; off += 2) {
        uint32_t v = static_cast<uint32_t>(image[off]) | (static_cast<uint32_t>(image[off + 1]) << 8);
        if (v > 0 && v < CODE_LIMIT && v != 0xFFFFu && seen.insert(v).second) {
            out.push_back(v);
        }
    }
    return out;
}

} // namespace rl78dec
