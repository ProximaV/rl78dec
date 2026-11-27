#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace rl78dec {

inline constexpr uint32_t VECTOR_TABLE_SIZE = 0x80;
inline constexpr uint32_t CODE_LIMIT = 0x80000;

bool is_fupd(const std::vector<uint8_t> &data);
std::vector<uint8_t> load_fupd(const std::vector<uint8_t> &data);
std::vector<uint8_t> load_file(const std::string &path, std::string *out_error = nullptr);
std::vector<uint32_t> vector_entries(const std::vector<uint8_t> &image);

} // namespace rl78dec
