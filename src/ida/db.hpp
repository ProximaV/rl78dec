#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "rl78dec/user_data.hpp"

namespace rl78dec {
namespace idadb {

inline constexpr const char *RL78DEC_NODE_NAME = "$ rl78dec";

FuncUserData get_func_data(uint64_t func_ea);
void set_func_data(uint64_t func_ea, const FuncUserData &data);

void set_var_rename(uint64_t func_ea, const std::string &old_name, const std::string &new_name);
void set_var_type(uint64_t func_ea, const std::string &var_name, const std::string &type_str);
void set_var_locator(uint64_t func_ea, const std::string &locator,
                     const std::optional<std::string> &name = std::nullopt,
                     const std::optional<std::string> &type_str = std::nullopt,
                     int flags = 0);
void set_statement_cmt(uint64_t func_ea, uint64_t stmt_ea, const std::string &cmt_str);
std::optional<std::string> get_statement_cmt(uint64_t func_ea, uint64_t stmt_ea);
void set_numform(uint64_t func_ea, uint64_t stmt_ea, int op_idx, const std::string &form_str);
std::optional<std::string> get_numform(uint64_t func_ea, uint64_t stmt_ea, int op_idx = 0);
void clear_func_overrides(uint64_t func_ea);
bool toggle_iflag(uint64_t func_ea, uint64_t branch_ea);
bool is_iflag_inverted(uint64_t func_ea, uint64_t branch_ea);
void set_func_proto(uint64_t func_ea, const std::string &proto_str);

bool get_sync_enabled();
void set_sync_enabled(bool enabled);

bool get_hide_casts();
void set_hide_casts(bool enabled);

void save_window_state(bool is_open, std::optional<uint64_t> func_ea = std::nullopt,
                       int lineno = 0, int col = 0, const std::string &mode = "c",
                       bool persist = true);
WindowState load_window_state();

void clear_all();

} // namespace idadb
} // namespace rl78dec
