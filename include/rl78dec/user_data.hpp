#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace rl78dec {

struct LvarUserEntry {
    std::string name;
    std::string type;
    int flags = 0;
};

// Persisted in IDA netnode "$ rl78dec" supstr(func_ea).
struct FuncUserData {
    std::unordered_map<std::string, std::string> renames;
    std::unordered_map<std::string, std::string> types;
    std::optional<std::string> proto;
    std::unordered_map<std::string, LvarUserEntry> lvars;
    std::unordered_map<std::string, std::string> comments;
    std::unordered_map<std::string, std::string> numforms;
    std::vector<uint64_t> iflags;

    void set_var_rename(const std::string &old_name, const std::string &new_name);
    void set_var_type(const std::string &var_name, const std::string &type_str);
    void set_func_proto(const std::string &proto_str);
    void set_line_comment(uint64_t key_ea, const std::string &cmt);
    void set_numform(uint64_t stmt_ea, int op_idx, const std::string &form_str);
    std::optional<std::string> get_numform(uint64_t stmt_ea, int op_idx = 0) const;
    bool toggle_iflag(uint64_t branch_ea);
    bool is_iflag_inverted(uint64_t branch_ea) const;
    void clear();
};

struct WindowState {
    bool is_open = false;
    std::optional<uint64_t> func_ea;
    int lineno = 0;
    int col = 0;
    std::string mode = "c";
};

inline constexpr uint64_t RL78DEC_WIN_STATE_KEY = 0x7FFFFFFFULL;

bool parse_func_user_data_json(const std::string &json_text, FuncUserData &out);
std::string serialize_func_user_data_json(const FuncUserData &data);

bool parse_window_state_json(const std::string &json_text, WindowState &out);
std::string serialize_window_state_json(const WindowState &st);

} // namespace rl78dec
