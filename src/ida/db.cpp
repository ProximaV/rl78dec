#include <ida.hpp>
#include <netnode.hpp>

#include "db.hpp"

namespace rl78dec {
namespace idadb {

namespace {

constexpr const char *BLOB_SENTINEL = "__RL78DEC_BLOB_V1__";
constexpr uchar BLOB_TAG = 'B';

WindowState g_mem_win_state;
bool g_has_mem_win_state = false;

netnode get_or_create_node() {
    netnode node;
    node.create(RL78DEC_NODE_NAME);
    return node;
}

std::optional<std::string> read_node_str(uint64_t key) {
    if (!netnode_inited()) return std::nullopt;
    netnode node(RL78DEC_NODE_NAME);
    if (node == BADNODE) return std::nullopt;

    qstring qval;
    if (node.supstr(&qval, static_cast<nodeidx_t>(key)) < 0) {
        return std::nullopt;
    }
    if (qval == BLOB_SENTINEL) {
        bytevec_t blob;
        if (netnode_qgetblob(node, &blob, 1, static_cast<nodeidx_t>(key << 8), BLOB_TAG) > 0) {
            size_t len = blob.size();
            while (len > 0 && blob[len - 1] == 0) --len;
            return std::string(reinterpret_cast<const char *>(blob.begin()), len);
        }
        return std::nullopt;
    }
    return std::string(qval.c_str(), qval.length());
}

void write_node_str(uint64_t key, const std::string &val) {
    if (!netnode_inited()) return;
    netnode node = get_or_create_node();
    if (node == BADNODE) return;

    if (val.size() + 1 <= MAXSPECSIZE) {
        node.delblob(static_cast<nodeidx_t>(key << 8), BLOB_TAG);
        node.supset(static_cast<nodeidx_t>(key), val.c_str(), val.size() + 1);
    } else {
        node.setblob(val.c_str(), val.size() + 1, static_cast<nodeidx_t>(key << 8), BLOB_TAG);
        node.supset(static_cast<nodeidx_t>(key), BLOB_SENTINEL);
    }
}

} // namespace

FuncUserData get_func_data(uint64_t func_ea) {
    FuncUserData out;
    if (auto raw = read_node_str(func_ea); raw.has_value()) {
        parse_func_user_data_json(*raw, out);
    }
    return out;
}

void set_func_data(uint64_t func_ea, const FuncUserData &data) {
    write_node_str(func_ea, serialize_func_user_data_json(data));
}

void set_var_rename(uint64_t func_ea, const std::string &old_name, const std::string &new_name) {
    auto d = get_func_data(func_ea);
    d.set_var_rename(old_name, new_name);
    set_func_data(func_ea, d);
}

void set_var_type(uint64_t func_ea, const std::string &var_name, const std::string &type_str) {
    auto d = get_func_data(func_ea);
    d.set_var_type(var_name, type_str);
    set_func_data(func_ea, d);
}

void set_var_locator(uint64_t func_ea, const std::string &locator,
                     const std::optional<std::string> &name,
                     const std::optional<std::string> &type_str,
                     int flags) {
    auto d = get_func_data(func_ea);
    auto &ent = d.lvars[locator];
    if (name.has_value()) ent.name = *name;
    if (type_str.has_value()) ent.type = *type_str;
    if (flags != 0) ent.flags = flags;
    if (ent.name.empty() && ent.type.empty() && ent.flags == 0) d.lvars.erase(locator);
    set_func_data(func_ea, d);
}

void set_statement_cmt(uint64_t func_ea, uint64_t stmt_ea, const std::string &cmt_str) {
    auto d = get_func_data(func_ea);
    d.set_line_comment(stmt_ea, cmt_str);
    set_func_data(func_ea, d);
}

std::optional<std::string> get_statement_cmt(uint64_t func_ea, uint64_t stmt_ea) {
    auto d = get_func_data(func_ea);
    char k1[32];
    std::snprintf(k1, sizeof(k1), "0x%llx", static_cast<unsigned long long>(stmt_ea));
    if (auto it = d.comments.find(k1); it != d.comments.end()) return it->second;
    std::string k2 = std::to_string(stmt_ea);
    if (auto it = d.comments.find(k2); it != d.comments.end()) return it->second;
    return std::nullopt;
}

void set_numform(uint64_t func_ea, uint64_t stmt_ea, int op_idx, const std::string &form_str) {
    auto d = get_func_data(func_ea);
    d.set_numform(stmt_ea, op_idx, form_str);
    set_func_data(func_ea, d);
}

std::optional<std::string> get_numform(uint64_t func_ea, uint64_t stmt_ea, int op_idx) {
    return get_func_data(func_ea).get_numform(stmt_ea, op_idx);
}

void clear_func_overrides(uint64_t func_ea) {
    FuncUserData empty;
    set_func_data(func_ea, empty);
}

bool toggle_iflag(uint64_t func_ea, uint64_t branch_ea) {
    auto d = get_func_data(func_ea);
    bool inv = d.toggle_iflag(branch_ea);
    set_func_data(func_ea, d);
    return inv;
}

bool is_iflag_inverted(uint64_t func_ea, uint64_t branch_ea) {
    return get_func_data(func_ea).is_iflag_inverted(branch_ea);
}

void set_func_proto(uint64_t func_ea, const std::string &proto_str) {
    auto d = get_func_data(func_ea);
    d.set_func_proto(proto_str);
    set_func_data(func_ea, d);
}

bool get_sync_enabled() {
    if (!netnode_inited()) return true;
    netnode node(RL78DEC_NODE_NAME);
    if (node == BADNODE) return true;
    sval_t v = node.altval(0);
    return v == 0 ? true : (v > 0);
}

void set_sync_enabled(bool enabled) {
    if (!netnode_inited()) return;
    netnode node = get_or_create_node();
    if (node == BADNODE) return;
    node.altset(0, enabled ? 1 : -1);
}

bool get_hide_casts() {
    if (!netnode_inited()) return false;
    netnode node(RL78DEC_NODE_NAME);
    if (node == BADNODE) return false;
    return node.altval(1) > 0;
}

void set_hide_casts(bool enabled) {
    if (!netnode_inited()) return;
    netnode node = get_or_create_node();
    if (node == BADNODE) return;
    node.altset(1, enabled ? 1 : 0);
}

void save_window_state(bool is_open, std::optional<uint64_t> func_ea,
                       int lineno, int col, const std::string &mode, bool persist) {
    g_mem_win_state.is_open = is_open;
    g_mem_win_state.func_ea = func_ea;
    g_mem_win_state.lineno = lineno;
    g_mem_win_state.col = col;
    g_mem_win_state.mode = mode.empty() ? "c" : mode;
    g_has_mem_win_state = true;
    if (persist) {
        write_node_str(RL78DEC_WIN_STATE_KEY, serialize_window_state_json(g_mem_win_state));
    }
}

WindowState load_window_state() {
    if (g_has_mem_win_state) return g_mem_win_state;
    WindowState ws;
    if (auto raw = read_node_str(RL78DEC_WIN_STATE_KEY); raw.has_value()) {
        parse_window_state_json(*raw, ws);
    }
    return ws;
}

void clear_all() {
    g_mem_win_state = WindowState{};
    g_has_mem_win_state = false;
    if (!netnode_inited()) return;
    netnode node(RL78DEC_NODE_NAME);
    if (node != BADNODE) node.kill();
}

} // namespace idadb
} // namespace rl78dec
