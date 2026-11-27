#include "rl78dec/user_data.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>

namespace rl78dec {

namespace {

std::string trim_ws(const std::string &s) {
    size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

std::string to_lower(std::string s) {
    for (char &c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string hex_ea_lower(uint64_t ea) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(ea));
    return buf;
}

std::string json_escape(const std::string &s) {
    std::string out;
    out.reserve(s.size() + 4);
    out.push_back('"');
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned>(c));
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(c));
                }
                break;
        }
    }
    out.push_back('"');
    return out;
}

struct JVal {
    enum Type { Null, Bool, Int, Str, Arr, Obj } type = Null;
    bool bval = false;
    int64_t ival = 0;
    uint64_t uval = 0;
    std::string sval;
    std::vector<JVal> arr;
    std::unordered_map<std::string, JVal> obj;
};

class JParser {
public:
    explicit JParser(const std::string &src) : s_(src) {}

    bool parse(JVal &out) {
        skip_ws();
        if (!parse_val(out)) return false;
        skip_ws();
        return pos_ == s_.size();
    }

private:
    const std::string &s_;
    size_t pos_ = 0;

    void skip_ws() {
        while (pos_ < s_.size() && std::isspace(static_cast<unsigned char>(s_[pos_]))) ++pos_;
    }

    bool match(const char *kw) {
        size_t n = std::strlen(kw);
        if (pos_ + n <= s_.size() && s_.compare(pos_, n, kw) == 0) {
            pos_ += n;
            return true;
        }
        return false;
    }

    bool parse_str(std::string &out) {
        if (pos_ >= s_.size() || s_[pos_] != '"') return false;
        ++pos_;
        out.clear();
        while (pos_ < s_.size()) {
            char c = s_[pos_++];
            if (c == '"') return true;
            if (c == '\\') {
                if (pos_ >= s_.size()) return false;
                char esc = s_[pos_++];
                switch (esc) {
                    case '"':  out.push_back('"'); break;
                    case '\\': out.push_back('\\'); break;
                    case '/':  out.push_back('/'); break;
                    case 'b':  out.push_back('\b'); break;
                    case 'f':  out.push_back('\f'); break;
                    case 'n':  out.push_back('\n'); break;
                    case 'r':  out.push_back('\r'); break;
                    case 't':  out.push_back('\t'); break;
                    case 'u': {
                        if (pos_ + 4 > s_.size()) return false;
                        unsigned code = 0;
                        for (int i = 0; i < 4; ++i) {
                            char hc = s_[pos_++];
                            code <<= 4;
                            if (hc >= '0' && hc <= '9') code |= static_cast<unsigned>(hc - '0');
                            else if (hc >= 'a' && hc <= 'f') code |= static_cast<unsigned>(hc - 'a' + 10);
                            else if (hc >= 'A' && hc <= 'F') code |= static_cast<unsigned>(hc - 'A' + 10);
                            else return false;
                        }
                        if (code <= 0x7F) {
                            out.push_back(static_cast<char>(code));
                        } else if (code <= 0x7FF) {
                            out.push_back(static_cast<char>(0xC0 | ((code >> 6) & 0x1F)));
                            out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
                        } else {
                            out.push_back(static_cast<char>(0xE0 | ((code >> 12) & 0x0F)));
                            out.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
                            out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
                        }
                        break;
                    }
                    default:
                        out.push_back(esc);
                        break;
                }
            } else {
                out.push_back(c);
            }
        }
        return false;
    }

    bool parse_num(JVal &out) {
        size_t start = pos_;
        if (s_[pos_] == '-') ++pos_;
        if (pos_ >= s_.size() || !std::isdigit(static_cast<unsigned char>(s_[pos_]))) return false;
        while (pos_ < s_.size() && std::isdigit(static_cast<unsigned char>(s_[pos_]))) ++pos_;
        if (pos_ < s_.size() && s_[pos_] == '.') {
            ++pos_;
            while (pos_ < s_.size() && std::isdigit(static_cast<unsigned char>(s_[pos_]))) ++pos_;
        }
        if (pos_ < s_.size() && (s_[pos_] == 'e' || s_[pos_] == 'E')) {
            ++pos_;
            if (pos_ < s_.size() && (s_[pos_] == '+' || s_[pos_] == '-')) ++pos_;
            while (pos_ < s_.size() && std::isdigit(static_cast<unsigned char>(s_[pos_]))) ++pos_;
        }
        std::string tok = s_.substr(start, pos_ - start);
        out.type = JVal::Int;
        if (!tok.empty() && tok[0] == '-') {
            out.ival = std::strtoll(tok.c_str(), nullptr, 10);
            out.uval = static_cast<uint64_t>(out.ival);
        } else {
            out.uval = std::strtoull(tok.c_str(), nullptr, 10);
            out.ival = static_cast<int64_t>(out.uval);
        }
        return true;
    }

    bool parse_arr(JVal &out) {
        ++pos_;
        out.type = JVal::Arr;
        skip_ws();
        if (pos_ < s_.size() && s_[pos_] == ']') {
            ++pos_;
            return true;
        }
        while (pos_ < s_.size()) {
            skip_ws();
            JVal elem;
            if (!parse_val(elem)) return false;
            out.arr.push_back(std::move(elem));
            skip_ws();
            if (pos_ < s_.size() && s_[pos_] == ',') {
                ++pos_;
                continue;
            }
            if (pos_ < s_.size() && s_[pos_] == ']') {
                ++pos_;
                return true;
            }
            return false;
        }
        return false;
    }

    bool parse_obj(JVal &out) {
        ++pos_;
        out.type = JVal::Obj;
        skip_ws();
        if (pos_ < s_.size() && s_[pos_] == '}') {
            ++pos_;
            return true;
        }
        while (pos_ < s_.size()) {
            skip_ws();
            std::string key;
            if (!parse_str(key)) return false;
            skip_ws();
            if (pos_ >= s_.size() || s_[pos_] != ':') return false;
            ++pos_;
            skip_ws();
            JVal val;
            if (!parse_val(val)) return false;
            out.obj[std::move(key)] = std::move(val);
            skip_ws();
            if (pos_ < s_.size() && s_[pos_] == ',') {
                ++pos_;
                continue;
            }
            if (pos_ < s_.size() && s_[pos_] == '}') {
                ++pos_;
                return true;
            }
            return false;
        }
        return false;
    }

    bool parse_val(JVal &out) {
        skip_ws();
        if (pos_ >= s_.size()) return false;
        char c = s_[pos_];
        if (c == '"') {
            out.type = JVal::Str;
            return parse_str(out.sval);
        }
        if (c == '{') return parse_obj(out);
        if (c == '[') return parse_arr(out);
        if (c == '-' || std::isdigit(static_cast<unsigned char>(c))) return parse_num(out);
        if (match("true"))  { out.type = JVal::Bool; out.bval = true;  return true; }
        if (match("false")) { out.type = JVal::Bool; out.bval = false; return true; }
        if (match("null"))  { out.type = JVal::Null; return true; }
        return false;
    }
};

void serialize_str_map(std::ostringstream &os, const std::unordered_map<std::string, std::string> &m) {
    os << "{";
    std::vector<std::string> keys;
    keys.reserve(m.size());
    for (const auto &[k, _] : m) keys.push_back(k);
    std::sort(keys.begin(), keys.end());
    for (size_t i = 0; i < keys.size(); ++i) {
        if (i > 0) os << ", ";
        os << json_escape(keys[i]) << ": " << json_escape(m.at(keys[i]));
    }
    os << "}";
}

} // namespace

void FuncUserData::set_var_rename(const std::string &old_name, const std::string &new_name) {
    std::string canonical = old_name;
    for (const auto &[k, v] : renames) {
        if (v == old_name) {
            canonical = k;
            break;
        }
    }
    if (new_name.empty() || new_name == canonical) {
        renames.erase(canonical);
    } else {
        renames[canonical] = new_name;
    }
}

void FuncUserData::set_var_type(const std::string &var_name, const std::string &type_str) {
    std::string clean = trim_ws(type_str);
    if (clean.empty()) {
        types.erase(var_name);
    } else {
        types[var_name] = clean;
    }
}

void FuncUserData::set_func_proto(const std::string &proto_str) {
    std::string clean = trim_ws(proto_str);
    if (clean.empty()) proto = std::nullopt;
    else proto = clean;
}

void FuncUserData::set_line_comment(uint64_t key_ea, const std::string &cmt) {
    std::string key = hex_ea_lower(key_ea);
    std::string clean = trim_ws(cmt);
    if (clean.empty()) {
        comments.erase(key);
    } else {
        comments[key] = clean;
    }
}

void FuncUserData::set_numform(uint64_t stmt_ea, int op_idx, const std::string &form_str) {
    std::string key = hex_ea_lower(stmt_ea) + ":" + std::to_string(op_idx);
    std::string trimmed = trim_ws(form_str);
    std::string low = to_lower(trimmed);
    if (trimmed.empty() || low == "default") {
        numforms.erase(key);
        return;
    }
    if (low.rfind("enum:", 0) == 0) {
        std::string ename = trim_ws(trimmed.substr(5));
        if (ename.empty()) numforms.erase(key);
        else numforms[key] = "enum:" + ename;
    } else {
        numforms[key] = low;
    }
}

std::optional<std::string> FuncUserData::get_numform(uint64_t stmt_ea, int op_idx) const {
    std::string k1 = hex_ea_lower(stmt_ea) + ":" + std::to_string(op_idx);
    auto it = numforms.find(k1);
    if (it != numforms.end()) return it->second;
    std::string k2 = std::to_string(stmt_ea) + ":" + std::to_string(op_idx);
    it = numforms.find(k2);
    if (it != numforms.end()) return it->second;
    return std::nullopt;
}

bool FuncUserData::toggle_iflag(uint64_t branch_ea) {
    auto it = std::find(iflags.begin(), iflags.end(), branch_ea);
    if (it != iflags.end()) {
        iflags.erase(it);
        return false;
    }
    iflags.push_back(branch_ea);
    return true;
}

bool FuncUserData::is_iflag_inverted(uint64_t branch_ea) const {
    return std::find(iflags.begin(), iflags.end(), branch_ea) != iflags.end();
}

void FuncUserData::clear() {
    renames.clear();
    types.clear();
    proto.reset();
    lvars.clear();
    comments.clear();
    numforms.clear();
    iflags.clear();
}

bool parse_func_user_data_json(const std::string &json_text, FuncUserData &out) {
    out.clear();
    if (json_text.empty()) return false;
    JVal root;
    JParser parser(json_text);
    if (!parser.parse(root) || root.type != JVal::Obj) return false;

    auto read_smap = [&](const char *field, std::unordered_map<std::string, std::string> &dst) {
        auto it = root.obj.find(field);
        if (it == root.obj.end() || it->second.type != JVal::Obj) return;
        for (const auto &[k, v] : it->second.obj) {
            if (v.type == JVal::Str) dst[k] = v.sval;
        }
    };
    read_smap("renames", out.renames);
    read_smap("types", out.types);
    read_smap("cmts", out.comments);
    read_smap("comments", out.comments);
    read_smap("numforms", out.numforms);

    auto pit = root.obj.find("proto");
    if (pit != root.obj.end() && pit->second.type == JVal::Str && !pit->second.sval.empty()) {
        out.proto = pit->second.sval;
    }

    auto lit = root.obj.find("lvars");
    if (lit != root.obj.end() && lit->second.type == JVal::Obj) {
        for (const auto &[k, v] : lit->second.obj) {
            if (v.type != JVal::Obj) continue;
            LvarUserEntry ent;
            auto nit = v.obj.find("name");
            if (nit != v.obj.end() && nit->second.type == JVal::Str) ent.name = nit->second.sval;
            auto tit = v.obj.find("type");
            if (tit != v.obj.end() && tit->second.type == JVal::Str) ent.type = tit->second.sval;
            auto fit = v.obj.find("flags");
            if (fit != v.obj.end() && fit->second.type == JVal::Int) ent.flags = static_cast<int>(fit->second.ival);
            out.lvars[k] = std::move(ent);
        }
    }

    auto iit = root.obj.find("iflags");
    if (iit != root.obj.end() && iit->second.type == JVal::Arr) {
        for (const auto &el : iit->second.arr) {
            if (el.type == JVal::Int) {
                out.iflags.push_back(el.uval);
            } else if (el.type == JVal::Str) {
                int base = (el.sval.rfind("0x", 0) == 0 || el.sval.rfind("0X", 0) == 0) ? 16 : 10;
                out.iflags.push_back(std::strtoull(el.sval.c_str(), nullptr, base));
            }
        }
    }
    return true;
}

std::string serialize_func_user_data_json(const FuncUserData &data) {
    std::ostringstream os;
    os << "{\"renames\": ";
    serialize_str_map(os, data.renames);
    os << ", \"types\": ";
    serialize_str_map(os, data.types);
    os << ", \"proto\": ";
    if (data.proto.has_value() && !data.proto->empty()) os << json_escape(*data.proto);
    else os << "null";
    os << ", \"lvars\": {";
    {
        std::vector<std::string> keys;
        keys.reserve(data.lvars.size());
        for (const auto &[k, _] : data.lvars) keys.push_back(k);
        std::sort(keys.begin(), keys.end());
        for (size_t i = 0; i < keys.size(); ++i) {
            if (i > 0) os << ", ";
            const auto &ent = data.lvars.at(keys[i]);
            os << json_escape(keys[i]) << ": {";
            bool first = true;
            if (!ent.name.empty()) {
                os << "\"name\": " << json_escape(ent.name);
                first = false;
            }
            if (!ent.type.empty()) {
                if (!first) os << ", ";
                os << "\"type\": " << json_escape(ent.type);
                first = false;
            }
            if (ent.flags != 0) {
                if (!first) os << ", ";
                os << "\"flags\": " << ent.flags;
            }
            os << "}";
        }
    }
    os << "}, \"comments\": ";
    serialize_str_map(os, data.comments);
    os << ", \"numforms\": ";
    serialize_str_map(os, data.numforms);
    os << ", \"iflags\": [";
    for (size_t i = 0; i < data.iflags.size(); ++i) {
        if (i > 0) os << ", ";
        os << data.iflags[i];
    }
    os << "]}";
    return os.str();
}

bool parse_window_state_json(const std::string &json_text, WindowState &out) {
    out = WindowState{};
    if (json_text.empty()) return false;
    JVal root;
    JParser parser(json_text);
    if (!parser.parse(root) || root.type != JVal::Obj) return false;

    if (auto it = root.obj.find("is_open"); it != root.obj.end() && it->second.type == JVal::Bool)
        out.is_open = it->second.bval;
    if (auto it = root.obj.find("func_ea"); it != root.obj.end() && it->second.type == JVal::Int)
        out.func_ea = it->second.uval;
    if (auto it = root.obj.find("lineno"); it != root.obj.end() && it->second.type == JVal::Int)
        out.lineno = static_cast<int>(it->second.ival);
    if (auto it = root.obj.find("col"); it != root.obj.end() && it->second.type == JVal::Int)
        out.col = static_cast<int>(it->second.ival);
    if (auto it = root.obj.find("mode"); it != root.obj.end() && it->second.type == JVal::Str)
        out.mode = it->second.sval;
    return true;
}

std::string serialize_window_state_json(const WindowState &st) {
    std::ostringstream os;
    os << "{\"is_open\": " << (st.is_open ? "true" : "false")
       << ", \"func_ea\": ";
    if (st.func_ea.has_value()) os << *st.func_ea;
    else os << "null";
    os << ", \"lineno\": " << st.lineno
       << ", \"col\": " << st.col
       << ", \"mode\": " << json_escape(st.mode) << "}";
    return os.str();
}

} // namespace rl78dec
