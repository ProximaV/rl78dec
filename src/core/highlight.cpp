#include "rl78dec/highlight.hpp"

#include <cctype>
#include <cstdio>
#include <unordered_set>

namespace rl78dec {

namespace {

const std::unordered_set<std::string> &c_keywords() {
    static const std::unordered_set<std::string> kws = {
        "void", "int", "unsigned", "signed", "char", "short", "long",
        "uint8_t", "uint16_t", "uint32_t", "int8_t", "int16_t", "int32_t",
        "uint", "ushort", "uchar", "if", "else", "while", "do", "for",
        "switch", "case", "default", "break", "continue", "return", "goto",
        "sizeof", "volatile", "const", "struct", "union", "enum", "typedef",
        "__far", "__near", "__interrupt", "__saddr", "__sfr", "__boolean"
    };
    return kws;
}

bool is_ident_start(char c) {
    return std::isalpha(static_cast<unsigned char>(c)) || c == '_';
}

bool is_ident_char(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '_';
}

void wrap(std::string &out, char color, const std::string &tok) {
    out.push_back(RL78_COLOR_ON_CH);
    out.push_back(color);
    out += tok;
    out.push_back(RL78_COLOR_OFF_CH);
    out.push_back(color);
}

} // namespace

std::string colorize_c_line(const std::string &line, const std::string &highlight_ident) {
    std::string out;
    out.reserve(line.size() * 2);

    size_t i = 0;
    size_t n = line.size();
    while (i < n) {
        char c = line[i];

        // Line comment // ...
        if (c == '/' && i + 1 < n && line[i + 1] == '/') {
            wrap(out, RL78_SCOLOR_AUTOCMT, line.substr(i));
            break;
        }

        // String / char literal
        if (c == '"' || c == '\'') {
            char quote = c;
            size_t j = i + 1;
            while (j < n) {
                if (line[j] == '\\' && j + 1 < n) {
                    j += 2;
                    continue;
                }
                if (line[j] == quote) {
                    ++j;
                    break;
                }
                ++j;
            }
            wrap(out, (quote == '"') ? RL78_SCOLOR_STRING : RL78_SCOLOR_CHAR, line.substr(i, j - i));
            i = j;
            continue;
        }

        // Numbers (hex or decimal)
        if (std::isdigit(static_cast<unsigned char>(c))) {
            size_t j = i + 1;
            while (j < n && (std::isxdigit(static_cast<unsigned char>(line[j])) ||
                             line[j] == 'x' || line[j] == 'X' ||
                             line[j] == 'u' || line[j] == 'U' ||
                             line[j] == 'l' || line[j] == 'L')) {
                ++j;
            }
            wrap(out, RL78_SCOLOR_NUMBER, line.substr(i, j - i));
            i = j;
            continue;
        }

        // Identifiers / keywords
        if (is_ident_start(c)) {
            size_t j = i + 1;
            while (j < n && is_ident_char(line[j])) ++j;
            std::string tok = line.substr(i, j - i);

            size_t k = j;
            while (k < n && line[k] == ' ') ++k;
            bool next_lparen = (k < n && line[k] == '(');
            bool next_colon = (k < n && line[k] == ':' && (k + 1 >= n || line[k + 1] != ':'));

            char col = RL78_SCOLOR_DEFAULT;
            if (!highlight_ident.empty() && tok == highlight_ident) {
                col = RL78_SCOLOR_CREF;
            } else if (c_keywords().count(tok)) {
                col = RL78_SCOLOR_KEYWORD;
            } else if (next_colon) {
                col = RL78_SCOLOR_LOCNAME;
            } else if (next_lparen) {
                if (tok.rfind("__rl78_", 0) == 0) {
                    col = RL78_SCOLOR_MACRO;
                } else {
                    col = RL78_SCOLOR_CODNAME;
                }
            } else if (tok.rfind("sub_", 0) == 0 || tok.rfind("loc_", 0) == 0) {
                col = RL78_SCOLOR_CODNAME;
            } else if (tok.rfind("g_", 0) == 0 || tok.rfind("sfr_", 0) == 0 ||
                       tok.rfind("saddr_", 0) == 0 || tok.rfind("mem", 0) == 0) {
                col = RL78_SCOLOR_DNAME;
            } else if (tok.rfind("a", 0) == 0 && tok.size() >= 2 && std::isdigit(static_cast<unsigned char>(tok[1]))) {
                col = RL78_SCOLOR_REG;
            } else {
                col = RL78_SCOLOR_DEFAULT;
            }

            if (col == RL78_SCOLOR_DEFAULT) {
                out += tok;
            } else {
                wrap(out, col, tok);
            }
            i = j;
            continue;
        }

        // Operators / punctuation
        if (!std::isspace(static_cast<unsigned char>(c))) {
            wrap(out, RL78_SCOLOR_SYMBOL, std::string(1, c));
        } else {
            out.push_back(c);
        }
        ++i;
    }

    return out;
}

std::string make_color_addr_tag(uint64_t ea) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%c%c%016llX",
                  RL78_COLOR_ON_CH, RL78_COLOR_ADDR_CH,
                  static_cast<unsigned long long>(ea));
    return std::string(buf);
}

std::string prepend_addr_tag(const std::string &colored_line, std::optional<uint64_t> ea) {
    if (!ea.has_value()) return colored_line;
    return make_color_addr_tag(*ea) + colored_line;
}

std::string strip_color_tags(const std::string &tagged) {
    std::string out;
    out.reserve(tagged.size());
    size_t i = 0;
    size_t n = tagged.size();
    while (i < n) {
        char c = tagged[i];
        if (c == RL78_COLOR_ON_CH && i + 1 < n) {
            char col = tagged[i + 1];
            i += 2;
            if (col == RL78_COLOR_ADDR_CH) {
                i += RL78_COLOR_ADDR_SZ;
                if (i > n) i = n;
            }
            continue;
        }
        if (c == RL78_COLOR_OFF_CH && i + 1 < n) {
            i += 2;
            continue;
        }
        out.push_back(c);
        ++i;
    }
    return out;
}

std::optional<uint64_t> extract_line_addr_tag(const std::string &tagged) {
    if (tagged.size() < 2 + RL78_COLOR_ADDR_SZ) return std::nullopt;
    if (tagged[0] == RL78_COLOR_ON_CH && tagged[1] == RL78_COLOR_ADDR_CH) {
        uint64_t v = 0;
        for (int i = 0; i < RL78_COLOR_ADDR_SZ; ++i) {
            char hc = tagged[2 + i];
            v <<= 4;
            if (hc >= '0' && hc <= '9') v |= static_cast<uint64_t>(hc - '0');
            else if (hc >= 'a' && hc <= 'f') v |= static_cast<uint64_t>(hc - 'a' + 10);
            else if (hc >= 'A' && hc <= 'F') v |= static_cast<uint64_t>(hc - 'A' + 10);
            else return std::nullopt;
        }
        return v;
    }
    return std::nullopt;
}

} // namespace rl78dec
