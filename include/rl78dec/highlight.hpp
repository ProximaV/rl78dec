#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace rl78dec {

inline constexpr char RL78_SCOLOR_DEFAULT  = '\x01';
inline constexpr char RL78_SCOLOR_REGCMT   = '\x02';
inline constexpr char RL78_SCOLOR_RPTCMT   = '\x03';
inline constexpr char RL78_SCOLOR_AUTOCMT  = '\x04';
inline constexpr char RL78_SCOLOR_INSN     = '\x05';
inline constexpr char RL78_SCOLOR_DATNAME  = '\x06';
inline constexpr char RL78_SCOLOR_DNAME    = '\x07';
inline constexpr char RL78_SCOLOR_DEMNAME  = '\x08';
inline constexpr char RL78_SCOLOR_SYMBOL   = '\x09';
inline constexpr char RL78_SCOLOR_CHAR     = '\x0A';
inline constexpr char RL78_SCOLOR_STRING   = '\x0B';
inline constexpr char RL78_SCOLOR_NUMBER   = '\x0C';
inline constexpr char RL78_SCOLOR_VOIDOP   = '\x0D';
inline constexpr char RL78_SCOLOR_CREF     = '\x0E';
inline constexpr char RL78_SCOLOR_DREF     = '\x0F';
inline constexpr char RL78_SCOLOR_CREFTAIL = '\x10';
inline constexpr char RL78_SCOLOR_DREFTAIL = '\x11';
inline constexpr char RL78_SCOLOR_ERROR    = '\x12';
inline constexpr char RL78_SCOLOR_PREFIX   = '\x13';
inline constexpr char RL78_SCOLOR_BINPREF  = '\x14';
inline constexpr char RL78_SCOLOR_EXTRA    = '\x15';
inline constexpr char RL78_SCOLOR_ALTOP    = '\x16';
inline constexpr char RL78_SCOLOR_HIDNAME  = '\x17';
inline constexpr char RL78_SCOLOR_LIBNAME  = '\x18';
inline constexpr char RL78_SCOLOR_LOCNAME  = '\x19';
inline constexpr char RL78_SCOLOR_CODNAME  = '\x1A';
inline constexpr char RL78_SCOLOR_ASMDIR   = '\x1B';
inline constexpr char RL78_SCOLOR_MACRO    = '\x1C';
inline constexpr char RL78_SCOLOR_DSTR     = '\x1D';
inline constexpr char RL78_SCOLOR_DCHAR    = '\x1E';
inline constexpr char RL78_SCOLOR_DNUM     = '\x1F';
inline constexpr char RL78_SCOLOR_KEYWORD  = '\x20';
inline constexpr char RL78_SCOLOR_REG      = '\x21';
inline constexpr char RL78_SCOLOR_IMPNAME  = '\x22';
inline constexpr char RL78_SCOLOR_SEGNAME  = '\x23';
inline constexpr char RL78_SCOLOR_UNKNAME  = '\x24';
inline constexpr char RL78_SCOLOR_CNAME    = '\x25';
inline constexpr char RL78_SCOLOR_UNAME    = '\x26';
inline constexpr char RL78_SCOLOR_COLLAPSED= '\x27';
inline constexpr char RL78_SCOLOR_ADDR     = '\x28';

inline constexpr char RL78_COLOR_ON_CH   = '\x01';
inline constexpr char RL78_COLOR_OFF_CH  = '\x02';
inline constexpr char RL78_COLOR_ADDR_CH = '\x28';
inline constexpr int  RL78_COLOR_ADDR_SZ = 16;

std::string colorize_c_line(const std::string &line, const std::string &highlight_ident = "");
std::string make_color_addr_tag(uint64_t ea);
std::string prepend_addr_tag(const std::string &colored_line, std::optional<uint64_t> ea);
std::string strip_color_tags(const std::string &tagged);
std::optional<uint64_t> extract_line_addr_tag(const std::string &tagged);

} // namespace rl78dec
