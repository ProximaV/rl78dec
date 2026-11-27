#include "rl78dec/sfr.hpp"

#include <cstdio>
#include <unordered_map>

namespace rl78dec {

namespace {

const char *kSfrBytes[256] = {
    "P0", "P1", "P2", "P3", "P4", "P5", "P6", "P7",
    "P8", "P9", "P10", "P11", "P12", "P13", "P14", "P15",
    "TXD0", nullptr, "RXD0", nullptr, "TXD3", nullptr, "RXD3", nullptr,
    nullptr, nullptr, "TDR01L", "TDR01H", nullptr, nullptr, nullptr, "ADCRH",
    "PM0", "PM1", "PM2", "PM3", "PM4", "PM5", "PM6", "PM7",
    "PM8", "PM9", "PM10", "PM11", "PM12", nullptr, "PM14", "PM15",
    "ADM0", "ADS", "ADM1", nullptr, nullptr, nullptr, nullptr, "KRM",
    "EGP0", "EGN0", "EGP1", "EGN1", nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr, nullptr, "TXD1", nullptr, "RXD1", nullptr,
    "TXD2", nullptr, "RXD2", nullptr, nullptr, nullptr, nullptr, nullptr,
    "IICA0", "IICS0", "IICF0", nullptr, "IICA1", "IICS1", "IICF1", nullptr,
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, "TDR03L", "TDR03H",
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, "TDR11L", "TDR11H", nullptr, nullptr, "TDR13L", "TDR13H",
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, "SEC", "MIN", "HOUR", "WEEK", "DAY", "MONTH",
    "YEAR", "SUBCUD", "ALARMWM", "ALARMWH", "ALARMWW", "RTCC0", "RTCC1", nullptr,
    "CMC", "CSC", "OSTC", "OSTS", "CKC", "CKS0", "CKS1", nullptr,
    "RESF", "LVIM", "LVIS", "WDTE", "CRCIN", "TOOL0", nullptr, nullptr,
    "DSA0", "DSA1", "DRA0L", "DRA0H", "DRA1L", "DRA1H", "DBC0L", "DBC0H",
    "DMC0", "DMC1", "DRC0", "DRC1", nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    "IF2L", "IF2H", "IF3L", nullptr, "MK2L", "MK2H", "MK3L", nullptr,
    "PR02L", "PR02H", "PR03L", nullptr, "PR12L", "PR12H", "PR13L", nullptr,
    "IF0L", "IF0H", "IF1L", "IF1H", "MK0L", "MK0H", "MK1L", "MK1H",
    "PR00L", "PR00H", "PR01L", "PR01H", "PR10L", "PR10H", "PR11L", "PR11H",
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr, "RESERVE", nullptr, nullptr, "PMC", "MEM",
};

} // namespace

std::optional<std::string> sfr_name_for(uint32_t addr) {
    if (addr < 0xFFF00u || addr > 0xFFFFFu) return std::nullopt;
    const char *n = kSfrBytes[addr - 0xFFF00u];
    if (!n) return std::nullopt;
    return std::string(n);
}

std::optional<uint32_t> sfr_addr_for(const std::string &name) {
    static const std::unordered_map<std::string, uint32_t> kRev = []() {
        std::unordered_map<std::string, uint32_t> m;
        for (uint32_t i = 0; i < 256; ++i) {
            if (kSfrBytes[i]) m[kSfrBytes[i]] = 0xFFF00u + i;
        }
        return m;
    }();
    auto it = kRev.find(name);
    if (it == kRev.end()) return std::nullopt;
    return it->second;
}

std::string default_cell_name(uint32_t addr) {
    if (auto s = sfr_name_for(addr); s.has_value()) return *s;
    char buf[32];
    if (addr >= 0xFFE20u && addr <= 0xFFF1Fu) {
        std::snprintf(buf, sizeof(buf), "saddr_%02X", addr & 0xFFu);
        return buf;
    }
    if (addr >= 0xF0000u) {
        std::snprintf(buf, sizeof(buf), "ram_%04X", addr & 0xFFFFu);
        return buf;
    }
    std::snprintf(buf, sizeof(buf), "m_%05X", addr);
    return buf;
}

} // namespace rl78dec
