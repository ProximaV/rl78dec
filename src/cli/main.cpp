#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "rl78dec/database.hpp"
#include "rl78dec/loader.hpp"
#include "rl78dec/pipeline.hpp"

int main(int argc, char **argv) {
    if (argc < 2) {
        std::fprintf(stderr, "Usage: rl78dec_cli <firmware.bin|fupd> [--ea 0xADDR] [-o out.c] [--ir]\n");
        return 1;
    }

    std::string input_path = argv[1];
    std::vector<uint32_t> entries;
    std::string out_path;
    bool dump_ir = false;

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--ea" && i + 1 < argc) {
            uint32_t ea = static_cast<uint32_t>(std::strtoul(argv[++i], nullptr, 0));
            entries.push_back(ea);
        } else if (arg == "-o" && i + 1 < argc) {
            out_path = argv[++i];
        } else if (arg == "--ir") {
            dump_ir = true;
        }
    }

    std::string err;
    std::vector<uint8_t> image = rl78dec::load_file(input_path, &err);
    if (!err.empty() || image.empty()) {
        std::fprintf(stderr, "Failed to load %s: %s\n", input_path.c_str(), err.c_str());
        return 1;
    }

    rl78dec::MemoryDatabaseProvider db(image.size(), 0);
    db.write_bytes(0, image);

    if (entries.empty()) {
        entries = rl78dec::vector_entries(image);
        if (entries.empty()) entries.push_back(0);
    }

    rl78dec::DecompileOptions opts;
    opts.verify_ir = true;
    auto img_res = rl78dec::decompile_image(db, entries, opts);

    std::string output;
    if (dump_ir) {
        for (const auto &[fea, fres] : img_res.funcs) {
            output += fres.ir_dump + "\n\n";
        }
    } else {
        output = img_res.listing_text;
    }

    if (!out_path.empty()) {
        std::ofstream ofs(out_path, std::ios::binary);
        ofs << output;
    } else {
        std::cout << output << "\n";
    }
    return img_res.errors.empty() ? 0 : 2;
}
