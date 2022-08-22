#undef NDEBUG
#include <cassert>
#include <cstdlib>
#include <dlfcn.h>
#include <optional>
#include <string>
#include <vector>

#include <LIEF/MachO.hpp>
#include <LIEF/logging.hpp>
#include <argparse/argparse.hpp>
#include <fmt/format.h>

using namespace LIEF::MachO;

static bool dylib_exists(const std::string &dylib_path) {
    if (auto *handle = dlopen(dylib_path.c_str(), RTLD_LAZY | RTLD_LOCAL)) {
        dlclose(handle);
        return true;
    } else {
        return false;
    }
}

static void dylibify(const std::string &in_path, const std::string &out_path,
                     const std::optional<std::string> dylib_path,
                     const std::vector<std::string> remove_dylibs,
                     const bool auto_remove_dylibs = false, const bool remove_info_plist = false,
                     const bool ios = false, const bool macos = false, const bool verbose = false) {
    assert(!(ios && macos));

    if (verbose) {
        LIEF::logging::set_level(LIEF::logging::LOGGING_LEVEL::LOG_TRACE);
    }

    std::unique_ptr<FatBinary> binaries = Parser::parse(in_path);

    for (Binary &binary : *binaries) {
        auto &hdr = binary.header();
        assert(hdr.file_type() == FILE_TYPES::MH_EXECUTE);
        if (verbose) {
            fmt::print("[-] Changing Mach-O type from executable to dylib\n");
        }
        hdr.file_type(FILE_TYPES::MH_DYLIB);
        if (verbose) {
            fmt::print("[-] Adding NO_REXPORTED_LIBS flag\n");
        }
        hdr.flags(hdr.flags() | (uint32_t)HEADER_FLAGS::MH_NO_REEXPORTED_DYLIBS);

        if (binary.code_signature()) {
            if (verbose) {
                fmt::print("[-] Removing code signature\n");
            }
            assert(binary.remove_signature());
        }

        if (remove_info_plist) {
            if (const auto *plist_sect = binary.get_section("__TEXT", "__info_plist")) {
                if (verbose) {
                    fmt::print("[-] Removing __TEXT,__info_plist\n");
                }
                binary.remove_section("__TEXT", "__info_plist", true);
            }
        }
    }

    binaries->write(out_path);
}

int main(int argc, const char **argv) {
    argparse::ArgumentParser parser(getprogname());
    parser.add_argument("-i", "--in").required().help("input Mach-O executable");
    parser.add_argument("-o", "--out").required().help("output Mach-O dylib");
    parser.add_argument("-d", "--dylib-path")
        .help("path for LC_ID_DYLIB command. e.g. @executable_path/Frameworks/libfoo.dylib");
    parser.add_argument("-r", "--remove-dylib")
        .nargs(argparse::nargs_pattern::any)
        .help("remove dylib dependency");
    parser.add_argument("-R", "--auto-remove-dylibs")
        .default_value(false)
        .implicit_value(true)
        .help("automatically remove unavailable dylib dependencies");
    parser.add_argument("-P", "--remove-info-plist")
        .default_value(false)
        .implicit_value(true)
        .help("remove __info_plist section");
    parser.add_argument("-I", "--ios")
        .default_value(false)
        .implicit_value(true)
        .help("patch platform to iOS");
    parser.add_argument("-M", "--macos")
        .default_value(false)
        .implicit_value(true)
        .help("patch platform to macOS");
    parser.add_argument("-V", "--verbose")
        .default_value(false)
        .implicit_value(true)
        .help("verbose mode");

    try {
        parser.parse_args(argc, argv);
    } catch (const std::runtime_error &err) {
        fmt::print(stderr, "Error parsing arguments: {:s}\n", err.what());
        return -1;
    }

    dylibify(parser.get<std::string>("--in"), parser.get<std::string>("--out"),
             parser.present("--dylib-path"), parser.get<std::vector<std::string>>("--remove-dylib"),
             parser.get<bool>("--auto-remove-dylibs"), parser.get<bool>("--remove-info-plist"),
             parser.get<bool>("--ios"), parser.get<bool>("--macos"), parser.get<bool>("--verbose"));

    return 0;
}
