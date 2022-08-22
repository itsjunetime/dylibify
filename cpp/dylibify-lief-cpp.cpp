#undef NDEBUG
#include <cassert>
#include <cstdlib>
#include <optional>
#include <string>
#include <vector>

#include <LIEF/MachO.hpp>
#include <LIEF/logging.hpp>
#include <argparse/argparse.hpp>
#include <fmt/format.h>

void dylibify(std::string in_path, std::string out_path, std::optional<std::string> dylib_path,
              std::vector<std::string> remove_dylibs, bool auto_remove_dylibs = false,
              bool remove_info_plist = false, bool ios = false, bool macos = false,
              bool verbose = false) {
    assert(!(ios && macos));
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
    parser.add_argument("-v", "--verbose")
        .default_value(false)
        .implicit_value(true)
        .help("verbose mode");

    try {
        parser.parse_args(argc, argv);
    } catch (const std::runtime_error &err) {
        fmt::print(stderr, "Error parsing arguments: {:s}\n", err.what());
        return -1;
    }

    dylibify(parser.get<std::string>("--in-path"), parser.get<std::string>("--out-path"),
             parser.present("--dylib-path"), parser.get<std::vector<std::string>>("--remove-dylib"),
             parser.get<bool>("--auto-remove-dylibs"), parser.get<bool>("--remove-info-plist"),
             parser.get<bool>("--ios"), parser.get<bool>("--macos"), parser.get<bool>("--verbose"));

    return 0;
}
