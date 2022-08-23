#undef NDEBUG
#include <cassert>
#include <cstdlib>
#include <dlfcn.h>
#include <filesystem>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <LIEF/MachO.hpp>
#include <LIEF/logging.hpp>
#include <argparse/argparse.hpp>
#include <fmt/format.h>

namespace fs = std::filesystem;
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

    auto binaries = Parser::parse(in_path);

    for (auto &binary : *binaries) {
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

        if (const auto *pgz_seg = binary.get_segment("__PAGEZERO")) {
            if (verbose) {
                fmt::print("[-] Removing __PAGEZERO segment\n");
            }
            binary.remove(*pgz_seg);
        }

        std::string new_dylib_path;
        if (dylib_path != std::nullopt) {
            new_dylib_path = *dylib_path;
        } else {
            fs::path dylib_path{out_path};
            new_dylib_path = fs::path{"@executable_path"} / dylib_path.filename();
        }
        if (verbose) {
            fmt::print("[-] Setting ID_DYLIB path to: '{:s}'\n", new_dylib_path);
        }
        const auto id_dylib_cmd = DylibCommand::id_dylib(new_dylib_path, 2, 0x00010000, 0x00010000);
        binary.add(id_dylib_cmd);

        if (remove_info_plist) {
            if (const auto *plist_sect = binary.get_section("__TEXT", "__info_plist")) {
                if (verbose) {
                    fmt::print("[-] Removing __TEXT,__info_plist\n");
                }
                binary.remove_section("__TEXT", "__info_plist", true);
            }
        }

        if (const auto *dylinker_cmd = binary.dylinker()) {
            if (verbose) {
                fmt::print("[-] Removing dynlinker command\n");
            }
            binary.remove(*dylinker_cmd);
        }

        if (const auto *main_cmd = binary.main_command()) {
            if (verbose) {
                fmt::print("[-] Removing MAIN command\n");
            }
            binary.remove(*main_cmd);
        }

        if (const auto *src_cmd = binary.source_version()) {
            if (verbose) {
                fmt::print("[-] Remvoing source version command\n");
            }
            binary.remove(*src_cmd);
        }

        if (ios || macos) {
            if (const auto *minver_cmd = binary.version_min()) {
                if (verbose) {
                    const auto &ver = minver_cmd->version();
                    const auto &sdk = minver_cmd->sdk();
                    fmt::print("[-] Removing old VERSION_MIN command (version: '{:d}.{:d}.{:d}' "
                               "SDK: '{:d}.{:d}.{:d}')\n",
                               ver[0], ver[1], ver[2], sdk[0], sdk[1], sdk[2]);
                }
                binary.remove(*minver_cmd);
            }
            if (const auto *buildver_cmd = binary.build_version()) {
                if (verbose) {
                    const auto *plat  = to_string(buildver_cmd->platform());
                    const auto &minos = buildver_cmd->minos();
                    const auto &sdk   = buildver_cmd->sdk();
                    fmt::print("[-] Removing old BUILD_VERSION command (platform: '{:s}' version: "
                               "'{:d}.{:d}.{:d}' SDK: '{:d}.{:d}.{:d}')\n",
                               plat, minos[0], minos[1], minos[2], sdk[0], sdk[1], sdk[2]);
                }
                binary.remove(*buildver_cmd);
            }
            const BuildVersion::version_t new_minos{11, 0, 0};
            const BuildVersion::version_t new_sdk{new_minos};
            BuildVersion::PLATFORMS new_plat;
            if (ios) {
                new_plat = BuildVersion::PLATFORMS::IOS;
            } else {
                new_plat = BuildVersion::PLATFORMS::MACOS;
            }
            if (verbose) {
                fmt::print("[-] Adding new BUILD_VERSION command (platform: '{:s}' version: "
                           "'{:d}.{:d}.{:d}' SDK: '{:d}.{:d}.{:d}')\n",
                           to_string(new_plat), new_minos[0], new_minos[1], new_minos[2],
                           new_sdk[0], new_sdk[1], new_sdk[2]);
            }
            auto new_buildver_cmd = BuildVersion{new_plat, new_minos, new_sdk, {}};
            new_buildver_cmd.print(std::cout);
            binary.add(new_buildver_cmd);
        }

        std::set<std::string> remove_dylib_set{remove_dylibs.cbegin(), remove_dylibs.cend()};

        if (auto_remove_dylibs) {
            for (const auto &dylib_cmd : binary.libraries()) {
                if (dylib_cmd.command() == LOAD_COMMAND_TYPES::LC_ID_DYLIB) {
                    continue;
                }
                const auto &test_dylib_path = dylib_cmd.name();
                if (!dylib_exists(test_dylib_path)) {
                    if (verbose) {
                        fmt::print("[-] Marking unavailable dylib '{:s}' for removal\n",
                                   test_dylib_path);
                    }
                    remove_dylib_set.emplace(test_dylib_path);
                }
            }
        }

        if (verbose && remove_dylib_set.size()) {
            fmt::print("[-] Dependant dylib removal list: '{:s}'\n",
                       fmt::join(remove_dylib_set, "', '"));
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
