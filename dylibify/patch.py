import ctypes
import logging
from typing import Optional

import lief

logger = logging.getLogger("dylibify")
log = lambda *args, **kwargs: logger.info(*args, **kwargs)
dbg = lambda *args, **kwargs: logger.debug(*args, **kwargs)


def dylibify(
    in_path: str,
    out_path: str,
    dylib_path: Optional[str] = None,
    remove_dylibs: Optional[list[str]] = None,
    auto_remove_dylibs: bool = False,
    remove_info_plist: bool = False,
    ios: bool = False,
    macos: bool = False,
):
    if remove_dylibs is None:
        remove_dylibs = []

    assert not (ios and macos)

    if ios:
        raise NotImplementedError("Implement iOS platform setting")
    if macos:
        raise NotImplementedError("Implement macOS platform setting")
    if dylib_path is not None:
        raise NotImplementedError("Implement custom dylib ID")

    lief.logging.set_level(lief.logging.LOGGING_LEVEL.TRACE)

    binary = lief.parse(in_path)
    assert binary is not None

    log("Removing signature")
    binary.remove_signature()

    if remove_info_plist:
        log("Removing __TEXT,__info_plist section")
        binary.remove_section("__TEXT", "__info_plist")

    if auto_remove_dylibs:
        for cmd in (
            cmd
            for cmd in binary.commands
            if isinstance(cmd, lief.MachO.DylibCommand)
            and cmd.command != lief.MachO.LOAD_COMMAND_TYPES.ID_DYLIB
        ):
            dbg(f"Trying to load dependant dylib '{cmd.name}'")
            try:
                handle = ctypes.CDLL(cmd.name)
                del handle
            except OSError:
                remove_dylibs.append(cmd.name)
                log(f"Missing dylib '{cmd.name}' will be removed")
    remove_dylibs = list(set(remove_dylibs))

    removed_imports = {}

    for i, imported_sym in enumerate(binary.imported_symbols):
        # dbg(f"imported_sym[{i:4}] = '{imported_sym.name}'")
        # if imported_sym.has_binding_info and imported_sym.binding_info.has_library:
        #     dbg(f"Import '{imported_sym.name}' from '{imported_sym.binding_info.library.name}'")
        if (
            imported_sym.has_binding_info
            and imported_sym.binding_info.has_library
            and imported_sym.binding_info.library.name in remove_dylibs
        ):
            removed_imports[imported_sym.name] = {
                "sym": imported_sym,
                "library": imported_sym.binding_info.library,
            }
            log(
                f"Removing symbol '{imported_sym.name}' imported from '{imported_sym.binding_info.library.name}'"
            )

    for i, cmd in enumerate(binary.commands):
        if (
            not isinstance(cmd, lief.MachO.DylibCommand)
            or cmd.command == lief.MachO.LOAD_COMMAND_TYPES.ID_DYLIB
        ):
            continue
        if cmd.name not in remove_dylibs:
            continue
        dbg(f"Removing load command for dylib '{cmd.name}' of type '{cmd.command}'")
        binary.remove(cmd)
        # binary.remove_command(i)

    for dylib in remove_dylibs:
        pass

    binary.write(out_path)
