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
    remove_info_plist: bool = False,
    ios: bool = False,
    macos: bool = False,
):
    if remove_dylibs is None:
        remove_dylibs = []

    assert not (ios and macos)

    if ios:
        log("fack l")
        dbg("fack d")
        raise NotImplementedError("Implement iOS platform setting")
    if macos:
        raise NotImplementedError("Implement macOS platform setting")
    if dylib_path is not None:
        raise NotImplementedError("Implement custom dylib ID")

    binary = lief.parse(in_path)
    assert binary is not None

    dbg("Removing signature")
    binary.remove_signature()

    if remove_info_plist:
        dbg("Removing __TEXT,__info_plist section")
        binary.remove_section("__TEXT", "__info_plist")

    removed_imports = {}

    for i, imported_sym in enumerate(binary.imported_symbols):
        dbg(f"imported_sym[{i:4}] = '{imported_sym.name}'")
        if imported_sym.has_binding_info and imported_sym.binding_info.has_library:
            dbg(f"Import '{imported_sym.name}' from '{imported_sym.binding_info.library.name}'")
        if (
            imported_sym.has_binding_info
            and imported_sym.binding_info.has_library
            and imported_sym.binding_info.library.name in remove_dylibs
        ):
            removed_imports[imported_sym.name] = {
                "sym": imported_sym,
                "library": imported_sym.binding_info.library,
            }

    dbg(f"Removed imports: {removed_imports}")

    for dylib in remove_dylibs:
        pass

    binary.write(out_path)
