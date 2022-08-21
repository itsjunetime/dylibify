//
//  main.m
//  dylibify
//
//  Created by Jake James on 7/13/18.
//  Copyright © 2018 Jake James. All rights reserved.
//
// clang -o dylibify dylibify.m -framework Foundation -fobjc-arc

#import <Foundation/Foundation.h>

#import <mach-o/loader.h>
#import <mach-o/swap.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SWAP32(p) __builtin_bswap32(p)

static void *load_bytes(FILE *obj_file, off_t offset, size_t size) {
    void *buf = calloc(1, size);
    fseek(obj_file, offset, SEEK_SET);
    fread(buf, size, 1, obj_file);
    return buf;
}

void write_bytes(FILE *obj_file, off_t offset, size_t size, void *bytes) {
    fseek(obj_file, offset, SEEK_SET);
    fwrite(bytes, size, 1, obj_file);
}

void patch_mach_header(FILE *obj_file, off_t offset, void *mh, BOOL is64bit) {
    if (is64bit) {
        printf("[*] Patching filetype & flags\n");
        printf("[-] FILETYPE was 0x%x\n", ((struct mach_header_64 *)mh)->filetype);
        printf("[-] FLAGS were: 0x%x\n", ((struct mach_header_64 *)mh)->flags);

        //----Change MH_EXECUTE to MH_DYLIB----//
        ((struct mach_header_64 *)mh)->filetype = MH_DYLIB;
        ((struct mach_header_64 *)mh)->flags |= MH_NO_REEXPORTED_DYLIBS;

        printf("[+] FILETYPE is 0x%x\n", ((struct mach_header_64 *)mh)->filetype);
        printf("[+] FLAGS are: 0x%x\n", ((struct mach_header_64 *)mh)->flags);

        write_bytes(obj_file, offset, sizeof(struct mach_header_64), mh);
    } else {
        printf("[*] Patching filetype & flags\n");
        printf("[-] FILETYPE was 0x%x\n", ((struct mach_header *)mh)->filetype);
        printf("[-] FLAGS were: 0x%x\n", ((struct mach_header *)mh)->flags);

        ((struct mach_header *)mh)->filetype = MH_DYLIB;
        ((struct mach_header *)mh)->flags |= MH_NO_REEXPORTED_DYLIBS;

        printf("[+] FILETYPE is 0x%x\n", ((struct mach_header *)mh)->filetype);
        printf("[+] FLAGS are: 0x%x\n", ((struct mach_header *)mh)->flags);

        write_bytes(obj_file, offset, sizeof(struct mach_header), mh);
    }
}

void patch_buildver(FILE *obj_file, off_t offset, struct build_version_command *buildver) {
    printf("[*] Patching buildver\n");
    printf("[-] PLATFORM was 0x%x\n", buildver->platform);
    printf("[-] MINOS was: 0x%x\n", buildver->minos);
    printf("[-] SDK was: 0x%x\n", buildver->sdk);

    buildver->platform = PLATFORM_MACOS;
    buildver->minos    = 0x000b0000;
    buildver->sdk      = 0x000b0000;

    printf("[-] PLATFORM is 0x%x\n", buildver->platform);
    printf("[-] MINOS is: 0x%x\n", buildver->minos);
    printf("[-] SDK is: 0x%x\n", buildver->sdk);

    write_bytes(obj_file, offset, sizeof(struct build_version_command), buildver);
}

void patch_minver(FILE *obj_file, off_t offset, struct version_min_command *minver, off_t mh_off,
                  struct mach_header_64 *mh) {
    printf("[*] Patching minver to buildver\n");
    printf("[-] PLATFORM was 0x%x\n", minver->cmd);
    printf("[-] MINOS was: 0x%x\n", minver->version);
    printf("[-] SDK was: 0x%x\n", minver->sdk);

    struct build_version_command *buildver = malloc(32);
    buildver->cmd                          = LC_BUILD_VERSION;
    // overwrite following LC_SOURCE_VERSION
    buildver->cmdsize  = 32;
    buildver->platform = PLATFORM_MACOS;
    buildver->minos    = 0x000b0000;
    buildver->sdk      = 0x000b0000;
    buildver->ntools   = 1;
    struct build_tool_version *toolver =
        (void *)((uintptr_t)buildver + sizeof(struct build_version_command));
    toolver->tool    = 3;
    toolver->version = 0x13371337;

    printf("[-] PLATFORM is 0x%x\n", buildver->platform);
    printf("[-] MINOS is: 0x%x\n", buildver->minos);
    printf("[-] SDK is: 0x%x\n", buildver->sdk);

    write_bytes(obj_file, offset, 32, buildver);

    printf("[-] mh ncmds was %d\n", mh->ncmds);
    mh->ncmds -= 1;
    printf("[-] mh ncmds is %d mh off: 0x%llx\n", mh->ncmds, mh_off);
    write_bytes(obj_file, mh_off, sizeof(*mh), mh);

    // minver->cmd = LC_VERSION_MIN_MACOSX;
    // minver->version = 0x000b0000;
    // minver->sdk = 0x000b0000;

    // printf("[-] PLATFORM is 0x%x\n", minver->cmd);
    // printf("[-] MINOS is: 0x%x\n", minver->version);
    // printf("[-] SDK is: 0x%x\n", minver->sdk);

    // write_bytes(obj_file, offset, sizeof(struct version_min_command), minver);
}

void patch_pagezero(FILE *obj_file, off_t offset, struct load_command *cmd, BOOL copied, void *seg,
                    size_t sizeofseg, const char *target) {

    uint32_t size = cmd->cmdsize;

    printf("\t\t[*] Patching __PAGEZERO\n");
    printf("\t\t[*] Nullifying\n");

    //----Nullify it----//
    memset(seg, 0, sizeofseg);

    //----Allocate data for our new command + @executable_path/NAME_OF_TARGET.dylib----//
    //----So, if you plan to link with it, don't rename the file and put it on same location as
    // binary----//
    //----Obviously, you can easily patch that yourself, if for some reason you want to----//
    struct dylib_command *dylib_cmd = (struct dylib_command *)malloc(
        sizeof(struct dylib_command) + [@(target) lastPathComponent].length + 52);

    dylib_cmd->cmd     = LC_ID_DYLIB;
    dylib_cmd->cmdsize = size;
    //----The string will be located where our dylib command ends----//
    dylib_cmd->dylib.name.offset           = sizeof(struct dylib_command);
    dylib_cmd->dylib.timestamp             = 1;
    dylib_cmd->dylib.current_version       = 0;
    dylib_cmd->dylib.compatibility_version = 0;

    //----If it's a FAT binary do not copy it twice----//
    if (!copied) {
        strcpy((char *)dylib_cmd + sizeof(struct dylib_command),
               ([[NSString stringWithFormat:@"@executable_path/Frameworks/%@",
                                            [@(target) lastPathComponent]] UTF8String]));
    }

    printf("\t\t[*] Doing the magic\n");

    write_bytes(obj_file, offset, sizeofseg, dylib_cmd);

    free(dylib_cmd);
}

static inline uintptr_t read_uleb128(uint8_t **pp, uint8_t *end) {
    uint8_t *p      = *pp;
    uint64_t result = 0;
    int bit         = 0;
    do {
        assert(p != end);
        uint64_t slice = *p & 0x7f;
        assert(bit <= 63);
        result |= (slice << bit);
        bit += 7;
    } while (*p++ & 0x80);

    *pp = p;
    return result;
}

static inline uintptr_t read_sleb128(uint8_t **pp, uint8_t *end) {
    uint8_t *p     = *pp;
    int64_t result = 0;
    int bit        = 0;
    uint8_t byte;
    do {
        assert(p != end);
        byte = *p++;
        result |= (((int64_t)(byte & 0x7f)) << bit);
        bit += 7;
    } while (byte & 0x80);
    // sign extend negative numbers
    if ((byte & 0x40) != 0)
        result |= (-1LL) << bit;
    *pp = p;
    return result;
}

static inline void read_string(uint8_t **pp, uint8_t *end) {
    uint8_t *p = *pp;
    while (*p != '\0' && (p < end))
        ++p;
    ++p;
    *pp = p;
}

// <3 qwerty
void rebase(struct dyld_info_command *dyld_info, uint8_t *map) {
    uint8_t *start = map;
    uint8_t *end   = start + dyld_info->rebase_size;
    char done      = 0;
    uint8_t *p     = start;
    while (!done && (p < end)) {
        uint8_t immediate = *p & REBASE_IMMEDIATE_MASK;
        uint8_t opcode    = *p & REBASE_OPCODE_MASK;
        ++p;

        switch (opcode) {
        case REBASE_OPCODE_DONE:
            done = 1;
            break;
        case REBASE_OPCODE_SET_TYPE_IMM:
            assert(immediate == REBASE_TYPE_POINTER);
            break;
        case REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
            printf("REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB before %p 0x%02x\n", &p[-1], p[-1]);
            p[-1] -= 1;
            printf("REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB after  %p 0x%02x\n", &p[-1], p[-1]);
            read_uleb128(&p, end);
            break;
        case REBASE_OPCODE_ADD_ADDR_ULEB:
            read_uleb128(&p, end);
            break;
        case REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
            break;
        case REBASE_OPCODE_DO_REBASE_IMM_TIMES:
            break;
        case REBASE_OPCODE_DO_REBASE_ULEB_TIMES:
            read_uleb128(&p, end);
            break;
        case REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB:
            read_uleb128(&p, end);
            break;
        case REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB:
            read_uleb128(&p, end);
            read_uleb128(&p, end);
            break;
        default:
            assert(0);
            break;
        }
    }
}

void bindit(uint8_t *map, size_t sz) {
    printf("bindit opcode buf: %p size: %zx\n", map, sz);
    uint8_t *start = map;
    uint8_t *end   = start + sz;
    char done      = 0;
    uint8_t *p     = start;

    while (!done && (p < end)) {
        uint8_t immediate = *p & BIND_IMMEDIATE_MASK;
        uint8_t opcode    = *p & BIND_OPCODE_MASK;
        ++p;
        switch (opcode) {
        case BIND_OPCODE_DONE:
            //                done = 1;
            break;
        case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
            break;
        case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
            read_uleb128(&p, end);
            break;
        case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
            break;
        case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
            printf("BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM symbol name: %s\n", p);
            read_string(&p, end);
            break;
        case BIND_OPCODE_SET_TYPE_IMM:
            break;
        case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
            printf("BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB before %p 0x%02x\n", &p[-1], p[-1]);
            p[-1] -= 1;
            printf("BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB after  %p 0x%02x\n", &p[-1], p[-1]);
            read_uleb128(&p, end);
            break;
        case BIND_OPCODE_SET_ADDEND_SLEB:
            read_sleb128(&p, end);
            break;
        case BIND_OPCODE_ADD_ADDR_ULEB:
            read_uleb128(&p, end);
            break;
        case BIND_OPCODE_DO_BIND:
            printf("BIND_OPCODE_DO_BIND\n");
            break;
        case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
            read_uleb128(&p, end);
            break;
        case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
            break;
        case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
            read_uleb128(&p, end);
            read_uleb128(&p, end);
            break;
        default:
            printf("opcode: 0x%x\n", opcode);
            assert(0);
            break;
        }
    }
}

void patch_dyldinfo(FILE *file, off_t offset, struct dyld_info_command *dyldinfo) {
    if (dyldinfo->rebase_off != 0) {
        printf("\n\n\nrebase\n\n\n");
        //----Some maths takes place in here, we need to iterate over the opcodes----//
        //----Some of them are just 1 byte, some are 2 bytes, some are whole strings----//
        //----We only need the ones referencing to segments, which are 1 byte----//

        // for (int i = 0; i < dyldinfo->rebase_size; i++) {
        //     uint8_t *bytes = load_bytes(file, offset + dyldinfo->rebase_off + i,
        //     sizeof(uint8_t));

        //     if ((*bytes & REBASE_OPCODE_MASK) == REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB) {
        //         printf("\t\t[-] REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB before = 0x%x\n",
        //         *bytes); *bytes -= 1; // "-1" -> one less segment = previous segment
        //         write_bytes(file, offset + dyldinfo->rebase_off + i, sizeof(uint8_t), bytes);
        //         bytes = load_bytes(file, offset + dyldinfo->rebase_off + i, sizeof(uint8_t));
        //         printf("\t\t[+] REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB now = 0x%x\n", *bytes);
        //         break;
        //     }
        //     free(bytes);
        // }
        uint8_t *bytes = load_bytes(file, offset + dyldinfo->rebase_off, dyldinfo->rebase_size);
        rebase(dyldinfo, bytes);
        write_bytes(file, offset + dyldinfo->rebase_off, dyldinfo->rebase_size, bytes);
        free(bytes);
    }
    if (dyldinfo->bind_off != 0) {
        printf("\n\n\nbind\n\n\n");
        uint8_t *bytes = load_bytes(file, offset + dyldinfo->bind_off, dyldinfo->bind_size);
        bindit(bytes, dyldinfo->bind_size);
        write_bytes(file, offset + dyldinfo->bind_off, dyldinfo->bind_size, bytes);
        free(bytes);
    }
    if (dyldinfo->lazy_bind_off != 0) {
        printf("\n\n\nlazy bind\n\n\n");
        uint8_t *bytes =
            load_bytes(file, offset + dyldinfo->lazy_bind_off, dyldinfo->lazy_bind_size);
        bindit(bytes, dyldinfo->lazy_bind_size);
        write_bytes(file, offset + dyldinfo->lazy_bind_off, dyldinfo->lazy_bind_size, bytes);
        free(bytes);
    }
    if (dyldinfo->weak_bind_off != 0) {
        printf("\n\n\nweak bind\n\n\n");
        uint8_t *bytes =
            load_bytes(file, offset + dyldinfo->weak_bind_off, dyldinfo->weak_bind_size);
        bindit(bytes, dyldinfo->weak_bind_size);
        write_bytes(file, offset + dyldinfo->weak_bind_off, dyldinfo->weak_bind_size, bytes);
        free(bytes);
    }
}

int dylibify(NSDictionary *args) {
    NSError *error             = nil;
    NSFileManager *fileManager = [NSFileManager defaultManager];

    //----Make sure we don't overwrite any file----//
    if ([fileManager fileExistsAtPath:args[@"out"]]) {
        if (true) {
            if (![fileManager removeItemAtPath:args[@"out"] error:&error] || error) {
                printf("[!] %s\n", [[error localizedDescription] UTF8String]);
                return -1;
            }
        } else {
            printf("[!] %s file exists!\n", [args[@"out"] UTF8String]);
            return -1;
        }
    }

    //----Create a copy of the file on the target destination----//
    [fileManager copyItemAtPath:args[@"in"] toPath:args[@"out"] error:&error];

    //----Handle errors----//
    if (error) {
        printf("[!] %s\n", [[error localizedDescription] UTF8String]);
        return -1;
    }

    //----Open the copied file for updating, in binary mode----//
    FILE *file = fopen([args[@"out"] UTF8String], "r+b");

    //----This variable will hold the binary location as we move on through reading it----//
    size_t offset            = 0;
    BOOL copied              = false;
    int ncmds                = 0;
    struct load_command *cmd = NULL;
    uint32_t *magic =
        load_bytes(file, offset, sizeof(uint32_t)); // at offset 0 we have the magic number
    printf("[i] MAGIC = 0x%x\n", *magic);

    //----64bit magic number----//
    if (*magic == 0xFEEDFACF) {

        printf("[i] 64bit binary\n");

        struct mach_header_64 *mh64 = load_bytes(file, offset, sizeof(struct mach_header_64));
        off_t mh64_off              = offset;

        //----Patch filetype and add MH_NO_REEXPORTED_DYLIB flag (required for linking with
        // it)----//
        patch_mach_header(file, offset, mh64, true); // patch
        offset += sizeof(struct mach_header_64);
        ncmds = mh64->ncmds;

        printf("[i] %d LOAD COMMANDS\n", ncmds);

        for (int i = 0; i < ncmds; i++) {
            cmd = load_bytes(file, offset, sizeof(struct load_command));

            if (cmd->cmd == LC_SEGMENT_64) {
                struct segment_command_64 *seg64 =
                    load_bytes(file, offset, sizeof(struct segment_command_64));

                printf("\t[i] LC_SEGMENT_64 (%s)\n", seg64->segname);

                //----Dylibs don't have the PAGEZERO segment, replace it with a LC_ID_DYLIB
                // command----//
                if (!strcmp(seg64->segname, "__PAGEZERO")) {
                    patch_pagezero(file, offset, cmd, copied, seg64,
                                   sizeof(struct segment_command_64), [args[@"out"] UTF8String]);
                }
                free(seg64);
            } else if (cmd->cmd == LC_DYLD_INFO_ONLY) {
                printf("[*] Found DYLD_INFO_ONLY!\n");
                struct dyld_info_command *dyldinfo =
                    load_bytes(file, offset, sizeof(struct dyld_info_command));

                //----Since we removed one segment we have to to rework opcodes so DATA is not
                // confused with LINKEDIT----//
                patch_dyldinfo(file, 0, dyldinfo);
                free(dyldinfo);
            } else if (cmd->cmd == LC_BUILD_VERSION) {
                printf("[*] found BUILD_VERSION!\n");
                struct build_version_command *buildver =
                    load_bytes(file, offset, sizeof(struct build_version_command));
                patch_buildver(file, offset, buildver);
                free(buildver);
            } else if (cmd->cmd == LC_VERSION_MIN_IPHONEOS) {
                printf("[*] found VERSION_MIN_IPHONEOS!\n");
                struct version_min_command *minver =
                    load_bytes(file, offset, sizeof(struct version_min_command));
                patch_minver(file, offset, minver, mh64_off, mh64);
                free(minver);
            } else {
                printf("[i] LOAD COMMAND %d = 0x%x\n", i, cmd->cmd);
            }
            offset += cmd->cmdsize;
            free(cmd);
        }
    }
    //----32bit magic number----//
    else if (*magic == 0xFEEDFACE) {

        printf("[i] 32bit binary\n");

        struct mach_header *mh = load_bytes(file, offset, sizeof(struct mach_header));
        patch_mach_header(file, offset, mh, false);
        offset += sizeof(struct mach_header);
        ncmds = mh->ncmds;
        free(mh);

        printf("[i] %d LOAD COMMANDS\n", ncmds);

        for (int i = 0; i < ncmds; i++) {
            cmd = load_bytes(file, offset, sizeof(struct load_command));
            if (cmd->cmd == LC_SEGMENT) {
                struct segment_command *seg =
                    load_bytes(file, offset, sizeof(struct segment_command));

                printf("\t[i] LC_SEGMENT (%s)\n", seg->segname);

                if (!strcmp(seg->segname, "__PAGEZERO")) {
                    patch_pagezero(file, offset, cmd, copied, seg, sizeof(struct segment_command),
                                   [args[@"out"] UTF8String]);
                }

                free(seg);
            } else if (cmd->cmd == LC_DYLD_INFO_ONLY) {
                printf("[*] Found DYLD_INFO_ONLY!\n");
                struct dyld_info_command *dyldinfo =
                    load_bytes(file, offset, sizeof(struct dyld_info_command));
                patch_dyldinfo(file, 0, dyldinfo);
                free(dyldinfo);
            } else {
                printf("[i] LOAD COMMAND %d = 0x%x\n", i, cmd->cmd);
            }
            offset += cmd->cmdsize;
            free(cmd);
        }
    }
    //----More than one architecture----//
    else if (*magic == 0xBEBAFECA) {

        printf("[i] FAT binary\n");

        size_t arch_offset     = sizeof(struct fat_header);
        struct fat_header *fat = load_bytes(file, offset, sizeof(struct fat_header));
        struct fat_arch *arch  = load_bytes(file, arch_offset, sizeof(struct fat_arch));
        int n                  = SWAP32(fat->nfat_arch);

        printf("[i] %d ARCHS\n", n);

        while (n-- > 0) {
            offset = SWAP32(arch->offset);
            magic  = load_bytes(file, offset, sizeof(uint32_t));

            if (*magic == 0xFEEDFACF) {
                printf("[i] Found 64bit architecture\n");

                struct mach_header_64 *mh64 =
                    load_bytes(file, offset, sizeof(struct mach_header_64));
                off_t mh64_off = offset;
                patch_mach_header(file, offset, mh64, true);
                offset += sizeof(struct mach_header_64);
                ncmds = mh64->ncmds;

                printf("[i] %d LOAD COMMANDS\n", ncmds);

                for (int i = 0; i < ncmds; i++) {
                    cmd = load_bytes(file, offset, sizeof(struct load_command));
                    if (cmd->cmd == LC_SEGMENT_64) {
                        struct segment_command_64 *seg64 =
                            load_bytes(file, offset, sizeof(struct segment_command_64));

                        printf("\t[i] LC_SEGMENT_64 (%s)\n", seg64->segname);

                        if (!strcmp(seg64->segname, "__PAGEZERO")) {
                            patch_pagezero(file, offset, cmd, copied, seg64,
                                           sizeof(struct segment_command_64),
                                           [args[@"out"] UTF8String]);
                            copied = true;
                        }
                        free(seg64);
                    } else if (cmd->cmd == LC_DYLD_INFO_ONLY) {
                        printf("[*] Found DYLD_INFO_ONLY!\n");
                        struct dyld_info_command *dyldinfo =
                            load_bytes(file, offset, sizeof(struct dyld_info_command));
                        patch_dyldinfo(file, SWAP32(arch->offset), dyldinfo);
                        free(dyldinfo);
                    } else if (cmd->cmd == LC_BUILD_VERSION) {
                        printf("[*] found BUILD_VERSION!\n");
                        struct build_version_command *buildver =
                            load_bytes(file, offset, sizeof(struct build_version_command));
                        patch_buildver(file, SWAP32(arch->offset), buildver);
                        free(buildver);
                    } else if (cmd->cmd == LC_VERSION_MIN_IPHONEOS) {
                        printf("[*] found VERSION_MIN_IPHONEOS!\n");
                        struct version_min_command *minver =
                            load_bytes(file, offset, sizeof(struct version_min_command));
                        patch_minver(file, offset, minver, mh64_off, mh64);
                        free(minver);
                    } else {
                        printf("[i] LOAD COMMAND %d = 0x%x\n", i, cmd->cmd);
                    }
                    offset += cmd->cmdsize;
                    free(cmd);
                }
            } else if (*magic == 0xFEEDFACE) {
                printf("[i] Found 32bit architecture\n");

                struct mach_header *mh = load_bytes(file, offset, sizeof(struct mach_header));
                patch_mach_header(file, offset, mh, false);
                offset += sizeof(struct mach_header);
                ncmds = mh->ncmds;
                free(mh);

                printf("[i] %d LOAD COMMANDS\n", ncmds);

                for (int i = 0; i < ncmds; i++) {
                    cmd = load_bytes(file, offset, sizeof(struct load_command));
                    if (cmd->cmd == LC_SEGMENT) {
                        struct segment_command *seg =
                            load_bytes(file, offset, sizeof(struct segment_command));
                        printf("\t[i] LC_SEGMENT (%s)\n", seg->segname);
                        if (!strcmp(seg->segname, "__PAGEZERO")) {
                            patch_pagezero(file, offset, cmd, copied, seg,
                                           sizeof(struct segment_command),
                                           [args[@"out"] UTF8String]);
                            copied = true;
                        }
                        free(seg);
                    } else if (cmd->cmd == LC_DYLD_INFO_ONLY) {
                        printf("[*] Found DYLD_INFO_ONLY!\n");
                        struct dyld_info_command *dyldinfo =
                            load_bytes(file, offset, sizeof(struct dyld_info_command));
                        patch_dyldinfo(file, SWAP32(arch->offset), dyldinfo);
                        free(dyldinfo);
                    } else {
                        printf("[i] LOAD COMMAND %d = 0x%x\n", i, cmd->cmd);
                    }
                    offset += cmd->cmdsize;
                    free(cmd);
                }
            } else {
                printf("[!] Unrecognized architecture with MAGIC = 0x%x\n", *magic);
                continue;
            }
            arch_offset += sizeof(struct fat_arch);
            arch = load_bytes(file, arch_offset, sizeof(struct fat_arch));
        }

        free(fat);
        free(arch);
    } else {
        printf("[!] Unrecognized file\n");
        goto err;
    }

err:
    fclose(file);
    return -1;
}

int main(int argc, const char **argv) {
    NSDictionary *args =
        [[NSUserDefaults standardUserDefaults] volatileDomainForName:NSArgumentDomain];
    NSLog(@"args: %@", args);
    if (!args[@"in"] || !args[@"out"]) {
        printf("Usage:\n\t%s -in <in> -out <out>\nExample:\n\t%s -in /usr/bin/executable -out "
               "/usr/lib/dylibified.dylib\n",
               argv[0], argv[0]);
        return -1;
    }

    dylibify(args);
    return 0;
}