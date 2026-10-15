/*
    LibrePods - AirPods liberated from Apple’s ecosystem
    Copyright (C) 2025 LibrePods contributors

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <android/log.h>
#include <cstring>
#include <string>
#include <vector>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <elf.h>
#include <atomic>
#include <jni.h>

#include "l2c_fcr_hook.h"

extern "C" {
#include "xz.h"
}

#define LOG_TAG "LibrePodsHook"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// the Bluetooth process and its stack library share our bitness (32-bit on armv7-only devices)
#ifdef __LP64__
using Elf_Ehdr = Elf64_Ehdr;
using Elf_Shdr = Elf64_Shdr;
using Elf_Sym = Elf64_Sym;
#else
using Elf_Ehdr = Elf32_Ehdr;
using Elf_Shdr = Elf32_Shdr;
using Elf_Sym = Elf32_Sym;
#endif
#define ELF_ST_TYPE(i) ((i) & 0xf)

static HookFunType hook_func = nullptr;

static uint8_t (*original_l2c_fcr_chk_chan_modes)(void *) = nullptr;

static tBTA_STATUS (*original_BTA_DmSetLocalDiRecord)(tSDP_DI_RECORD *, uint32_t *) = nullptr;

static std::atomic<bool> enableSdpHook(false);

// enough to cover tL2C_CCB up to ertm_info.allowed_modes on known builds (0xE1 on Android 11 armv7);
// ccbs live in a static pool, so over-reading the last one stays in mapped .bss
static constexpr size_t kCcbScanSize = 512;

uint8_t fake_l2c_fcr_chk_chan_modes(void *p_ccb) {
    LOGI("fake_l2c_fcr_chk_chan_modes called");
    uint8_t orig = 0;
    uint8_t before[kCcbScanSize];
    if (p_ccb) memcpy(before, p_ccb, kCcbScanSize);
    if (original_l2c_fcr_chk_chan_modes)
        orig = original_l2c_fcr_chk_chan_modes(p_ccb);

    // The original just cleared ERTM (0x08) / streaming (0x10) from ertm_info.allowed_modes
    // because the AirPods don't advertise them, leaving 0. Faking the return value isn't
    // enough where the check is also inlined elsewhere (Android 11): it fails again and the
    // channel is torn down. Allow basic mode (0x01) instead, so config falls back to it.
    // Locate the field by diffing rather than hardcoding a per-build offset.
    if (!orig && p_ccb) {
        auto *ccb = static_cast<uint8_t *>(p_ccb);
        size_t changed = 0, idx = 0;
        for (size_t i = 0; i < kCcbScanSize; ++i) {
            if (before[i] != ccb[i]) {
                ++changed;
                idx = i;
            }
        }
        if (changed == 1 && ccb[idx] == 0 && (before[idx] & ~0x19) == 0) {
            ccb[idx] = 0x01;
            LOGI("fake_l2c_fcr_chk_chan_modes: allowed_modes @+0x%zx 0x%02x -> basic", idx, before[idx]);
        }
    }

    LOGI("fake_l2c_fcr_chk_chan_modes: orig = %d, returning 1", orig);
    return 1;
}

tBTA_STATUS fake_BTA_DmSetLocalDiRecord(tSDP_DI_RECORD *p_device_info, uint32_t *p_handle) {

    LOGI("fake_BTA_DmSetLocalDiRecord called");

    if (original_BTA_DmSetLocalDiRecord &&
        enableSdpHook.load(std::memory_order_relaxed))
        original_BTA_DmSetLocalDiRecord(p_device_info, p_handle);

    LOGI("fake_BTA_DmSetLocalDiRecord: modifying vendor to 0x004C, vendor_id_source to 0x0001");

    if (p_device_info) {
        p_device_info->vendor = 0x004C;
        p_device_info->vendor_id_source = 0x0001;
    }

    LOGI("fake_BTA_DmSetLocalDiRecord: returning status %d",
         original_BTA_DmSetLocalDiRecord ? original_BTA_DmSetLocalDiRecord(p_device_info, p_handle)
                                         : BTA_FAILURE);
    return original_BTA_DmSetLocalDiRecord ? original_BTA_DmSetLocalDiRecord(p_device_info,
                                                                             p_handle)
                                           : BTA_FAILURE;
}

static bool decompressXZ(const uint8_t *input, size_t input_size, std::vector<uint8_t> &output) {

    LOGI("decompressXZ called with input_size: %zu", input_size);

    xz_crc32_init();
#ifdef XZ_USE_CRC64
    xz_crc64_init();
#endif

    struct xz_dec *dec = xz_dec_init(XZ_DYNALLOC, 64U << 20);
    if (!dec) {
        LOGE("decompressXZ: xz_dec_init failed");
        return false;
    }
    LOGI("decompressXZ: xz_dec_init succeeded");

    struct xz_buf buf{};
    buf.in = input;
    buf.in_pos = 0;
    buf.in_size = input_size;

    output.resize(input_size * 8);

    buf.out = output.data();
    buf.out_pos = 0;
    buf.out_size = output.size();

    LOGI("decompressXZ: entering decompression loop");
    while (true) {
        LOGI("decompressXZ: xz_dec_run iteration, buf.in_pos: %zu, buf.out_pos: %zu", buf.in_pos,
             buf.out_pos);
        enum xz_ret ret = xz_dec_run(dec, &buf);

        LOGI("decompressXZ: xz_dec_run returned %d", ret);

        if (ret == XZ_STREAM_END)
            break;

        if (ret != XZ_OK) {
            LOGE("decompressXZ: xz_dec_run error");
            xz_dec_end(dec);
            return false;
        }

        if (buf.out_pos == buf.out_size) {
            size_t old = output.size();
            LOGI("decompressXZ: resizing output to %zu", old * 2);
            output.resize(old * 2);
            buf.out = output.data();
            buf.out_size = output.size();
        }
    }

    output.resize(buf.out_pos);
    xz_dec_end(dec);
    LOGI("decompressXZ: decompression successful, output size: %zu", output.size());
    return true;
}

static bool getLibraryPath(const char *name, std::string &out) {
    LOGI("getLibraryPath called with name: %s", name);

    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        LOGE("getLibraryPath: fopen failed");
        return false;
    }

    char line[1024];

    LOGI("getLibraryPath: scanning /proc/self/maps");
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, name)) {
            LOGI("getLibraryPath: found line containing %s", name);
            char *path = strchr(line, '/');
            if (path) {
                out = path;
                out.erase(out.find('\n'));
                LOGI("getLibraryPath: path found: %s", out.c_str());
                fclose(fp);
                return true;
            }
        }
    }

    fclose(fp);
    LOGI("getLibraryPath: failed to find path for %s", name);
    return false;
}

static uintptr_t getModuleBase(const char *name) {
    LOGI("getModuleBase called with name: %s", name);

    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        LOGE("getModuleBase: fopen failed");
        return 0;
    }

    char line[1024];
    uintptr_t base = 0;

    LOGI("getModuleBase: scanning /proc/self/maps");
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, name)) {
            base = strtoull(line, nullptr, 16);
            LOGI("getModuleBase: found base at 0x%lx", base);
            break;
        }
    }

    fclose(fp);
    LOGI("getModuleBase: failed to find base for %s", name);
    return base;
}

static uint64_t
findSymbolOffsetDynsym(const std::vector<uint8_t> &elf, const char *symbol_substring) {

    LOGI("findSymbolOffsetDynsym called with %s", symbol_substring);

    auto *eh = reinterpret_cast<const Elf_Ehdr *>(elf.data());
    auto *shdr = reinterpret_cast<const Elf_Shdr *>(
            elf.data() + eh->e_shoff);

    const char *shstr = reinterpret_cast<const char *>(
            elf.data() + shdr[eh->e_shstrndx].sh_offset);

    const Elf_Shdr *dynsym = nullptr;
    const Elf_Shdr *dynstr = nullptr;

    for (int i = 0; i < eh->e_shnum; ++i) {
        const char *secname = shstr + shdr[i].sh_name;

        if (!strcmp(secname, ".dynsym"))
            dynsym = &shdr[i];
        if (!strcmp(secname, ".dynstr"))
            dynstr = &shdr[i];
    }

    if (!dynsym || !dynstr) {
        LOGE("findSymbolOffsetDynsym: dynsym or dynstr not found");
        return 0;
    }

    auto *symbols = reinterpret_cast<const Elf_Sym *>(
            elf.data() + dynsym->sh_offset);

    const char *strings = reinterpret_cast<const char *>(
            elf.data() + dynstr->sh_offset);

    size_t count = dynsym->sh_size / sizeof(Elf_Sym);

    LOGI("findSymbolOffsetDynsym: scanning %zu symbols", count);

    for (size_t i = 0; i < count; ++i) {
        const char *name = strings + symbols[i].st_name;

        if (strstr(name, symbol_substring) && ELF_ST_TYPE(symbols[i].st_info) == STT_FUNC) {

            LOGI("findSymbolOffsetDynsym: matched %s @ 0x%lx", name,
                 (unsigned long) symbols[i].st_value);

            return symbols[i].st_value;
        }
    }

    LOGI("findSymbolOffsetDynsym: no match for %s", symbol_substring);
    return 0;
}

static uint64_t findSymbolOffset(const std::vector<uint8_t> &elf, const char *symbol_substring) {

    LOGI("findSymbolOffset called with symbol_substring: %s", symbol_substring);

    auto *eh = reinterpret_cast<const Elf_Ehdr *>(elf.data());
    auto *shdr = reinterpret_cast<const Elf_Shdr *>(
            elf.data() + eh->e_shoff);

    const char *shstr = reinterpret_cast<const char *>(
            elf.data() + shdr[eh->e_shstrndx].sh_offset);

    const Elf_Shdr *symtab = nullptr;
    const Elf_Shdr *strtab = nullptr;

    LOGI("findSymbolOffset: parsing ELF sections");
    for (int i = 0; i < eh->e_shnum; ++i) {
        const char *secname = shstr + shdr[i].sh_name;
        if (!strcmp(secname, ".symtab"))
            symtab = &shdr[i];
        if (!strcmp(secname, ".strtab"))
            strtab = &shdr[i];
    }

    if (!symtab || !strtab) {
        LOGE("findSymbolOffset: symtab or strtab not found");
        return 0;
    }
    LOGI("findSymbolOffset: found symtab and strtab");

    auto *symbols = reinterpret_cast<const Elf_Sym *>(
            elf.data() + symtab->sh_offset);

    const char *strings = reinterpret_cast<const char *>(
            elf.data() + strtab->sh_offset);

    size_t count = symtab->sh_size / sizeof(Elf_Sym);

    LOGI("findSymbolOffset: scanning %zu symbols", count);
    for (size_t i = 0; i < count; ++i) {
        const char *name = strings + symbols[i].st_name;

        if (strstr(name, symbol_substring) && ELF_ST_TYPE(symbols[i].st_info) == STT_FUNC) {

            LOGI("findSymbolOffset: matched symbol %s at 0x%lx", name,
                 (unsigned long) symbols[i].st_value);

            return symbols[i].st_value;
        }
    }

    LOGI("findSymbolOffset: no match found for %s", symbol_substring);
    return 0;
}

static bool hookLibrary(const char *libname) {
    LOGI("hookLibrary called with libname: %s", libname);

    if (!hook_func) {
        LOGE("hook_func not initialized");
        return false;
    }

    std::string path;
    if (!getLibraryPath(libname, path)) {
        LOGE("Failed to locate %s", libname);
        return false;
    }
    LOGI("hookLibrary: located path: %s", path.c_str());

    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        LOGE("hookLibrary: open failed");
        return false;
    }

    struct stat st{};
    if (fstat(fd, &st) != 0) {
        LOGE("hookLibrary: fstat failed");
        close(fd);
        return false;
    }
    LOGI("hookLibrary: opened file, size: %lld", (long long) st.st_size);

    std::vector<uint8_t> file(st.st_size);
    read(fd, file.data(), st.st_size);
    close(fd);

    auto *eh = reinterpret_cast<Elf_Ehdr *>(file.data());
    auto *shdr = reinterpret_cast<Elf_Shdr *>(
            file.data() + eh->e_shoff);

    const char *shstr = reinterpret_cast<const char *>(
            file.data() + shdr[eh->e_shstrndx].sh_offset);

    uint64_t chk_offset = 0;
    uint64_t sdp_offset = 0;

    for (int i = 0; i < eh->e_shnum; ++i) {
        if (!strcmp(shstr + shdr[i].sh_name, ".gnu_debugdata")) {
            LOGI("hookLibrary: found .gnu_debugdata section");

            std::vector<uint8_t> compressed(file.begin() + shdr[i].sh_offset,
                                            file.begin() + shdr[i].sh_offset + shdr[i].sh_size);

            std::vector<uint8_t> decompressed;

            if (decompressXZ(compressed.data(), compressed.size(), decompressed)) {

                chk_offset = findSymbolOffset(decompressed, "l2c_fcr_chk_chan_modes");

                sdp_offset = findSymbolOffset(decompressed, "BTA_DmSetLocalDiRecord");
            } else {
                LOGE("debugdata decompress failed");
            }

            break;
        }
    }

    if (!chk_offset) {
        LOGI("fallback dynsym chk");
        chk_offset = findSymbolOffsetDynsym(file, "l2c_fcr_chk_chan_modes");
    }

    if (!sdp_offset) {
        LOGI("fallback dynsym sdp");
        sdp_offset = findSymbolOffsetDynsym(file, "BTA_DmSetLocalDiRecord");
    }

    uintptr_t base = getModuleBase(libname);
    if (!base) {
        LOGE("hookLibrary: getModuleBase failed");
        return false;
    }

    if (chk_offset) {
        void *target = reinterpret_cast<void *>(base + chk_offset);
        hook_func(target, (void *) fake_l2c_fcr_chk_chan_modes,
                  (void **) &original_l2c_fcr_chk_chan_modes);
        LOGI("hooked chk");
    }

    if (sdp_offset) {
        void *target = reinterpret_cast<void *>(base + sdp_offset);
        hook_func(target, (void *) fake_BTA_DmSetLocalDiRecord,
                  (void **) &original_BTA_DmSetLocalDiRecord);
        LOGI("hooked sdp");
    }

    return chk_offset || sdp_offset;
}

static void on_library_loaded(const char *name, void *) {
    LOGI("on_library_loaded called with name: %s", name);

    static bool hooked = false;
    if (hooked || !strstr(name, "bluetooth")) return;

    // Android 13+: stack is in libbluetooth_jni.so. Android 12 and below: libbluetooth.so
    // (libbluetooth_qti.so on QTI), usually pulled in as a dependency of a JNI lib that
    // may be vendor-named (e.g. MediaTek's libmtkbluetooth_jni.so)
    for (const char *lib : {"libbluetooth_jni.so", "libbluetooth_qti.so", "libbluetooth.so"}) {
        if (hookLibrary(lib)) {
            hooked = true;
            return;
        }
    }
}

extern "C" [[gnu::visibility("default")]]
[[gnu::used]]
NativeOnModuleLoaded native_init(const NativeAPIEntries *entries) {
    LOGI("native_init called with entries: %p", entries);
    hook_func = (HookFunType) entries->hook_func;
    LOGI("LibrePodsNativeHook initialized, sdp hook enabled: %d",
         enableSdpHook.load(std::memory_order_relaxed));
    return on_library_loaded;
}

extern "C" JNIEXPORT void JNICALL
Java_me_kavishdevar_librepods_utils_NativeBridge_setSdpHook(JNIEnv *, jobject thiz,
                                                            jboolean enable) {
    LOGI("setSdpHook called with enable: %d", enable);
    enableSdpHook.store(enable, std::memory_order_relaxed);

    LOGI("sdp hook enabled: %d", enable);
}
