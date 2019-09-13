//
// Created by 刘友学 on 2018/11/17.
//
#include <string>

#include <fcntl.h>
#include <sys/mman.h>
#include <memory>
#include <iostream>
#include <unistd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <streambuf>
#include <fstream>
#include <iterator>
#include <vector>
#include <regex>
#include <unordered_map>
#include <map>
#include <cstdio>
#include <elf.h>
#include <link.h>

#include <android/log.h>

#define EMPTY_STRING ""
#define ATOLL(str)	strtoull((str).c_str(), NULL, 16)

#ifndef DT_GNU_HASH
#define DT_GNU_HASH 0x6ffffef5
#endif

#ifndef FLAG_GNU_HASH
#define FLAG_GNU_HASH 0x00000040
#endif

#define powerof2(x)     ((((x)-1)&(x))==0)

struct MapsLine {
    unsigned long 	mStart; // code address
    std::string		mPerm;
    std::string		mPath;

    void parse(std::string lineContent) {
        std::vector<std::string> tokens = split(lineContent, "\\s+");
        if (tokens.size() > 5) {
            std::string addressRange = tokens[0];
            mPerm = tokens[1];
            if (addressRange != EMPTY_STRING && mPerm != EMPTY_STRING && mPerm.find("r-xp") != std::string::npos) {
                std::vector<std::string> ranges = split(addressRange, "-");
                if (ranges.size() != 0) {
                    mStart = ATOLL(ranges[0]);
                }
            }

            mPath = tokens[5];
        }
    }

private:
    static std::vector<std::string> split(const std::string& in, const std::string& delim) {
        std::regex re { delim };
        return std::vector<std::string> {
                std::sregex_token_iterator(in.begin(), in.end(), re, -1),
                std::sregex_token_iterator()
        };
    }
};

/* Compute the load-bias of an existing executable. This shall only
 * be used to compute the load bias of an executable or shared library
 * that was loaded by the kernel itself.
 *
 * Input:
 *    elf    -> address of ELF header, assumed to be at the start of the file.
 * Return:
 *    load bias, i.e. add the value of any p_vaddr in the file to get
 *    the corresponding address in memory.
 */
static ElfW(Addr) get_elf_exec_load_bias(const ElfW(Ehdr)* elf, const ElfW(Phdr)* phdr_table, unsigned long load_address) {
    const ElfW(Phdr)* phdr_end = phdr_table + elf->e_phnum;

    for (const ElfW(Phdr)* phdr = phdr_table; phdr < phdr_end; phdr++) {
        if (phdr->p_type == PT_LOAD) {
            return load_address - phdr->p_vaddr;
        }
    }
    return 0;
}

struct ScopedIfstream {
    std::ifstream mIs;
    ScopedIfstream(const std::string& file) : mIs(file){
    }
    ~ScopedIfstream() {
        if (mIs) {
            mIs.close();
        }
    }
};

std::unordered_map<std::string, MapsLine*> gMapsLineMap;

void parseIfEmpty() {
    if (!gMapsLineMap.empty()) {
        return;
    }

    ScopedIfstream file("/proc/self/maps");
    if (!file.mIs) {
        return;
    }

    std::string line;
    while (getline(file.mIs, line)) {
        if (line.empty()) continue;
        MapsLine* mapsLine = new MapsLine;
        mapsLine->parse(line);
        if (!mapsLine->mPath.empty() && mapsLine->mPerm.find("r-xp") != std::string::npos) {
            gMapsLineMap[mapsLine->mPath] = mapsLine;
        }
    }
}

struct ScopedFd {
    int mFd;
    ScopedFd(const char *filePath) {
        mFd = open(filePath, O_RDONLY);
    }
    bool isValid() {
        return mFd > 0;
    }
    ~ScopedFd() {
        if (isValid()) {
            close(mFd);
        }
    }
};

struct Context {
    void *mem;
    size_t size;
    ElfW(Addr) load_bias;

    const char* strtab_;

    ElfW(Sym)* symtab_;
    ElfW(Word) dynamic_memsz;

    uint32_t nbucket_;
#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCUnusedGlobalDeclarationInspection"
    uint32_t nchain_;
#pragma clang diagnostic pop
    uint32_t* bucket_;
    uint32_t* chain_;

    uint32_t gnu_nbucket_;
    uint32_t gnu_sym_offset;
    uint32_t gnu_maskwords_;
#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCUnusedGlobalDeclarationInspection"
    size_t strtab_size_;
#pragma clang diagnostic pop
    ElfW(Addr)* gnu_bloom_filter_;
    uint32_t* gnu_bucket_;
    uint32_t* gnu_chain_;

    uint32_t flags_;

    bool is_gnu_hash() {
        return (flags_ & FLAG_GNU_HASH) != 0;
    }
};

static void phdr_table_get_dynamic_section(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                ElfW(Addr) load_bias, ElfW(Dyn)** dynamic,
                ElfW(Word)* dynamic_flags, ElfW(Word)* dynamic_memsz) {
    *dynamic = nullptr;
    for (size_t i = 0; i < phdr_count; ++i) {
        const ElfW(Phdr)& phdr = phdr_table[i];
        if (phdr.p_type == PT_DYNAMIC) {
            *dynamic = reinterpret_cast<ElfW(Dyn)*>(load_bias + phdr.p_vaddr);
            if (dynamic_memsz) {
                *dynamic_memsz = static_cast<ElfW(Word)>(phdr.p_memsz);
            }
            if (dynamic_flags) {
                *dynamic_flags = phdr.p_flags;
            }
            return;
        }
    }
}

void* dd_dlopen(const char *filePath) {
    parseIfEmpty();
    ScopedFd fd(filePath);
    if (!fd.isValid()) {
        return nullptr;
    }
    off_t size = lseek(fd.mFd, 0, SEEK_END);
    if (size <= 0) {
        return nullptr;
    }

    Context *context = new Context;

    context->size = static_cast<size_t>(size);
    context->mem = mmap(NULL, context->size, PROT_READ, MAP_SHARED, fd.mFd, 0);
    if (context->mem == MAP_FAILED) {
        return nullptr;
    }

    ElfW(Ehdr)* ehdr = reinterpret_cast<ElfW(Ehdr)*>(context->mem);
    const ElfW(Phdr)* phdr_table =
            reinterpret_cast<const ElfW(Phdr)*>(reinterpret_cast<uintptr_t>(ehdr) + ehdr->e_phoff);

    MapsLine* mapsLine = gMapsLineMap[filePath];
    if (mapsLine == nullptr) {
        return nullptr;
    }

    context->load_bias = get_elf_exec_load_bias(ehdr, phdr_table, mapsLine->mStart);

    ElfW(Word) dynamic_flags = 0;
    ElfW(Dyn)* dynamic;

    phdr_table_get_dynamic_section(phdr_table, ehdr->e_phnum, context->load_bias, &dynamic, &dynamic_flags, &context->dynamic_memsz);

    ElfW(Addr) load_bias = context->load_bias;

    for (ElfW(Dyn)* d = dynamic; d->d_tag != DT_NULL; ++d) {
        __android_log_print(ANDROID_LOG_ERROR, "liuyx", "d_tag = 0x%llx", d->d_tag);
        switch (d->d_tag) {
            case DT_HASH:
                context->nbucket_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[0];
                context->nchain_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[1];
                context->bucket_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr + 8);
                context->chain_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr + 8 + context->nbucket_ * 4);
                break;

            case DT_GNU_HASH:
                context->gnu_nbucket_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[0];
                context->gnu_sym_offset = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[1];
                context->gnu_maskwords_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[2];

                context->gnu_bloom_filter_ = reinterpret_cast<ElfW(Addr)*>(load_bias + d->d_un.d_ptr + 16);
                context->gnu_bucket_ = reinterpret_cast<uint32_t*>(context->gnu_bloom_filter_ + context->gnu_maskwords_);
                // amend chain for symndx = header[1]
                context->gnu_chain_ = context->gnu_bucket_ + context->gnu_nbucket_;

                if (!powerof2(context->gnu_maskwords_)) {
                    break;
                }
                --context->gnu_maskwords_;

                context->flags_ |= FLAG_GNU_HASH;
                break;

            case DT_STRTAB:
                context->strtab_ = reinterpret_cast<const char*>(load_bias + d->d_un.d_ptr);
                break;

            case DT_STRSZ:
                context->strtab_size_ = d->d_un.d_val;
                break;

            case DT_SYMTAB:
                context->symtab_ = reinterpret_cast<ElfW(Sym)*>(load_bias + d->d_un.d_ptr);
                break;

            default:
                break;

        }
    }
    return reinterpret_cast<void*>(context);
}

static uint32_t elf_hash(const char* name) {
    const uint8_t* name_bytes = reinterpret_cast<const uint8_t*>(name);
    uint32_t h = 0, g;

    while (*name_bytes) {
        h = (h << 4) + *name_bytes++;
        g = h & 0xf0000000;
        h ^= g;
        h ^= g >> 24;
    }

    return h;
}

static bool is_symbol_global_and_defined(const ElfW(Sym)* s) {
    if (ELF_ST_BIND(s->st_info) == STB_GLOBAL ||
            ELF_ST_BIND(s->st_info) == STB_WEAK) {
        return s->st_shndx != SHN_UNDEF;
    }
    return false;
}

static ElfW(Addr) call_ifunc_resolver(ElfW(Addr) resolver_addr) {
    typedef ElfW(Addr) (*ifunc_resolver_t)(void);
    ifunc_resolver_t ifunc_resolver = reinterpret_cast<ifunc_resolver_t >(resolver_addr);
    ElfW(Addr) ifunc_addr = ifunc_resolver();
    return ifunc_addr;
}

static ElfW(Addr) resolve_symbol_address(const ElfW(Sym)* s, ElfW(Addr) load_bias) {
    if (ELF_ST_TYPE(s->st_info) == 10) {
        return call_ifunc_resolver(s->st_value + load_bias);
    }
    return static_cast<ElfW(Addr)>(s->st_value + load_bias);
}

uint32_t gnu_hash(const char* name_arg) {
    uint32_t h = 5381;
    const uint8_t* name = reinterpret_cast<const uint8_t*>(name_arg);
    while (*name != 0) {
        h += (h << 5) + *name++; // h*33 + c = h + h * 32 + c = h + h << 5 + c
    }
    return h;
}


bool gnu_lookup(Context* context, const char* symbol_name,
                        uint32_t* symbol_index) {
    const uint32_t hash = gnu_hash(symbol_name);

    const uint32_t nbuckets = context->gnu_nbucket_;
    const uint32_t offset = context->gnu_sym_offset;
    const uint32_t* buckets = context->gnu_bucket_;
    const uint32_t* chain = context->gnu_chain_;

    uint32_t symix = buckets[hash % nbuckets];
    if (symix < offset) {
        return nullptr;
    }

    ElfW(Sym)* symtab = context->symtab_;

    while (true) {
        const char *symname = context->strtab_ + symtab[symix].st_name;
        const uint32_t h = chain[symix - offset];

        if (hash | 1 == h | 1 && strcmp(symname, symbol_name) == 0) {
            *symbol_index = symix;
            return true;
        }

        if (hash & 1) {
            break;
        }

        symix++;

        ++symtab;
    }

    return false;
}

void elf_lookup(Context* context, const char* sym, uint32_t* symbol_index) {

    uint32_t hash = elf_hash(sym);

    uint32_t* bucket = context->bucket_;
    uint32_t nbucket = context->nbucket_;
    uint32_t* chain = context->chain_;

    ElfW(Sym)* symtab = context->symtab_;
    const char* strtab = context->strtab_;

    for (uint32_t n = bucket[hash % nbucket]; n != 0; n = chain[n]) {
        ElfW(Sym)* s = symtab + n;
        if (strcmp(strtab + s->st_name, sym) == 0) {
            if (is_symbol_global_and_defined(s)) {
                *symbol_index = n;
                break;
            }
        }
    }
}

uint32_t linear_lookup(Context* context, const char* sym) {
    ElfW(Sym)* symtab = context->symtab_;
    const char *strtab = context->strtab_;

    for (int i = 0; i < context->gnu_sym_offset; i++, symtab++) {
        const char *s = strtab + symtab->st_name;
        if (strcmp(s, sym) == 0) {
            return static_cast<uint32_t>(symtab->st_value);
        }
    }

    return 0;
}

void* dd_dlsym(void* handle, const char *sym) {
    if (handle == nullptr) {
        return nullptr;
    }

    Context *context = reinterpret_cast<Context*>(handle);

    void* ret;

    ElfW(Sym)* symtab = context->symtab_;
    const ElfW(Addr) load_bias = context->load_bias;

    uint32_t symbol_index = 0;

    if (context->is_gnu_hash()) {
        gnu_lookup(context, sym, &symbol_index);
    } else {
        elf_lookup(context, sym, &symbol_index);
    }

    if (symbol_index == 0) {
        symbol_index = linear_lookup(context, sym);
        if (symbol_index == 0) {
            return nullptr;
        }
    }

    ElfW(Sym)* result = nullptr;
    if (symbol_index != 0) {
        result = symtab + symbol_index;
    }

    if (result == nullptr) {
        return nullptr;
    }

    uint32_t bind = ELF_ST_BIND(result->st_info);
    if (bind == STB_GLOBAL || bind == STB_WEAK) {
        ret = reinterpret_cast<void*>(resolve_symbol_address(result, load_bias));
        return ret;
    }

    return nullptr;
}

void dd_dlclose(void *handle) {
    Context *context = reinterpret_cast<Context*>(handle);

    if (!context) {
        return;
    }

    munmap(context->mem, context->size);

    delete context;
}

