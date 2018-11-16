#include <fcntl.h>
#include <sys/mman.h>
#include <string>
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
#include <dlfcn.h>

#define EMPTY_STRING ""
#define ATOLL(str)	strtoull((str).c_str(), NULL, 16)

struct MapsLine {
	unsigned long 	mStart; // code address
	unsigned long 	mEnd;
	std::string		mPerm;
	std::string		mPath;
	std::string		mLine;

	void parse(std::string lineContent) {
		mLine = lineContent;
		std::vector<std::string> tokens = split(lineContent, "\\s+");
		if (tokens.size() > 5) {
			std::string addressRange = tokens[0];
			mPerm = tokens[1];
			if (addressRange != EMPTY_STRING && mPerm != EMPTY_STRING && mPerm.find("r-xp") != std::string::npos) {
				std::vector<std::string> ranges = split(addressRange, "-");
				if (ranges.size() != 0) {
					mStart = ATOLL(ranges[0]);
					mEnd = ATOLL(ranges[1]);
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

struct ScopedIfstream {
	std::ifstream mIs;
	ScopedIfstream(const std::string& file) : mIs(std::ifstream(file)) {}
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

struct ScopedMmap {
	int mFd;
	size_t mSize;
	void *mMem;
	ScopedMmap(int fd, size_t size) {
		mMem = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
	}
	~ScopedMmap() {
		if (mMem != nullptr && mSize > 0) {
			munmap(mMem, mSize);
		}
	}
};

struct Context {
	uint8_t *mem;
	off_t bias;
	void* load_addr;

	/* --- DynSym --- */
	ElfW(Sym)* dynsym;
	const char *dynstr;
	size_t dynSymCnt;

	Context() {
		mem = nullptr;
		bias = 0;
		load_addr = nullptr;
		dynsym = nullptr;
		dynstr = nullptr;
		dynSymCnt = 0;
	}

};

static ElfW(Addr) get_elf_load_bias(const ElfW(Ehdr)* elf) {
	ElfW(Addr) offset = elf->e_phoff;
	const ElfW(Phdr)* phdr_table = reinterpret_cast<const ElfW(Phdr)*>(reinterpret_cast<uintptr_t>(elf) + offset);
	const ElfW(Phdr)* phdr_end = phdr_table + elf->e_phnum;

	for (const ElfW(Phdr)* phdr = phdr_table; phdr < phdr_end; phdr++) {
		if (phdr->p_type == PT_LOAD) {
			return reinterpret_cast<ElfW(Addr)>(elf) + phdr->p_offset - phdr->p_vaddr;
		}
	}
	return 0;
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
	if (!context) {
		return nullptr;
	}

	ScopedMmap elfMap(fd.mFd, size);
	if (elfMap.mMem == MAP_FAILED) {
		return nullptr;
	}

	ElfW(Ehdr)* ehdr = reinterpret_cast<ElfW(Ehdr)*>(elfMap.mMem);

	MapsLine* mapsLine = gMapsLineMap[filePath];
	if (mapsLine == nullptr) {
		return nullptr;
	}

	context->mem = reinterpret_cast<uint8_t*>(elfMap.mMem);
	uint8_t *mem = context->mem;

	context->load_addr = reinterpret_cast<void*>(mapsLine->mStart);

	ElfW(Shdr)* shdr = reinterpret_cast<ElfW(Shdr)*>(mem + ehdr->e_shoff);
	const char *shstrtab = reinterpret_cast<const char*>(&mem[shdr[ehdr->e_shstrndx].sh_offset]);

	const char *section;
	for (int i = 0; i < ehdr->e_shnum; i++) {
		section = &shstrtab[shdr[i].sh_name];
		switch (shdr[i].sh_type) {
			case SHT_DYNSYM:
				if (strcmp(section, ".dynsym") == 0) {
					if (context->dynsym) {
						return nullptr;
					}

					context->dynSymCnt = shdr[i].sh_size / sizeof(ElfW(Sym));

					if (context->dynSymCnt <= 0) {
						return nullptr;
					}

					context->dynsym = reinterpret_cast<ElfW(Sym)*>(malloc(shdr[i].sh_size));
					if (!context->dynsym) {
						return nullptr;
					}

					memcpy(context->dynsym, mem + shdr[i].sh_offset, shdr[i].sh_size);
				}
				break;
			case SHT_STRTAB:
				if (context->dynstr) {
					break;
				}
				context->dynstr = reinterpret_cast<const char*>(malloc(shdr[i].sh_size));
				if (!context->dynstr) {
					return nullptr;
				}
				memcpy(reinterpret_cast<void*>(const_cast<char*>(context->dynstr)), mem + shdr[i].sh_offset, shdr[i].sh_size);
				break;

			case SHT_PROGBITS:
				if (!context->dynstr || !context->dynsym) {
					break;
				}
				context->bias = shdr[i].sh_addr - shdr[i].sh_offset;
				break;
		}
	}

	return reinterpret_cast<void*>(context);
}

void* dd_dlsym(void* handle, const char *sym) {
	if (handle == nullptr) {
		return nullptr;
	}
	Context *context = reinterpret_cast<Context*>(handle);
	ElfW(Sym)* symtab = context->dynsym;
	const char *strtab = context->dynstr;

	const ElfW(Addr) load_bias = get_elf_load_bias(reinterpret_cast<ElfW(Ehdr)*>(context->mem));

	for (int i = 0; i < context->dynSymCnt; i++, symtab++) {
		if (strcmp(strtab + symtab->st_name, sym) == 0) {
			return reinterpret_cast<void*>(reinterpret_cast<long>(context->load_addr) + symtab->st_value);
		}
	}
	return nullptr;
}

void dd_dlclose(void *handle) {
	Context *context = reinterpret_cast<Context*>(handle);

	if (!context) {
		return;
	}

	if (context->dynsym) {
		free(context->dynsym);
	}

	if (context->dynstr) {
		free(const_cast<char*>(context->dynstr));
	}

	delete context;
}

int main(int argc, char **argv) {
	std::string filePath = "/lib/x86_64-linux-gnu/libc-2.24.so";
	void* handle = dd_dlopen(filePath.c_str());

	void *sym = dd_dlsym(handle, "puts");

	printf("%p\n", sym);

	typedef int (*My_puts)(const char *);

	My_puts myPuts = (My_puts)(sym);
	myPuts("hello,world");

	dd_dlclose(handle);
}
