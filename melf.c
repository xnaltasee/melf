#include <elf.h>
#include <errno.h>
#include <stdio.h>

static int valid_elfheader(Elf64_Ehdr *elf_buf)
{
	return elf_buf->e_ident[EI_MAG0] == ELFMAG0 &&
	       elf_buf->e_ident[EI_MAG1] == ELFMAG1 &&
	       elf_buf->e_ident[EI_MAG2] == ELFMAG2 &&
	       elf_buf->e_ident[EI_MAG3] == ELFMAG3;
}

static char *parse_elfheader_class(Elf64_Ehdr *elf_buf)
{
	switch (elf_buf->e_ident[EI_CLASS]) {
	case ELFCLASS32:
		return "32";
	case ELFCLASS64:
		return "64";
	}

	return "Unknown";
}

static char *parse_elfheader_data(Elf64_Ehdr *elf_buf)
{
	switch (elf_buf->e_ident[EI_DATA]) {
	case ELFDATA2LSB:
		return "little-endian";
	case ELFDATA2MSB:
		return "big-endian";
	}

	return "Unknown";
}

static char *parse_elfheader_version(Elf64_Ehdr *elf_buf)
{
	return elf_buf->e_ident[EI_VERSION] == EV_CURRENT ? "Current" : "Unknown";
}

static char *parse_elfheader_osabi(Elf64_Ehdr *elf_buf)
{
	char *osabi_data[] = {
		[ELFOSABI_SYSV] = "UNIX System V",
		[ELFOSABI_HPUX] = "HP-UX",
		[ELFOSABI_NETBSD] = "NetBSD",
		[ELFOSABI_LINUX] = "Linux",
		[ELFOSABI_SOLARIS] = "Sun Solaris",
		[ELFOSABI_AIX] = "IBM AIX",
		[ELFOSABI_IRIX] = "SGI IRIX",
		[ELFOSABI_FREEBSD] = "FreeBSD",
		[ELFOSABI_TRU64] = "Compaq TRU64 UNIX",
		[ELFOSABI_MODESTO] = "Novell Modesto",
		[ELFOSABI_OPENBSD] = "OpenBSD",
		[ELFOSABI_ARM_AEABI] = "ARM EABI",
		[ELFOSABI_ARM] = "ARM",
		[ELFOSABI_STANDALONE] = "Standalone"
	};

	if (osabi_data[elf_buf->e_ident[EI_OSABI]])
		return osabi_data[elf_buf->e_ident[EI_OSABI]];

	return "Unknown";
}

static int parse_elfheader_abiver(Elf64_Ehdr *elf_buf)
{
	return elf_buf->e_ident[EI_ABIVERSION];
}

static char *parse_elfheader_type(Elf64_Ehdr *elf_buf)
{
	char *elftype_data[] = {
		[ET_REL] = "REL (Relocatable file)",
		[ET_EXEC] = "EXEC (Executable file)",
		[ET_DYN] = "DYN (Shared object)",
		[ET_CORE] = "CORE (Core file)"
	};

	if (elftype_data[elf_buf->e_type])
		return elftype_data[elf_buf->e_type];

	return "NONE (Uknown type)";
}

/* TODO: e_machine (architecture) function */

static void dump_elfheader(Elf64_Ehdr *elf_buf)
{
	printf("Magic   : ");

	for (int i = 0; i < EI_NIDENT; i++)
		printf("%02x ", elf_buf->e_ident[i]);
	printf("\n");

	printf("Class                              : ELF%s\n", parse_elfheader_class(elf_buf));
	printf("Data                               : %s\n", parse_elfheader_data(elf_buf));
	printf("Version                            : %s\n", parse_elfheader_version(elf_buf));
	printf("OS/ABI                             : %s\n", parse_elfheader_osabi(elf_buf));
	printf("ABI version                        : %#x\n", parse_elfheader_abiver(elf_buf));
	printf("Type                               : %s\n", parse_elfheader_type(elf_buf));
	printf("Entry virtual address              : %#lx\n", elf_buf->e_entry);
	printf("Program header table's file offset : %lu bytes\n", elf_buf->e_phoff);
	printf("Section header table's file offset : %lu bytes\n", elf_buf->e_shoff);
	printf("Flags                              : %#x\n", elf_buf->e_flags);
	printf("Size of this ELF header            : %u bytes\n", elf_buf->e_ehsize);
	printf("Size of program header table       : %u bytes\n", elf_buf->e_phentsize);
	printf("Number of program header table     : %u\n", elf_buf->e_phnum);
	printf("Size of section header's           : %u bytes\n", elf_buf->e_shentsize);
	printf("Number of section header table     : %u\n", elf_buf->e_shnum);
	printf("Section header table index         : %u\n", elf_buf->e_shstrndx);
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "usage: %s binary-file\n", argv[0]);
		return 1;
	}

	int ret = 0;
	errno = 0;
	unsigned char buffer[sizeof(Elf64_Ehdr)];

	FILE *fp = fopen(argv[1], "rb");
	if (!fp) {
		perror("fopen");
		return 1;
	}

	size_t r = fread(buffer, sizeof(Elf64_Ehdr), sizeof(*buffer), fp);
	if (r != sizeof(*buffer)) {
		ret = 1;
		perror("fread");
		goto done;
	}

	Elf64_Ehdr *elf_buffer = (Elf64_Ehdr *)buffer;
	if (valid_elfheader(elf_buffer)) {
		dump_elfheader(elf_buffer);
	} else {
		ret = 1;
		printf("Not an ELF file\n");
	}

done:
	fclose(fp);
	return ret;
}
