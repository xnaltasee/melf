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
	switch (elf_buf->e_ident[EI_OSABI]) {
	case ELFOSABI_HPUX:
		return "HP-UX";
	case ELFOSABI_NETBSD:
		return "NetBSD";
	case ELFOSABI_LINUX:
		return "Linux";
	case ELFOSABI_SOLARIS:
		return "Solaris";
	case ELFOSABI_IRIX:
		return "IRIX";
	case ELFOSABI_FREEBSD:
		return "FreeBSD";
	case ELFOSABI_TRU64:
		return "TRU64 UNIX";
	case ELFOSABI_ARM:
		return "ARM";
	case ELFOSABI_STANDALONE:
		return "Stand-alone";
	}
	return "UNIX - System V";
}

static int parse_elfheader_abiver(Elf64_Ehdr *elf_buf)
{
	return elf_buf->e_ident[EI_ABIVERSION];
}

static char *parse_elfheader_type(Elf64_Ehdr *elf_buf)
{
	switch (elf_buf->e_type) {
	case ET_REL:
		return "REL (Relocatable file)";
	case ET_EXEC:
		return "EXEC (Executable file)";
	case ET_DYN:
		return "DYN (Shared object)";
	case ET_CORE:
		return "CORE (Core file)";
	}
	return "NONE (Uknown type)";
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

	Elf64_Ehdr *test = (Elf64_Ehdr *)buffer;
	if (valid_elfheader(test)) {
		printf("Class   : ELF%s\n", parse_elfheader_class(test));
		printf("Data    : %s\n", parse_elfheader_data(test));
		printf("Version : %s\n", parse_elfheader_version(test));
		printf("OS/ABI  : %s\n", parse_elfheader_osabi(test));
		printf("ABI ver : %#x\n", parse_elfheader_abiver(test));
		printf("Type    : %s\n", parse_elfheader_type(test));
	} else {
		ret = 1;
		printf("Not an ELF file\n");
	}

done:
	fclose(fp);
	return ret;
}
