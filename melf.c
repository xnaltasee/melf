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
	char *class_data[] = {
		[ELFCLASS32] = "32",
		[ELFCLASS64] = "64"
	};

	if (class_data[elf_buf->e_ident[EI_CLASS]])
		return class_data[elf_buf->e_ident[EI_CLASS]];

	return "Unknown";
}

static char *parse_elfheader_data(Elf64_Ehdr *elf_buf)
{
	char *elf_data[] = {
		[ELFDATA2LSB] = "little-endian",
		[ELFDATA2MSB] = "big-endian"
	};

	if (elf_data[elf_buf->e_ident[EI_DATA]])
		return elf_data[elf_buf->e_ident[EI_DATA]];

	return "Unknown";
}

static char *parse_elfheader_version(Elf64_Ehdr *elf_buf)
{
	return !!(elf_buf->e_ident[EI_VERSION]) ? "Current" : "Invalid";
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

static char *parse_elfheader_machine(Elf64_Ehdr *elf_buf)
{
	/* This list is from https://man7.org/linux/man-pages/man5/elf.5.html .
	 * Still not complete but usable for some machine like AMD x86-64 */
	char *elfmachine_data[] = {
		[EM_M32] = "AT&T WE 32100",
		[EM_SPARC] = "Sun Microsystems SPARC",
		[EM_386] = "Intel 80386",
		[EM_68K] = "Motorola 68000",
		[EM_88K] = "Motorola 88000",
		[EM_MIPS] = "MIPS RS3000 (big endian)",
		[EM_PARISC] = "HP/PA",
		[EM_SPARC32PLUS] = "SPARC 32+",
		[EM_PPC] = "PowerPC",
		[EM_PPC64] = "PowerPC 64-bit",
		[EM_S390] = "IBM S/390",
		[EM_SH] = "Renesas SuperH",
		[EM_SPARCV9] = "SPARC v9 64-bit",
		[EM_IA_64] = "Intel Itanium",
		[EM_X86_64] = "AMD x86-64",
		[EM_VAX] = "DEC Vax"
	};

	if (elfmachine_data[elf_buf->e_machine])
		return elfmachine_data[elf_buf->e_machine];

	return "Unknown";
}

static Elf64_Addr parse_elfheader_entry(Elf64_Ehdr *elf_buf)
{
	return elf_buf->e_entry;
}

static Elf64_Off parse_elfheader_phoff(Elf64_Ehdr *elf_buf)
{
	return elf_buf->e_phoff;
}

static Elf64_Off parse_elfheader_shoff(Elf64_Ehdr *elf_buf)
{
	return elf_buf->e_shoff;
}

static uint32_t parse_elfheader_flags(Elf64_Ehdr *elf_buf)
{
	return elf_buf->e_flags;
}

static uint16_t parse_elfheader_ehsize(Elf64_Ehdr *elf_buf)
{
	return elf_buf->e_ehsize;
}

static uint16_t parse_elfheader_phentsize(Elf64_Ehdr *elf_buf)
{
	return elf_buf->e_phentsize;
}

static uint16_t parse_elfheader_phnum(Elf64_Ehdr *elf_buf)
{
	return elf_buf->e_phnum;
}

static uint16_t parse_elfheader_shentsize(Elf64_Ehdr *elf_buf)
{
	return elf_buf->e_shentsize;
}

static uint16_t parse_elfheader_shnum(Elf64_Ehdr *elf_buf)
{
	return elf_buf->e_shnum;
}

static uint16_t parse_elfheader_shstrndx(Elf64_Ehdr *elf_buf)
{
	return elf_buf->e_shstrndx;
}

static void dump_elfheader(Elf64_Ehdr *elf_buf)
{
	printf("Magic   : ");

	for (int i = 0; i < EI_NIDENT; i++)
		printf("%02x ", elf_buf->e_ident[i]);
	printf("\n");

	printf("Class                              : ELF%s\n",
				parse_elfheader_class(elf_buf));
	printf("Data                               : %s\n",
				parse_elfheader_data(elf_buf));
	printf("Version                            : %s\n",
				parse_elfheader_version(elf_buf));
	printf("OS/ABI                             : %s\n",
				parse_elfheader_osabi(elf_buf));
	printf("ABI version                        : %#x\n",
				parse_elfheader_abiver(elf_buf));
	printf("Type                               : %s\n",
				parse_elfheader_type(elf_buf));
	printf("Machine                            : %s\n",
				parse_elfheader_machine(elf_buf));
	printf("Entry virtual address              : %#lx\n",
				parse_elfheader_entry(elf_buf));
	printf("Program header table's file offset : %lu bytes\n",
				parse_elfheader_phoff(elf_buf));
	printf("Section header table's file offset : %lu bytes\n",
				parse_elfheader_shoff(elf_buf));
	printf("Flags                              : %#x\n",
				parse_elfheader_flags(elf_buf));
	printf("Size of this ELF header            : %u bytes\n",
				parse_elfheader_ehsize(elf_buf));
	printf("Size of program header table       : %u bytes\n",
				parse_elfheader_phentsize(elf_buf));
	printf("Number of program header table     : %u\n",
				parse_elfheader_phnum(elf_buf));
	printf("Size of section header's           : %u bytes\n",
				parse_elfheader_shentsize(elf_buf));
	printf("Number of section header table     : %u\n",
				parse_elfheader_shnum(elf_buf));
	printf("Section header table index         : %u\n",
				parse_elfheader_shstrndx(elf_buf));
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

	size_t r = fread(buffer, sizeof(*buffer), sizeof(Elf64_Ehdr), fp);
	if (r != sizeof(Elf64_Ehdr)) {
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
