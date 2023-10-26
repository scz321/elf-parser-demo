#include <stdio.h>
#include <stdbool.h> //乐，c语言原生没有bool类型
#include <string.h>
#define BUF_MAX (1024 * 1024)
#define IS_DEBUGGING false // 用来控制是否进行debug输出相关信息

// Elf32_Ehdr的定义是和数据的实际排布方式一致的，所以，按照手册，给出
// 完整的定义方式是一种更加高效的方式！

// 32 bit elf
//  typedef struct {
//      unsigned char e_ident[16]; /* ELF identification */
//      __uint16_t e_type;         /* Object file type */
//      __uint16_t e_machine;      /* Machine type */
//      __uint32_t e_version;      /* Object file version */
//      __uint32_t e_entry;        /* Entry point address */
//      __uint32_t e_phoff;        /* Program header offset */
//      __uint32_t e_shoff;        /* Section header offset */
//      __uint32_t e_flags;        /* Processor-specific flags */
//      __uint16_t e_ehsize;       /* ELF header size */
//      __uint16_t e_phentsize;    /* Size of program header entry */
//      __uint16_t e_phnum;        /* Number of program header entries */
//      __uint16_t e_shentsize;    /* Size of section header entry */
//      __uint16_t e_shnum;        /* Number of section header entries */
//      __uint16_t e_shstrndx;     /* Section name string table index */
//  } Elf32_Ehdr;

// typedef struct {
//     __uint32_t sh_name;        /* Section name */
//     __uint32_t sh_type;        /* Section type */
//     __uint32_t sh_flags;       /* Section attributes */
//     __uint32_t sh_addr;        /* Virtual address in memory */
//     __uint32_t sh_offset;      /* Offset in file */
//     __uint32_t sh_size;        /* Size of section */
//     __uint32_t sh_link;        /* Link to related section */
//     __uint32_t sh_info;        /* Miscellaneous information */
//     __uint32_t sh_addralign;   /* Address alignment boundary */
//     __uint32_t sh_entsize;     /* Size of entries, if section has table */
// } Elf32_Shdr;

// typedef struct {
//     __uint32_t st_name;
//     __uint32_t st_value;
//     __uint32_t st_size;
//     unsigned char st_info;
//     unsigned char st_other;
//     __uint16_t st_shndx;
// } Elf_Sym;

// 64 bit elf
typedef struct
{
	unsigned char e_ident[16]; /* ELF identification */
	__uint16_t e_type;		   /* Object file type */
	__uint16_t e_machine;	   /* Machine type */
	__uint32_t e_version;	   /* Object file version */
	__uint64_t e_entry;		   /* Entry point address */
	__uint64_t e_phoff;		   /* Program header offset */
	__uint64_t e_shoff;		   /* Section header offset */
	__uint32_t e_flags;		   /* Processor-specific flags */
	__uint16_t e_ehsize;	   /* ELF header size */
	__uint16_t e_phentsize;	   /* Size of program header entry */
	__uint16_t e_phnum;		   /* Number of program header entries */
	__uint16_t e_shentsize;	   /* Size of section header entry */
	__uint16_t e_shnum;		   /* Number of section header entries */
	__uint16_t e_shstrndx;	   /* Section name string table index */
} Elf64_Ehdr;
Elf64_Ehdr *header;

typedef struct
{
	__uint32_t sh_name;		 /* Section name */
	__uint32_t sh_type;		 /* Section type */
	__uint64_t sh_flags;	 /* Section attributes */
	__uint64_t sh_addr;		 /* Virtual address in memory */
	__uint64_t sh_offset;	 /* Offset in file */
	__uint64_t sh_size;		 /* Size of section */
	__uint32_t sh_link;		 /* Link to related section */
	__uint32_t sh_info;		 /* Miscellaneous information */
	__uint64_t sh_addralign; /* Address alignment boundary */
	__uint64_t sh_entsize;	 /* Size of entries, if section has table */
} Elf64_Shdr;
Elf64_Shdr *shstrtbl; // 一个特殊的元素，单独开一个全局变量来记录
Elf64_Shdr *strtbl;
Elf64_Shdr *symtbl;
// 所需要的全局变量

typedef struct
{
	__uint32_t st_name;	 /* Symbol name */
	__uint8_t st_info;	 /* Type and Binding attributes */
	__uint8_t st_other;	 /* Reserved */
	__uint16_t st_shndx; /* Section table index */
	__uint64_t st_value; /* Symbol value */
	__uint64_t st_size;	 /* Size of object (e.g., common) */
} Elf64_Sym;



// section header table//确实，看似你只需要这几个量就够了，但是
typedef struct SHTbl
{
	int e_shentsize;
	int e_shnum;
	__uint64_t e_shoff;
} SHTbl;
SHTbl sh_tbl;
// 一个全局数组，存储elf文件的所有信息,这里elfInfo数组一个元素的大小是一个字节，与二进制文件一一对应
__uint8_t elfInfo[BUF_MAX];

// char* strtbl;//这个指针记录strtbl这个特殊section的起始地址，由于我们后续自然会以字符方式逐个读取，所以char*型

// 预期功能：输入函数在汇编代码中的十六进制虚拟地址，输出解析elf文件得到的函数名
char *getFunName(__uint64_t vaddr)
{
	// 获取字符串表的起始地址
	char *strTab = (char *)&elfInfo[strtbl->sh_offset];

	// 获取符号表的起始地址
	Elf64_Sym *symTab = (Elf64_Sym *)&elfInfo[symtbl->sh_offset];

	// 计算符号表中的符号数量
	int numSymbols = symtbl->sh_size / symtbl->sh_entsize;

	// 遍历符号表
	for (int i = 0; i < numSymbols; i++)
	{
		Elf64_Sym *symbol = &symTab[i];

		// 比较符号的虚拟地址和输入的虚拟地址
		if (symbol->st_value == vaddr)
		{
			// 如果找到匹配的符号，返回符号的名字
			return &strTab[symbol->st_name];
		}
	}

	// 如果没有找到匹配的符号，返回 NULL
	return NULL;
}

// 辅助函数
// 使用已有的elf文件初始化elfInfo数组的内容
bool elfInfoInit(char *fileName)
{
	FILE *file = fopen(fileName, "rb");
	if (file == NULL)
	{
		fprintf(stderr, "Error opening file.\n");
		return false;
	}

	// Read file into elfInfo and handle errors
	size_t bytesRead = fread(elfInfo, 1, BUF_MAX, file);
	if (bytesRead == 0)
	{
		fprintf(stderr, "Error reading file.\n");
		fclose(file);
		return false;
	}

	fclose(file);
	return true;
}

// 获取section header table的相关信息，具体包括：e_shentsize、e_shnum、e_shoff
bool get_sh_info()
{
	header = (Elf64_Ehdr *)elfInfo;

	if (header->e_shoff == 0 || header->e_shentsize == 0 || header->e_shnum == 0)
	{
		fprintf(stderr, "Invalid section header.\n");
		return false;
	}

	sh_tbl.e_shentsize = header->e_shentsize;
	sh_tbl.e_shnum = header->e_shnum;
	sh_tbl.e_shoff = header->e_shoff;

	return true;
}

// 获取strtbl的相关信息，具体包括：strtbl起始位置
bool initShStrTbl()
{
	shstrtbl = (Elf64_Shdr *)&elfInfo[sh_tbl.e_shoff + (header->e_shstrndx) * header->e_shentsize];
	return true;
}

// 辅助函数：输入：已知的session name，输出该session的相关信息(返回类型为Elf64_Shdr*)
Elf64_Shdr *findByName(char *name)
{
	// 获取字符串表的起始地址
	char *strTab = (char *)&elfInfo[shstrtbl->sh_offset];

	// 遍历所有 section headers
	for (int i = 0; i < sh_tbl.e_shnum; i++)
	{
		Elf64_Shdr *shdr = (Elf64_Shdr *)&elfInfo[sh_tbl.e_shoff + i * sh_tbl.e_shentsize];
		char *secName = &strTab[shdr->sh_name];

		// 比较 section 的名字和输入的名字
		if (strcmp(secName, name) == 0)
		{
			return shdr;
		}
	}

	// 如果没有找到匹配的 section，返回 NULL
	return NULL;
}

int main(int argc, char *argv[])
{
	char *fName = "t1";
	if (argc < 2)
	{
		fprintf(stderr, "Usage: %s <ELF file>\n", argv[0]);
		return 1;
	}

	if (!elfInfoInit(argv[1]))
	{
		return 1;
	}
	if (IS_DEBUGGING)
	{
		printf("部分elf-header信息:\n");
		for (int i = 0; i < 64; i++)
		{
			printf("%02x ", elfInfo[i]);
			if ((i + 1) % 16 == 0)
				printf("\n");
		}
	}

	if (!get_sh_info(&sh_tbl))
	{
		return 1;
	}
	if (IS_DEBUGGING)
	{
		printf("get_sh_info执行后，sh_tbl:\n");
		printf(" sh_tbl.e_shentsize:%d\n", sh_tbl.e_shentsize);
		printf(" sh_tbl.e_shnum:%d\n", sh_tbl.e_shnum);
		printf(" sh_tbl.e_shoff:%lu\n", sh_tbl.e_shoff);
	}

	if (!initShStrTbl())
	{
		printf("initStrTbl执行出现问题！\n");
		return 1;
	}
	if (IS_DEBUGGING)
	{
		printf("initShStrTbl执行后:\n");
		// printf("strtbl对应的第一个字符串：%s\n", strtbl);
		// printf("strtbl指针实际值：0x%02x\n", strtbl);
		printf("shstrtbl->sh_offset:0x%08lx\n", shstrtbl->sh_offset);
	}
	strtbl = findByName(".strtab");
	symtbl = findByName(".symtab");
	// TODO: Implement further logic
	// char* ret=getFunName()
	char* ret=getFunName(4471);
	printf("预期是输出：main，实际输出：%s\n",ret);
	return 0;
}
