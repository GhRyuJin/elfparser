/**
Author : beautifularea
Date   : 1/1/2018
Function : parse elf file.
*/

#include <iostream> //std::cout
#include <elf.h> //elf
#include <stdlib.h> // exit()
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h> //open
#include <unistd.h> //read lseek
#include <assert.h> //assert
#include <string.h> //strcat 

/*
Elf header
*/
//EI_CLASS
const static char* ei_class[] = {"ELFCLASSNONE", "ELFCLASS32", "ELFCLASS64"};

//EI_DATA
const static char* ei_data[] = {"ELFDATANONE", "ELFDATA2LSB", "ELFDATA2MSB"};

//EI_VERSION
const static char* ei_version[] = {"EV_NONE", "EV_CURRENT"};

//EI_OSABI
const static char* ei_osabi[] = {"ELFOSABI_NONE/ELFOSABI_SYSV", "ELFOSABI_SYSV", "ELFOSABI_HPUX", "ELFOSABI_NETBSD",
                                 "ELFOSABI_LINUX", "ELFOSABI_SOLARIS", "ELFOSABI_IRIX",
                                 "ELFOSABI_FREEBSD", "ELFOSABI_TRU64", "ELFOSABI_ARM",
                                 "ELFOSABI_STANDALONE"};
//E_TYPE
const static char* e_type[] = {"ET_NONE", "ET_REL", "ET_EXEC", "ET_DYN", "ET_CORE"};

//e_machine
const static char* e_machine[] = {"EM_NONE", "EM_M32", "EM_SPARC", "EM_386", "EM_68K",
                                  "EM_88K", "EM_860", "EM_MIPS", "EM_PARISC", "EM_SPARC32PLUS",
                                  "EM_PPC", "EM_PPC64", "EM_S390", "EM_ARM", "EM_SH",
                                  "EM_SPARCV9", "EM_IA_64", "EM_X86_64", "EM_VAX"};

//e_version
const static char* e_version[] = {"EV_NONE", "EV_CURRENT"};

//e_shstrndx
const static char* e_shstrndx[] = {"SHN_UNDEF", "SHN_LORESERVE", "SHN_LOPROC", "SHN_HIPROC",
                                    "SHN_ABS", "SHN_COMMON", "SHN_HIRESERVE"};

/*
program header
*/
const static char* p_type[] = {"PT_NULL", "PT_LOAD", "PT_DYNAMIC", "PT_INTERP",
                                "PT_NOTE", "PT_SHLIB", "PT_PHDR", "PT_LOPROC",
                                "PT_HIPROC", "PT_GNU_STACK"};

/*
Section Header
*/
const static char* sh_type[] = {"SHT_NULL", "SHT_PROGBITS", "SHT_SYMTAB",
                                "SHT_STRTAB", "SHT_RELA", "SHT_HASH",
                                "SHT_DYNAMIC", "SHT_NOTE", "SHT_NOBITS",
                                "SHT_REL", "SHT_SHLIB", "SHT_DYNSYM",
                                "SHT_LOPROC", "SHT_HIPROC", "SHT_LOUSER",
                                "SHT_HIUSER"};

void 
read_elf_ehdr(int fd, Elf64_Ehdr* hdr)
{
    assert(hdr != NULL);
    ssize_t n = read(fd, (void*)hdr, sizeof(Elf64_Ehdr));
    std::cout << "n = " << n << "\t" << "sizeof ehdr = " << sizeof(Elf64_Ehdr) << std::endl;
    assert(n == sizeof(Elf64_Ehdr));
    std::cout << "Read elf file completely." << std::endl;
}

bool
check_if_valid_elf(Elf64_Ehdr* hdr)
{
    assert(hdr != NULL);

    //check e_ident array's first byte, it must be filled with ELFMAG0(0x7f)
    //2-E 3-L 4-F
    return (hdr->e_ident[0] == 0x7f) &&
           (hdr->e_ident[1] == 'E' ) &&
           (hdr->e_ident[2] == 'L' ) &&
           (hdr->e_ident[3] == 'F' );
}

void
print_elf_ehdr(Elf64_Ehdr* hdr)
{
    assert(hdr != NULL);

    printf("--------------Elf64_Ehdr-------------\n");
    printf("e_ident : \n");
    printf("%-5c %-5c %-5c %-5c\n", hdr->e_ident[0], 
                                    hdr->e_ident[1],
                                    hdr->e_ident[2],
                                    hdr->e_ident[3]);

    printf("EI_CLASS      = %-s\n", ei_class[hdr->e_ident[4]]);
    printf("EI_DATA       = %-s\n", ei_data[hdr->e_ident[5]]);
    printf("EI_VERSION    = %-s\n", ei_version[hdr->e_ident[6]]);
    printf("EI_OSABI      = %-s\n", ei_osabi[hdr->e_ident[7]]);
    printf("EI_ABIVERSION = %-d\n", hdr->e_ident[8]);
    printf("EI_PAD        = %-d\n", hdr->e_ident[EI_PAD]);
    printf("EI_NIDENT     = %-d\n", hdr->e_ident[EI_NIDENT]);
    printf("e_type        = %-s\n", e_type[hdr->e_type]);
    printf("e_machine     = %-u\n", hdr->e_machine);
    printf("e_version     = %-s\n", e_version[hdr->e_version]);
    printf("e_entry       = 0x%08x\n", (int)hdr->e_entry);
    printf("e_ehsize      = 0x%x\n", hdr->e_ehsize);
    printf("e_phoff       = 0x%x\n", (int)hdr->e_phoff);
    printf("e_shoff       = 0x%x\n", (int)hdr->e_shoff);
    printf("e_flags       = %d\n",   hdr->e_flags);
    printf("e_phentsize   = %d\n",   hdr->e_phentsize);
    printf("e_phum        = %d\n",   hdr->e_phnum);
    printf("e_shentsize   = %d\n",   hdr->e_shentsize);
    printf("e_shnum       = %d\n",   hdr->e_shnum);
    printf("e_shstrndx    = 0x%x\n", hdr->e_shstrndx);
    /*
    std::cout << "0-" << SHN_LOPROC << std::endl;
    std::cout << "1" << SHN_UNDEF << std::endl;
    std::cout << "2" << SHN_LORESERVE << std::endl;
    std::cout << "3" << SHN_HIPROC << std::endl;
    std::cout << "4" << SHN_ABS << std::endl;
    std::cout << "5" << SHN_COMMON << std::endl;
    std::cout << "6" << SHN_HIRESERVE << std::endl;
    */
}

void
read_elf_phdr(int fd, Elf64_Phdr* phdr, Elf64_Ehdr* ehdr)
{
    assert(phdr != NULL);
    off_t off = lseek(fd, ehdr->e_phoff, SEEK_SET);
    assert(off == (off_t)ehdr->e_phoff);

    for(size_t i = 0; i < ehdr->e_phnum; ++i) {
        size_t n = read(fd, (void*)(&phdr[i]), sizeof(Elf64_Phdr));
        assert(n == ehdr->e_phentsize);
    }
}

void
print_elf_phdr(Elf64_Phdr* phdr, Elf64_Ehdr* ehdr)
{
    assert(phdr != NULL && ehdr != NULL);

    printf("************ Program Header ************\n");

    std::cout << "program header num =  " << ehdr->e_phnum << std::endl;

    for(size_t i = 0; i < ehdr->e_phnum; ++i) {
        Elf64_Phdr *phdr_ = &phdr[i];    
        printf("\n"); 
        
        /*
        */
        printf("Type                : %u\n", phdr_->p_type);//p_type[phdr_->p_type]);
        printf("Offset              : %lu\n", phdr_->p_offset);
        printf("Virtual Address     : 0x%x\n", (int)phdr_->p_vaddr);
        printf("Physical Address    : 0x%x\n", (int)phdr_->p_paddr);
        printf("File Size           : %lu\n", phdr_->p_filesz);
        printf("Memory Size         : %lu\n", phdr_->p_memsz);
        //flags
        /*char flags[16];
        uint32_t flag = phdr_->p_flags;
        if(flag & 0x01)
        {
            strcat(flags, "PF_X ");
        }
        if(flag & 0x02)
        {
            strcat(flags, "PF_W ");
        }
        if(flag & 0x04)
        {
            strcat(flags, "PF_R ");
        }
        */

        printf("Flags               : %u\n",  phdr_->p_flags);
        printf("Align               : %lu\n", phdr_->p_align);
    }
}

void
read_elf_shdr(int fd, Elf64_Shdr* shdr, Elf64_Ehdr* ehdr)
{
    assert(shdr != NULL);
    assert(ehdr != NULL);

    off_t off = lseek(fd, ehdr->e_shoff, SEEK_SET);
    assert(off == ehdr->e_shoff);

    for(size_t i = 0; i < ehdr->e_shnum; i++)
    {
        size_t n = read(fd, (void*)(&shdr[i]), sizeof(Elf64_Shdr));
        assert(n == ehdr->e_shentsize);
    }
}

void
print_elf_shdr(Elf64_Shdr* shdr, Elf64_Ehdr* ehdr)
{
    assert(shdr != NULL);
    assert(ehdr != NULL);

    printf("************ Section Header ************\n");
    printf("Name                : %u\n", shdr->sh_name);
    printf("Type                : %s\n", sh_type[shdr->sh_type]);
    
    char flag[49];
    uint32_t flags = shdr->sh_flags;
    if(flags ==0)
        goto xxx;
    if(flags & SHF_WRITE)
    {
        strcat(flag, "SHF_WRITE ");
    }
    if(flags & SHF_ALLOC)
    {
        strcat(flag, "SHF_ALLOC ");
    }
    if(flags & SHF_EXECINSTR)
    {
        strcat(flag, "SHF_EXECINSTR ");
    }
    if(flags & SHF_MASKPROC)
    {
        strcat(flag, "SHF_MASKPROC ");
    }
    printf("Flag                : %s\n", flag);
    xxx:
    printf("Flag                : %d\n", flags);

    printf("Address             : 0x%x\n", (int)shdr->sh_addr);
    printf("Offset              : %lu\n", shdr->sh_offset);
    printf("Size                : %lu\n", shdr->sh_size);
    printf("Link                : %u\n", shdr->sh_link);
    printf("Info                : %u\n", shdr->sh_info);
    printf("Align               : %lu\n", shdr->sh_addralign);
    printf("Entsize             : %lu\n", shdr->sh_entsize);
}

int main(int argc, char** argv)
{
    int fd;
    Elf64_Ehdr ehdr;

    if(argc < 2)
    {
        std::cout << "Error input file!" << std::endl;
        std::cout << "Eg. parser xxx(your elf file) " << std::endl;
        exit(-1);
    }

    fd = open(argv[1], O_RDONLY);
    if(fd < 0)
    {
        std::cout << "Invalid file, Cannot open it!" << std::endl;
    }
    else
    {
        std::cout << "Open elf file [" << argv[1] << "] correctly." << std::endl;
    }

    read_elf_ehdr(fd, &ehdr);   
    
    bool checker = check_if_valid_elf(&ehdr);
    if(checker)
    {
        std::cout << "This is a valid elf file." << std::endl;
    }
    else 
    {
        std::cout << "This is a invalid elf file!" << std::endl;
        exit(-1);
    }
    print_elf_ehdr(&ehdr);

    //program header
    Elf64_Phdr* phdr = (Elf64_Phdr*)malloc(ehdr.e_phnum * ehdr.e_phentsize);
    if(phdr != NULL)
    {
        read_elf_phdr(fd, phdr, &ehdr);
        print_elf_phdr(phdr, &ehdr);
    }
    else
    {
        printf("Program Header : Failed to malloc %d bytes\n", (int)(ehdr.e_phnum * ehdr.e_phentsize));
        exit(-1);
    }

    //section header
    Elf64_Shdr* shdr = (Elf64_Shdr*)malloc(ehdr.e_shnum * ehdr.e_shentsize);
    if(shdr != NULL)
    {
        read_elf_shdr(fd, shdr, &ehdr);
        print_elf_shdr(shdr, &ehdr);
    }
    else
    {
        printf("Section Header : Failed to malloc %d bytes\n", (ehdr.e_shnum * ehdr.e_shentsize));
    }
}
