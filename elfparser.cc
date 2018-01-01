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
#include <unistd.h> //read
#include <assert.h> //assert

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

void 
read_elf_phdr(int fd, Elf64_Ehdr* hdr)
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
print_elf_hdr(Elf64_Ehdr* hdr)
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
    printf("e_machine     = %-s\n", e_machine[hdr->e_machine]);
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
    printf("e_shstrndx    = %-s\n",  e_shstrndx[hdr->e_shstrndx]);

}

int main(int argc, char** argv)
{
    int fd;
    Elf64_Ehdr hdr;

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

    read_elf_phdr(fd, &hdr);   
    
    bool checker = check_if_valid_elf(&hdr);
    if(checker)
    {
        std::cout << "This is a valid elf file." << std::endl;
    }
    else 
    {
        std::cout << "This is a invalid elf file!" << std::endl;
        exit(-1);
    }

    print_elf_hdr(&hdr);
}
