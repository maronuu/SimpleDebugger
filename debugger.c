#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#define OPCODE_INT3 0xcc

// struct user_regs_struct {
//     unsigned long long int r15;
//     unsigned long long int r14;
//     unsigned long long int r13;
//     unsigned long long int r12;
//     unsigned long long int rbp;
//     unsigned long long int rbx;
//     unsigned long long int r11;
//     unsigned long long int r10;
//     unsigned long long int r9;
//     unsigned long long int r8;
//     unsigned long long int rax;
//     unsigned long long int rcx;
//     unsigned long long int rdx;
//     unsigned long long int rsi;
//     unsigned long long int rdi;
//     unsigned long long int orig_rax;
//     unsigned long long int rip;
//     unsigned long long int cs;
//     unsigned long long int eflags;
//     unsigned long long int rsp;
//     unsigned long long int ss;
//     unsigned long long int fs_base;
//     unsigned long long int gs_base;
//     unsigned long long int ds;
//     unsigned long long int es;
//     unsigned long long int fs;
//     unsigned long long int gs;
// };

typedef struct ElfHandler {
    Elf64_Ehdr *ehdr;             // ELF header
    Elf64_Phdr *phdr;             // program header
    Elf64_Shdr *shdr;             // section header
    uint8_t *mem;                 // memory map of the executable
    char *exec_cmd;               // exec command
    char *symbol_name;            // symbol name to be traced
    Elf64_Addr symbol_addr;       // symbol address
    struct user_regs_struct regs; // registers
} ElfHandler_t;

Elf64_Addr lookup_symbol_addr_by_name(ElfHandler_t *, const char *);
void display_registers(const ElfHandler_t *);

int main(int argc, char **argv, char **envp) {
    // parse command line arguments
    if (argc < 3) {
        printf("Usage: %s <program> <function>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    ElfHandler_t eh;
    memset(&eh, 0, sizeof(ElfHandler_t));
    if ((eh.exec_cmd = strdup(argv[1])) == NULL) {
        perror("strdup");
        exit(EXIT_FAILURE);
    }
    char *args[2];
    args[0] = eh.exec_cmd;
    args[1] = NULL;
    if ((eh.symbol_name = strdup(argv[2])) == NULL) {
        perror("strdup");
        exit(EXIT_FAILURE);
    }

    // read and dump elf file
    int fd;
    if ((fd = open(argv[1], O_RDONLY)) < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        exit(EXIT_FAILURE);
    }
    if ((eh.mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED) {
        perror("mmap");
        exit(EXIT_FAILURE);
    }
    // split the mem into ehdr, phdr, shdr
    eh.ehdr = (Elf64_Ehdr *)eh.mem;
    eh.phdr = (Elf64_Phdr *)(eh.mem + eh.ehdr->e_phoff);
    eh.shdr = (Elf64_Shdr *)(eh.mem + eh.ehdr->e_shoff);

    // validate the elf file
    if (eh.mem[0] != 0x7f && !strcmp((char *)&eh.mem[1], "ELF")) {
        printf("Not an ELF file\n");
        exit(EXIT_FAILURE);
    }
    if (eh.ehdr->e_type != ET_EXEC) {
        printf("%s is not an ELF executable\n", eh.exec_cmd);
        exit(-1);
    }
    if (eh.ehdr->e_machine != EM_X86_64) {
        printf("Not an x86_64 executable\n");
        exit(EXIT_FAILURE);
    }
    if (eh.ehdr->e_shstrndx == 0 || eh.ehdr->e_shoff == 0 || eh.ehdr->e_shnum == 0) {
        printf("No section header\n");
        exit(EXIT_FAILURE);
    }

    // lookup the symbol
    if ((eh.symbol_addr = lookup_symbol_addr_by_name(&eh, eh.symbol_name)) == 0) {
        printf("Symbol not found\n");
        exit(EXIT_FAILURE);
    }
    close(fd);

    // fork and exec
    int pid;
    if ((pid = fork()) < 0) {
        perror("fork");
        exit(EXIT_FAILURE);
    }
    // child executes the given program
    if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace");
            exit(EXIT_FAILURE);
        }
        if (execve(eh.exec_cmd, args, envp) < 0) {
            perror("execve");
            exit(EXIT_FAILURE);
        }
        exit(EXIT_SUCCESS);
    }
    int status;
    wait(&status);

    // beginning of tracing
    printf("Tracing pid:%d at symbol addr %lx\n", pid, eh.symbol_addr);

    // get original instruction
    const long original_inst = ptrace(PTRACE_PEEKTEXT, pid, eh.symbol_addr, NULL);
    // modify to trap instruction
    const long trap_inst = (original_inst & ~0xff) | OPCODE_INT3;
    ptrace(PTRACE_POKETEXT, pid, eh.symbol_addr, trap_inst);

    while (1) {
        // resume process execution
        if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
            perror("PTRACE_CONT");
            exit(EXIT_FAILURE);
        }
        wait(&status);

        if (WIFEXITED(status)) {
            break;
        }
        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
            // get registers info and display them
            if (ptrace(PTRACE_GETREGS, pid, NULL, &eh.regs) < 0) {
                perror("PTRACE_GETREGS");
                exit(EXIT_FAILURE);
            }
            display_registers(&eh);
            printf("\nPlease hit [ENTER] key to continue: ");
            getchar();
            // restore original instruction
            if (ptrace(PTRACE_POKETEXT, pid, eh.symbol_addr, original_inst) < 0) {
                perror("PTRACE_POKETEXT");
                exit(EXIT_FAILURE);
            }
            // single step to execute the original instruction
            eh.regs.rip -= 1;
            if (ptrace(PTRACE_SETREGS, pid, NULL, &eh.regs) < 0) {
                perror("PTRACE_SETREGS");
                exit(EXIT_FAILURE);
            }
            if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0) {
                perror("PTRACE_SINGLESTEP");
                exit(EXIT_FAILURE);
            }
            wait(NULL);
            // restore trap instruction
            if (ptrace(PTRACE_POKETEXT, pid, eh.symbol_addr, trap_inst) < 0) {
                perror("PTRACE_POKETEXT");
                exit(EXIT_FAILURE);
            }
        }
    }
    if (WIFEXITED(status)) {
        printf("Completed tracing pid: %d\n", pid);
    }
    exit(EXIT_SUCCESS);
}

Elf64_Addr lookup_symbol_addr_by_name(ElfHandler_t *eh, const char *target_symname) {
    char *str_tbl;
    Elf64_Sym *sym_tbl;
    Elf64_Shdr *cand_shdr;
    uint32_t link_to_str_tbl;
    char *cand_symname;

    // iterate through the section headers
    for (int i = 0; i < eh->ehdr->e_shnum; i++) {
        if (eh->shdr[i].sh_type != SHT_SYMTAB)
            continue;

        cand_shdr = &eh->shdr[i];
        // get the symbol table
        sym_tbl = (Elf64_Sym *)&eh->mem[cand_shdr->sh_offset];
        // get the string table
        link_to_str_tbl = cand_shdr->sh_link;
        str_tbl = (char *)&eh->mem[eh->shdr[link_to_str_tbl].sh_offset];

        // iterate through the symbol table
        for (int j = 0; j < eh->shdr[i].sh_size / sizeof(Elf64_Sym); j++, sym_tbl++) {
            // check if the symbol name matches
            cand_symname = &str_tbl[sym_tbl->st_name];
            if (strcmp(cand_symname, target_symname) == 0) {
                return (sym_tbl->st_value);
            }
        }
    }
    return 0;
}

void display_registers(const ElfHandler_t *eh) {
    printf("\n");
    printf("%%rax: %llx\n", eh->regs.rax);
    printf("%%rbx: %llx\n", eh->regs.rbx);
    printf("%%rcx: %llx\n", eh->regs.rcx);
    printf("%%rdx: %llx\n", eh->regs.rdx);
    printf("%%rsi: %llx\n", eh->regs.rsi);
    printf("%%rdi: %llx\n", eh->regs.rdi);
    printf("%%rbp: %llx\n", eh->regs.rbp);
    printf("%%rsp: %llx\n", eh->regs.rsp);
    printf("%%r8: %llx\n", eh->regs.r8);
    printf("%%r9: %llx\n", eh->regs.r9);
    printf("%%r10: %llx\n", eh->regs.r10);
    printf("%%r11: %llx\n", eh->regs.r11);
    printf("%%r12: %llx\n", eh->regs.r12);
    printf("%%r13: %llx\n", eh->regs.r13);
    printf("%%r14: %llx\n", eh->regs.r14);
    printf("%%r15: %llx\n", eh->regs.r15);
    printf("%%rip: %llx\n", eh->regs.rip);
    printf("%%rflags: %llx\n", eh->regs.eflags);
    printf("%%cs: %llx\n", eh->regs.cs);
    printf("%%ss: %llx\n", eh->regs.ss);
    printf("%%ds: %llx\n", eh->regs.ds);
    printf("%%es: %llx\n", eh->regs.es);
    printf("%%fs: %llx\n", eh->regs.fs);
    printf("%%gs: %llx\n", eh->regs.gs);
}