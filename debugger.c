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
#include <unistd.h>

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


typedef struct handle {
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    Elf64_Shdr *shdr;
    uint8_t *mem;
    char *symbol_name;
    Elf64_Addr symbol_addr;
    struct user_regs_struct regs;
    char *exec;
} handle_t;

Elf64_Addr lookup_by_symbol(handle_t *, const char *);

int main(int argc, char **argv, char **envp) {
    if (argc < 3) {
        printf("Usage: %s <program> <function>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    handle_t h;
    memset(&h, 0, sizeof(handle_t));
    if ((h.exec = strdup(argv[1])) == NULL) {
        perror("strdup");
        exit(EXIT_FAILURE);
    }
    char *args[2];
    args[0] = h.exec;
    args[1] = NULL;
    if ((h.symbol_name = strdup(argv[2])) == NULL) {
        perror("strdup");
        exit(EXIT_FAILURE);
    }
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
    if ((h.mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED) {
        perror("mmap");
        exit(EXIT_FAILURE);
    }
    // split the mem into ehdr, phdr, shdr
    h.ehdr = (Elf64_Ehdr *)h.mem;
    h.phdr = (Elf64_Phdr *)(h.mem + h.ehdr->e_phoff);
    h.shdr = (Elf64_Shdr *)(h.mem + h.ehdr->e_shoff);
    
    if (h.mem[0] != 0x7f && !strcmp((char *)&h.mem[1], "ELF")) {
        printf("Not an ELF file\n");
        exit(EXIT_FAILURE);
    }
    if (h.ehdr->e_type != ET_EXEC) {
      printf("%s is not an ELF executable\n", h.exec);
      exit(-1);
    }
    if (h.ehdr->e_machine != EM_X86_64) {
        printf("Not an x86_64 executable\n");
        exit(EXIT_FAILURE);
    }
    if (h.ehdr->e_shstrndx == 0 || h.ehdr->e_shoff == 0 || h.ehdr->e_shnum == 0) {
        printf("No section header\n");
        exit(EXIT_FAILURE);
    }
    if ((h.symbol_addr = lookup_by_symbol(&h, h.symbol_name)) == 0) {
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
    if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace");
            exit(EXIT_FAILURE);
        }
        if (execve(h.exec, args, envp) < 0) {
            perror("execve");
            exit(EXIT_FAILURE);
        }
        exit(EXIT_SUCCESS);
    }
    int status;
    wait(&status);

    printf("Tracing pid %d at %lx\n", pid, h.symbol_addr);
    
    long trap, orig;
    // get original instruction
    orig = ptrace(PTRACE_PEEKTEXT, pid, h.symbol_addr, NULL);
    // modify to trap instruction
    trap = (orig & ~0xff) | 0xcc;
    ptrace(PTRACE_POKETEXT, pid, h.symbol_addr, trap);

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
            if (ptrace(PTRACE_GETREGS, pid, NULL, &h.regs) < 0) {
                perror("PTRACE_GETREGS");
                exit(EXIT_FAILURE);
            }
            printf("\n");
            printf("%%rax: %llx\n", h.regs.rax);
            printf("%%rbx: %llx\n", h.regs.rbx);
            printf("%%rcx: %llx\n", h.regs.rcx);
            printf("%%rdx: %llx\n", h.regs.rdx);
            printf("%%rsi: %llx\n", h.regs.rsi);
            printf("%%rdi: %llx\n", h.regs.rdi);
            printf("%%rbp: %llx\n", h.regs.rbp);
            printf("%%rsp: %llx\n", h.regs.rsp);
            printf("%%r8: %llx\n", h.regs.r8);
            printf("%%r9: %llx\n", h.regs.r9);
            printf("%%r10: %llx\n", h.regs.r10);
            printf("%%r11: %llx\n", h.regs.r11);
            printf("%%r12: %llx\n", h.regs.r12);
            printf("%%r13: %llx\n", h.regs.r13);
            printf("%%r14: %llx\n", h.regs.r14);
            printf("%%r15: %llx\n", h.regs.r15);
            printf("%%rip: %llx\n", h.regs.rip);
            printf("%%rflags: %llx\n", h.regs.eflags);
            printf("%%cs: %llx\n", h.regs.cs);
            printf("%%ss: %llx\n", h.regs.ss);
            printf("%%ds: %llx\n", h.regs.ds);
            printf("%%es: %llx\n", h.regs.es);
            printf("%%fs: %llx\n", h.regs.fs);
            printf("%%gs: %llx\n", h.regs.gs);
            printf("\nPlease hit any key to continue: ");
            getchar();
            if (ptrace(PTRACE_POKETEXT, pid, h.symbol_addr, orig) < 0) {
                perror("PTRACE_POKETEXT");
                exit(EXIT_FAILURE);
            }
            h.regs.rip -= 1;
            if (ptrace(PTRACE_SETREGS, pid, NULL, &h.regs) < 0) {
                perror("PTRACE_SETREGS");
                exit(EXIT_FAILURE);
            }
            if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0) {
                perror("PTRACE_SINGLESTEP");
                exit(EXIT_FAILURE);
            }
            wait(NULL);
            if (ptrace(PTRACE_POKETEXT, pid, h.symbol_addr, trap) < 0) {
                perror("PTRACE_POKETEXT");
                exit(EXIT_FAILURE);
            }
        }
    }
    if (WIFEXITED(status)) {
        printf("Completed tracing pid: %d\n", pid);
        exit(EXIT_SUCCESS);
    }
}

Elf64_Addr lookup_by_symbol(handle_t *h, const char *symname) {
  int i, j;
  char *strtab;
  Elf64_Sym *symtab;
  for (i = 0; i < h->ehdr->e_shnum; i++) {
    if (h->shdr[i].sh_type == SHT_SYMTAB) {
      strtab = (char *)&h->mem[h->shdr[h->shdr[i].sh_link].sh_offset];
      symtab = (Elf64_Sym *)&h->mem[h->shdr[i].sh_offset];
      for (j = 0; j < h->shdr[i].sh_size / sizeof(Elf64_Sym); j++, symtab++) {
        if (strcmp(&strtab[symtab->st_name], symname) == 0)
          return (symtab->st_value);
      }
    }
  }
  return 0;
}