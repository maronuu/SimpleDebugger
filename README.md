# Small debugger with ptrace

## How to build
```bash
make
```

## How to execute
### Prepare executable ELF files to be debugged
#### print string
```bash
gcc -no-pie test_print.c -o test_print
```
#### add

```bash
gcc -no-pie test_add.c -o test_add

```
### Run debugger
```bash
// ./debugger <ELF executable> <symbol name>
./debugger test_print print_string

./debugger test_add add
```

At every breakpoint (i.e., given symbol name), the debugger displays the current register state. To proceed, press the Enter key.
