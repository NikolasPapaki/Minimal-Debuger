/* C standard library */
#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* POSIX */
#include <unistd.h>
#include <sys/user.h>
#include <sys/wait.h>

/* Linux */
#include <syscall.h>
#include <sys/ptrace.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <libelf.h>
#include <gelf.h>
#include <capstone/capstone.h>

#define TOOL "min_gdb"

#define die(...)                                \
    do                                          \
    {                                           \
        fprintf(stderr, TOOL ": " __VA_ARGS__); \
        fputc('\n', stderr);                    \
        exit(EXIT_FAILURE);                     \
    } while (0)

char *SymbolTable[100];
long unsigned int Address[100];
int myindex;

long unsigned int BreakAddress[20];
long unsigned int BreakInstructions[20];
int numBreaks;

Elf_Data *text_data = NULL;
csh handle;

long text_start;

/* Disasemble commands using capstone*/
void disas(csh handle, const unsigned char *buffer, unsigned int size, long curr_address)
{
    cs_insn *insn;
    size_t count;

    count = cs_disasm(handle, buffer, size, text_start, 0, &insn);

    if (count > 0)
    {
        size_t j = 0;
        while (insn[j].address != curr_address)
            j++;

        size_t i;
        for (i = j; i < j + 10; i++)
        {
            fprintf(stderr, "0x%" PRIx64 ":\t%s\t\t%s\n", insn[i].address, insn[i].mnemonic, insn[i].op_str);
            if (!strcmp(insn[i].mnemonic, "retq"))
                break;
        }
        cs_free(insn, count);
    }
    else
        fprintf(stderr, "ERROR: Failed to disassemble given code!\n");
}

void process_inspect(int pid)
{
    struct user_regs_struct regs;

    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
        die("%s", strerror(errno));

    long current_ins = ptrace(PTRACE_PEEKDATA, pid, regs.rip, 0);
    if (current_ins == -1)
        die("(peekdata) %s", strerror(errno));

    disas(handle, text_data->d_buf, text_data->d_size, regs.rip);
}

long set_breakpoint(int pid, long address)
{
    /* Backup current code.  */
    long previous_code = 0;
    previous_code = ptrace(PTRACE_PEEKDATA, pid, (void *)address, 0);
    if (previous_code == -1)
        die("(peekdata) %s", strerror(errno));

    /* Insert the breakpoint. */
    long trap = (previous_code & 0xFFFFFFFFFFFFFF00) | 0xCC;
    if (ptrace(PTRACE_POKEDATA, pid, (void *)address, (void *)trap) == -1)
        die("(pokedata) %s", strerror(errno));

    return previous_code;
}

void process_step(int pid)
{

    if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1)
        die("(singlestep) %s", strerror(errno));

    waitpid(pid, 0, 0);
}

void remove_breakpoint(int pid, int number)
{
    if (ptrace(PTRACE_POKEDATA, pid, (void *)BreakAddress[number - 1], (void *)BreakInstructions[number - 1]) == -1)
        die("(remove breakpoint) %s", strerror(errno));

    int j;
    for (j = number - 1; j < numBreaks - 1; j++)
    {
        BreakAddress[j] = BreakAddress[j + 1];
        BreakInstructions[j] = BreakInstructions[j + 1];
    }

    numBreaks--;
}

void serve_breakpoint_disas(int pid, long original_instruction, long address)
{
    struct user_regs_struct regs;

    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
        die("(getregs) %s", strerror(errno));

    process_inspect(pid);

    // fprintf(stderr, "Resuming.\n");

    if (ptrace(PTRACE_POKEDATA, pid, (void *)address, (void *)original_instruction) == -1)
        die("(pokedata) %s", strerror(errno));

    regs.rip = address;

    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1)
        die("(setregs) %s", strerror(errno));
}

void serve_breakpoint(int pid, long original_instruction, long address)
{
    struct user_regs_struct regs;

    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
        die("(getregs) %s", strerror(errno));

    // fprintf(stderr, "Resuming.\n");

    if (ptrace(PTRACE_POKEDATA, pid, (void *)address, (void *)original_instruction) == -1)
        die("(pokedata) %s", strerror(errno));

    regs.rip = address;

    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1)
        die("(setregs) %s", strerror(errno));
}

void load_symbol_table(char *filename)
{

    Elf *elf;

    /* Initilization.  */
    if (elf_version(EV_CURRENT) == EV_NONE)
        die("(version) %s", elf_errmsg(-1));

    int fd = open(filename, O_RDONLY);

    elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf)
        die("(begin) %s", elf_errmsg(-1));

    /* Loop over sections.  */
    Elf_Scn *scn = NULL;
    GElf_Shdr shdr;
    size_t shstrndx;

    if (elf_getshdrstrndx(elf, &shstrndx) != 0)
        die("(getshdrstrndx) %s", elf_errmsg(-1));

    int found = 0; // Flag used to determine if file has symbol table

    while ((scn = elf_nextscn(elf, scn)) != NULL)
    {
        if (gelf_getshdr(scn, &shdr) != &shdr)
            die("(getshdr) %s", elf_errmsg(-1));

        /* Locate symbol table.  */
        if (!strcmp(elf_strptr(elf, shstrndx, shdr.sh_name), ".symtab"))
        {
            found = 1;
            break;
        }
    }

    /* Call the functions to print symbol and dynamic tables*/
    if (found == 0)
    {
        fprintf(stderr, "File is stripped and symblol table cant be found\n");
        exit(-1);
    }
    else
    {
        Elf_Data *symtab_data;
        int count = 0;

        /* Get section header index. */
        if (elf_getshdrstrndx(elf, &shstrndx) != 0)
            die("(getshdrstrndx) %s", elf_errmsg(-1));

        /* Get the descriptor.  */
        if (gelf_getshdr(scn, &shdr) != &shdr)
            die("(getshdr) %s", elf_errmsg(-1));

        symtab_data = elf_getdata(scn, NULL);
        count = shdr.sh_size / shdr.sh_entsize;

        myindex = 0;
        for (int i = 0; i < count; ++i) // Loop until you process all symbols in symbol table
        {
            GElf_Sym sym;
            gelf_getsym(symtab_data, i, &sym);
            if (ELF64_ST_TYPE(sym.st_info) == STT_FUNC)
            {
                SymbolTable[myindex] = elf_strptr(elf, shdr.sh_link, sym.st_name);
                Address[myindex] = sym.st_value;
                myindex = myindex + 1;
            }
        }

        /* for (int i = 0; i < myindex; ++i)
             printf("%s\t%lx\n", SymbolTable[i], Address[i]);
        */
    }
}

/* Load .text section into buffer*/
void load_text_section(char *filename)
{

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        exit(-1);

    /* AT&T */
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);

    Elf *elf;

    /* Initilization.  */
    if (elf_version(EV_CURRENT) == EV_NONE)
        die("(version) %s", elf_errmsg(-1));

    int fd = open(filename, O_RDONLY);

    elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf)
        die("(begin) %s", elf_errmsg(-1));

    /* Loop over sections.  */
    Elf_Scn *scn = NULL;
    GElf_Shdr shdr;
    size_t shstrndx;
    if (elf_getshdrstrndx(elf, &shstrndx) != 0)
        die("(getshdrstrndx) %s", elf_errmsg(-1));

    while ((scn = elf_nextscn(elf, scn)) != NULL)
    {
        if (gelf_getshdr(scn, &shdr) != &shdr)
            die("(getshdr) %s", elf_errmsg(-1));

        /* Locate .text  */
        if (!strcmp(elf_strptr(elf, shstrndx, shdr.sh_name), ".text"))
        {
            text_data = elf_getdata(scn, text_data);
            text_start = 0x400000 + shdr.sh_offset;
            // printf("Start of .text is %lx\n\n", text_start);
        }
    }
}

long getAddress(char *name)
{

    int i;
    for (i = 0; i < myindex; i++)
        if (!strcmp(SymbolTable[i], name))
            return Address[i];

    return -1;
}

void addInstruction(long original_instraction, long address) // Add original instruction and address into parallel table
{
    fprintf(stderr, "Breakpoint %d added at address %p: \n\n", numBreaks + 1, (void *)address);
    BreakInstructions[numBreaks] = original_instraction;
    BreakAddress[numBreaks] = address;
    numBreaks++;
}

long getInstruction(long address) // Gives the original instraction at address where break point was added
{
    int i;
    for (i = 0; i < numBreaks; i++)
        if (BreakAddress[i] == address)
            return BreakInstructions[i];

    return -1;
}

void Print_breakpoints()
{
    int i;
    printf("\nList of breakpoints\n");
    for (i = 0; i < numBreaks; i++)
        printf("%d\t%ld\n", i + 1, BreakAddress[i]);
}

int checkAddress(long addr)
{

    int i;
    for (i = 0; i < numBreaks; i++)
        if (BreakAddress[i] == addr)
            return 0;

    return 1;
}

void Print_menu(pid_t pid)
{

    while (1)
    {
        printf("\n\nAdd software breakpoints (b)\n");
        printf("List currently enabled software breakpoints (l)\n");
        printf("Delete software breakpoinrs (d)\n");
        printf("Run the program (r)\n");
        printf("Continue the program (c)\n\n");

        char *temp = (char *)malloc(sizeof(char) * 10);
        char *ptr;
        char opt;
        int address;
        long original_instruction;
        struct user_regs_struct regs;

        char string[100];
        char akiro;
        scanf("%[^\n]%c", string, &akiro);
        opt = string[0];

        switch (opt)
        {
        case 'b':
            if (string[2] == '*')
            {
                address = strtoul(temp, &ptr, 16);
            }
            else
            {
                strcpy(temp, &string[2]);
                address = getAddress(temp);
            }

            if (checkAddress(address))
                addInstruction(set_breakpoint(pid, address), address);
            else
                printf("Breakpoint already added at address 0x%x\n", address);

            break;

        case 'l':
            Print_breakpoints();
            break;

        case 'd':
            strcpy(temp, &string[2]);
            remove_breakpoint(pid, atoi(temp));
            break;

        case 'r':
            ptrace(PTRACE_CONT, pid, 0, 0);
            waitpid(pid, 0, 0);

            if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
            {
                if (errno == ESRCH)
                {
                    /* System call was exit; so we need to end.  */
                    fprintf(stderr, "\n");
                    exit(regs.rdi);
                }
                die("%s", strerror(errno));
            }

            printf("-Breakpoint at 0x%llx\n\n", regs.rip - 1);
            original_instruction = getInstruction(regs.rip - 1);             // find original instraction that used to be in this address
            serve_breakpoint_disas(pid, original_instruction, regs.rip - 1); // server breakpoint
            process_step(pid);
            // printf("Re adding break point at address %llx\n", regs.rip - 1);
            set_breakpoint(pid, regs.rip - 1);
            break;

        case 'c':
            ptrace(PTRACE_CONT, pid, 0, 0);
            waitpid(pid, 0, 0);

            if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
            {
                if (errno == ESRCH)
                {
                    /* System call was exit; so we need to end.  */
                    fprintf(stderr, "\n");
                    exit(regs.rdi);
                }
                die("%s", strerror(errno));
            }

            printf("-Breakpoint at 0x%llx\n\n", regs.rip - 1);
            original_instruction = getInstruction(regs.rip - 1);       // find original instraction that used to be in this address
            serve_breakpoint(pid, original_instruction, regs.rip - 1); // server breakpoint
            process_step(pid);
            // printf("Re adding break point at address %llx\n", regs.rip - 1);
            set_breakpoint(pid, regs.rip - 1);
            break;

        default:
            printf("This not function is not supported by min_gdb\n\n");
            break;
        }
    }
}

int main(int argc, char **argv)
{
    if (argc <= 1)
        die("min_strace <program>: %d", argc);

    load_symbol_table(argv[1]); // Load symbols and their address into array
    load_text_section(argv[1]); // Load text section in buffer

    /* fork() for executing the program that is analyzed.  */
    pid_t pid = fork();
    switch (pid)
    {
    case -1: /* error */
        die("%s", strerror(errno));
    case 0: /* Code that is run by the child. */
        /* Start tracing.  */
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        /* execvp() is a system call, the child will block and
           the parent must do waitpid().
           The waitpid() of the parent is in the label
           waitpid_for_execvp.
         */
        execvp(argv[1], argv + 1);
        die("%s", strerror(errno));
    }

    /* Code that is run by the parent.  */
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);
    waitpid(pid, 0, 0);

    Print_menu(pid);

    return 0;
}
