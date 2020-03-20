/*
** inject_code.c
*/

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include "utils.h"

#define USAGE               "Usage: ./inject_code <pid_tracee> <path_bin> <func_target>"

#define SAVE_CODE           "Save code"
#define INJECT_CODE         "Inject code"
#define SAVE_REGS           "Save registers"
#define MODIFY_REGS         "Modify registers"
#define CALL_POSIX_MEMALIGN "Call posix_memalign"
#define CALL_MPROTECT       "Call mprotect"
#define RESTORE_CODE        "Restore code"
#define RESTORE_REGS        "Restore registers"
#define ERR_PARSE_OBJDUMP   "Error: could not parse objdump output"
#define ERR_OPEN_STREAM     "Error: could not open stream"
#define ERR_ALLOC_MEM       "Error: could not allocate memory in process"
#define ERR_CHANGE_PROTECT  "Error: could not change access protections"
#define ERR_POSIX_MEMALIGN  "Error: posix_memalign failed"
#define ERR_MPROTECT        "Error: mprotect failed"

#define CODE_SIZE           4

/*
 * inject_call_in_func
 */
int         inject_call_in_func(pid_t pid_tracee, long offset_func_target)
{
    char    code_inject[CODE_SIZE] = {(char)0xCC, (char)0xFF, (char)0xD0, (char)0xCC};
    FILE    *stream_mem;

    /* Open stream of tracee address space file */
    if ((stream_mem = open_stream_proc_at_offset(pid_tracee, offset_func_target, "w")) == NULL)
    {
        fprintf(stderr, "%s\n", ERR_OPEN_STREAM);
        return (-1);
    }

    /* Write to tracee address space file (0xCC, 0xFF, 0xDO, 0xCC) */
    if (fwrite(code_inject, 1, sizeof(code_inject), stream_mem) != sizeof(code_inject))
    {
        perror("fwrite");
        return (-1);
    }

    /* Close stream */
    fclose(stream_mem);

    printf("Successfully injected code at: 0x%.8lx\n", offset_func_target);

    /* Restart tracee */
    if ((ptrace(PTRACE_CONT, pid_tracee, NULL, NULL)) == -1)
    {
        perror("ptrace");
        return (-1);
    }

    /* Wait for tracee to stop */
    if (waitpid(pid_tracee, NULL, 0) == -1)
    {
        perror("waitpid");
        return (-1);
    }

    return (0);
}


/*
 * alloc_mem_in_process
 */
long        alloc_mem_in_process(pid_t pid_tracee, long offset_func_target)
{
    long    addr_posix_memalign;
    long    addr_mem_alloc;
    char    code_origin[CODE_SIZE];
    FILE    *stream_mem;
    struct user_regs_struct regs;
    struct user_regs_struct regs_copy;

    printf("%s\n", SAVE_CODE);

    /* Open stream of tracee address space file to read memory */
    if ((stream_mem = open_stream_proc_at_offset(pid_tracee, offset_func_target, "r")) == NULL)
    {
        fprintf(stderr, "%s\n", ERR_OPEN_STREAM);
        return (-1);
    }

    /* Save memory zone to replace */
    memset(code_origin, 0, CODE_SIZE);
    if (fread(code_origin, 1, CODE_SIZE, stream_mem) != CODE_SIZE)
    {
        perror("fread");
        return (-1);
    }

    /* Close stream */
    if (fclose(stream_mem) != 0)
    {
        perror("fclose");
        return (-1);
    }

    printf("%s\n", INJECT_CODE);

    /* Inject call in function via RAX register (accumulator) */
    if (inject_call_in_func(pid_tracee, offset_func_target) == -1)
    {
        fprintf(stderr, "%s\n", ERR_ALLOC_MEM);
        return (-1);
    }

    printf("%s\n", SAVE_REGS);

    /* Get registers values from tracee */
    if (ptrace(PTRACE_GETREGS, pid_tracee, &regs, &regs) == -1)
    {
        perror("ptrace");
        return (-1);
    }

    /* Save registers original values */
    regs_copy = regs;

    printf("%s\n", MODIFY_REGS);

    /* Get address of posix_memalign function in libc */
    addr_posix_memalign = get_addr_libc_func(pid_tracee, "__posix_memalign");

    /* Modify registers to call posix_memalign funtion */
    regs.rax = addr_posix_memalign; // Put in RAX posix_memalign address
    regs.rip = offset_func_target + 1; // Put in RIP address of next instruction

    /* Initialize function parameters posix_memalign(void**, size_t, size_t) */
    regs.rdi = regs.rsp; // Put in RDI a pointer to top of stack
    regs.rsi = getpagesize(); // Put in RSI number of bytes in a memory page
    regs.rdx = getpagesize(); // Put in RDX number of bytes in a memory page

    /* Display registers */
    printf("RIP: 0x%.8llx\n", regs.rip);
    printf("RSP: 0x%.8llx\n", regs.rsp);
    printf("RAX: 0x%.8llx\n", regs.rax);
    printf("RDI: 0x%.8llx\n", regs.rdi);
    printf("RSI: 0x%.8llx\n", regs.rsi);
    printf("RDX: 0x%.8llx\n", regs.rdx);

    /* Set registers values of tracee */
    if (ptrace(PTRACE_SETREGS, pid_tracee, &regs, &regs) == -1)
    {
        perror("ptrace");
        return (-1);
    }

    /* Restart tracee */
    if ((ptrace(PTRACE_CONT, pid_tracee, NULL, NULL)) == -1)
    {
        perror("ptrace");
        return (-1);
    }

    printf("%s\n", CALL_POSIX_MEMALIGN);

    /* Wait for tracee to stop */
    if (waitpid(pid_tracee, NULL, 0) == -1)
    {
        perror("waitpid");
        return (-1);
    }

    /* Get registers values from tracee */
    if (ptrace(PTRACE_GETREGS, pid_tracee, &regs, &regs) == -1)
    {
        perror("ptrace");
        return (-1);
    }

    /* Display registers */
    printf("RIP: 0x%.8llx\n", regs.rip);
    printf("RSP: 0x%.8llx\n", regs.rsp);
    printf("RAX: 0x%.8llx\n", regs.rax);
    printf("RDI: 0x%.8llx\n", regs.rdi);
    printf("RSI: 0x%.8llx\n", regs.rsi);
    printf("RDX: 0x%.8llx\n", regs.rdx);

    printf("%s\n", RESTORE_CODE);

    /* Open stream of tracee address space file to write to memory */
    if ((stream_mem = open_stream_proc_at_offset(pid_tracee, offset_func_target, "w")) == NULL)
    {
        fprintf(stderr, "%s\n", ERR_OPEN_STREAM);
        return (-1);
    }

    /* Write original instruction to address space file */
    if (fwrite(code_origin, 1, CODE_SIZE, stream_mem) != CODE_SIZE)
    {
        perror("fwrite");
        return (-1);
    }

    /* Close stream */
    fclose(stream_mem);

    printf("%s\n", RESTORE_REGS);

    /* Restore registers */
    regs_copy.rip = offset_func_target; // Put in RIP offset target function
    if (ptrace(PTRACE_SETREGS, pid_tracee, &regs_copy, &regs_copy) == -1)
    {
        perror("ptrace");
        return (-1);
    }

    /* Test return value of posix_memalign (should be 0 on success) */
    if (regs.rax != 0) {
        fprintf(stderr, "%s\n", ERR_POSIX_MEMALIGN);
        return (-1);
    }
    else
    {
        addr_mem_alloc = regs.rax;
        printf("Address of allocated memory by posix_memalign: 0x%.8lx\n", addr_mem_alloc);
    }

    return (addr_mem_alloc);
}


/*
 * change_access_protections
 */
int         change_access_protections(pid_t pid_tracee, long addr_mem_alloc, long offset_func_target)
{
    long    addr_mprotect;
    char    code_origin[CODE_SIZE];
    FILE    *stream_mem;
    struct user_regs_struct regs;
    struct user_regs_struct regs_copy;

    printf("%s\n", SAVE_CODE);

    /* Open stream of tracee address space file to read memory */
    if ((stream_mem = open_stream_proc_at_offset(pid_tracee, offset_func_target, "r")) == NULL)
    {
        fprintf(stderr, "%s\n", ERR_OPEN_STREAM);
        return (-1);
    }

    /* Save memory zone to replace */
    memset(code_origin, 0, CODE_SIZE);
    if (fread(code_origin, 1, CODE_SIZE, stream_mem) != CODE_SIZE)
    {
        perror("fread");
        return (-1);
    }

    /* Close stream */
    if (fclose(stream_mem) != 0)
    {
        perror("fclose");
        return (-1);
    }

    printf("%s\n", INJECT_CODE);

    /* Inject call in function via RAX register (accumulator) */
    if (inject_call_in_func(pid_tracee, offset_func_target) == -1)
    {
        fprintf(stderr, "%s\n", ERR_ALLOC_MEM);
        return (-1);
    }

    printf("%s\n", SAVE_REGS);

    /* Get registers values from tracee */
    if (ptrace(PTRACE_GETREGS, pid_tracee, &regs, &regs) == -1)
    {
        perror("ptrace");
        return (-1);
    }

    /* Save registers original values */
    regs_copy = regs;

    printf("%s\n", MODIFY_REGS);

    /* Get address of mprotect function in libc */
    addr_mprotect = get_addr_libc_func(pid_tracee, "__mprotect");

    /* Modify registers to call mprotect function */
    regs.rax = addr_mprotect; // Put in RAX mprotect address
    regs.rip = offset_func_target + 1; // Put in RIP address of next instruction

    /* Initialize function parameters mprotect(void*, size_t, int) */
    regs.rdi = addr_mem_alloc; // Put in RDI a pointer to injected code
    regs.rsi = getpagesize(); // Put in RSI number of bytes in a memory page
    regs.rdx = (PROT_READ | PROT_WRITE | PROT_EXEC); // Put in RDX combination of accesses

    /* Display registers */
    printf("RIP: 0x%.8llx\n", regs.rip);
    printf("RSP: 0x%.8llx\n", regs.rsp);
    printf("RAX: 0x%.8llx\n", regs.rax);
    printf("RDI: 0x%.8llx\n", regs.rdi);
    printf("RSI: 0x%.8llx\n", regs.rsi);
    printf("RDX: 0x%.8llx\n", regs.rdx);

    /* Set registers values of tracee */
    if (ptrace(PTRACE_SETREGS, pid_tracee, &regs, &regs) == -1)
    {
        perror("ptrace");
        return (-1);
    }

    /* Restart tracee */
    if ((ptrace(PTRACE_CONT, pid_tracee, NULL, NULL)) == -1)
    {
        perror("ptrace");
        return (-1);
    }

    printf("%s\n", CALL_MPROTECT);

    /* Wait for tracee to stop */
    if (waitpid(pid_tracee, NULL, 0) == -1)
    {
        perror("waitpid");
        return (-1);
    }

    /* Get registers values from tracee */
    if (ptrace(PTRACE_GETREGS, pid_tracee, &regs, &regs) == -1)
    {
        perror("ptrace");
        return (-1);
    }

    /* Display registers */
    printf("RIP: 0x%.8llx\n", regs.rip);
    printf("RSP: 0x%.8llx\n", regs.rsp);
    printf("RAX: 0x%.8llx\n", regs.rax);
    printf("RDI: 0x%.8llx\n", regs.rdi);
    printf("RSI: 0x%.8llx\n", regs.rsi);
    printf("RDX: 0x%.8llx\n", regs.rdx);

    printf("%s\n", RESTORE_CODE);

    /* Open stream of tracee address space file to write to memory */
    if ((stream_mem = open_stream_proc_at_offset(pid_tracee, offset_func_target, "w")) == NULL)
    {
        fprintf(stderr, "%s\n", ERR_OPEN_STREAM);
        return (-1);
    }

    /* Write original instruction to address space file */
    if (fwrite(code_origin, 1, CODE_SIZE, stream_mem) != CODE_SIZE)
    {
        perror("fwrite");
        return (-1);
    }

    /* Close stream */
    fclose(stream_mem);

    printf("%s\n", RESTORE_REGS);

    /* Restore registers */
    regs_copy.rip = offset_func_target; // Put in RIP offset target function
    if (ptrace(PTRACE_SETREGS, pid_tracee, &regs_copy, &regs_copy) == -1)
    {
        perror("ptrace");
        return (-1);
    }

    /* Test return value of mprotect (should be 0 on success) */
    if (regs.rax != 0) {
        fprintf(stderr, "%s\n", ERR_MPROTECT);
        return (-1);
    }

    printf("Successfully changed access protections at: 0x%.8lx\n", addr_mem_alloc);

    return (0);
}


/*
 * main
 */
int         main(int argc, char **argv)
{
    pid_t   pid_tracee;
    long    offset_func_target;
    long    addr_mem_alloc;
    char    *path_bin;
    char    *func_target;

    /* Check arguments */
    if (argc < 4)
    {
        printf("%s\n", USAGE);
        exit(EXIT_FAILURE);
    }

    /* Get arguments */
    pid_tracee = atoi(argv[1]);
    path_bin = argv[2];
    func_target = argv[3];

    /* Attach tracee */
    if (ptrace(PTRACE_ATTACH, pid_tracee, NULL, NULL) == -1)
    {
        perror("ptrace");
        exit(EXIT_FAILURE);
    }

    /* Wait for tracee to stop */
    if (waitpid(pid_tracee, NULL, 0) == -1)
    {
        perror("waitpid");
        exit(EXIT_FAILURE);
    }

    /* Get target function address by parsing objdump output */
    if ((offset_func_target = get_offset_section(path_bin, func_target)) == (long)-1)
    {
        fprintf(stderr, "%s\n", ERR_PARSE_OBJDUMP);
        exit(EXIT_FAILURE);
    }

    /* Allocate memory in process */
    if ((addr_mem_alloc = alloc_mem_in_process(pid_tracee, offset_func_target)) == -1)
    {
        fprintf(stderr, "%s\n", ERR_ALLOC_MEM);
        exit(EXIT_FAILURE);
    }

    /* Change access protections */
    if ((change_access_protections(pid_tracee, addr_mem_alloc, offset_func_target)) == -1)
    {
        fprintf(stderr, "%s\n", ERR_CHANGE_PROTECT);
        exit(EXIT_FAILURE);
    }

    /* Detach tracee */
    if (ptrace(PTRACE_DETACH, pid_tracee, NULL, NULL) == -1)
    {
        perror("ptrace");
        exit(EXIT_FAILURE);
    }

    return (EXIT_SUCCESS);
}
