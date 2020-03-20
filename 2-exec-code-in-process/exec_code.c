/*
** exec_code.c
*/

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#define USAGE             "Usage: ./exec_code <pid_tracee> <path_bin> <func_target>"

#define SAVE_CODE         "Save code"
#define INJECT_CODE       "Inject code"
#define SAVE_REGS         "Save registers"
#define MODIFY_REGS       "Modify registers"
#define CALL_HELLO        "Call hello"
#define RESTORE_CODE      "Restore code"
#define RESTORE_REGS      "Restore registers"
#define SUCCESS_EXEC_CODE "Successfully executed code in process"
#define ERR_PARSE_OBJDUMP "Error: could not parse objdump output"
#define ERR_EXEC_HELLO    "Error: could not execute hello"
#define ERR_EXEC_CODE     "Error: could not execute code in process"

#define PATH_SIZE         256
#define BUFFER_SIZE       512
#define OFFSET_SIZE       16
#define BASE              16
#define CODE_SIZE         4

/*
 * get_offset_section
 */
long        get_offset_section(char *path_bin, char *section)
{
    long    offset;
    char    cmd_objdump[PATH_SIZE];
    char    buffer[BUFFER_SIZE];
    FILE    *stream_objdump;

    /* Create objdump command */
    memset(cmd_objdump, 0, PATH_SIZE);
    snprintf(cmd_objdump, PATH_SIZE, "objdump -t %s | grep %s", path_bin, section);

    /* Open new process with objdump command */
    if ((stream_objdump = popen(cmd_objdump, "r")) == NULL)
    {
        perror("popen");
        return (-1);
    }

    /* Parse objdump output to get section offset */
    memset(buffer, 0, OFFSET_SIZE);
    if (fgets(buffer, OFFSET_SIZE + 1, stream_objdump) == NULL)
    {
        perror("fgets");
        return (-1);
    }

    /* Close stream */
    if (pclose(stream_objdump) == -1)
    {
        perror("pclose");
        return (-1);
    }

    /* Convert buffer to long integer */
    offset = strtoul(buffer, NULL, BASE);

    return (offset);
}

/*
 * exec_code_in_process
 */
int         exec_code_in_process(pid_t pid_tracee, char *path_bin, char *func_target)
{
    char    path_mem[PATH_SIZE];
    FILE    *stream_mem;

    char    code_origin[CODE_SIZE];
    char    code_inject[CODE_SIZE] = {(char)0xCC, (char)0xFF, (char)0xD0, (char)0xCC};

    long    offset_func_target;
    long    offset_func_hello;

    struct user_regs_struct regs;
    struct user_regs_struct regs_copy;

    /* Attach tracee */
    if (ptrace(PTRACE_ATTACH, pid_tracee, NULL, NULL) == -1)
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

    /* Create path of tracee address space file */
    memset(path_mem, 0, PATH_SIZE);
    snprintf(path_mem, PATH_SIZE, "/proc/%d/mem", pid_tracee);

    /* Get target function offset by parsing objdump output */
    if ((offset_func_target = get_offset_section(path_bin, func_target)) == (long)-1)
    {
        printf("%s\n", ERR_PARSE_OBJDUMP);
        return (-1);
    }

    printf("%s\n", SAVE_CODE);

    /* Open tracee address space file */
    if ((stream_mem = fopen(path_mem, "r")) == NULL)
    {
        perror("fopen");
        return (-1);
    }

    /* Move file position indicator to target function offset (SEEK_SET denotes beginning of file) */
    if (fseek(stream_mem, offset_func_target, SEEK_SET) == -1)
    {
        perror("fseek");
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
    fclose(stream_mem);

    printf("%s\n", INJECT_CODE);

    /* Open tracee address space file (write mode) */
    if ((stream_mem = fopen(path_mem, "w")) == NULL)
    {
        perror("fopen");
        return (-1);
    }

    /* Move file position indicator to address of target function (SEEK_SET denotes beginning of file) */
    if (fseek(stream_mem, offset_func_target, SEEK_SET) == -1)
    {
        perror("fseek");
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

    /* Restart tracee */
    if (ptrace(PTRACE_CONT, pid_tracee, NULL, NULL) == -1)
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

    /* Get hello function offset by parsing objdump output */
    if ((offset_func_hello = get_offset_section(path_bin, "hello")) == (long)-1)
    {
        printf("%s\n", ERR_PARSE_OBJDUMP);
        return (-1);
    }

    printf("Offset of hello: Ox%.8lx\n", offset_func_hello);

    /* Modify registers to call hello function */
    regs.rax = offset_func_hello; // Put in RAX hello function address
    regs.rip = offset_func_target + 1; // Put in RIP address of next instruction

    /* Initialize function parameters hello(int) */
    regs.rdi = 42; // Put in RDI value 42

    /* Display registers */
    printf("RIP: 0x%.8llx\n", regs.rip);
    printf("RSP: 0x%.8llx\n", regs.rsp);
    printf("RAX: 0x%.8llx\n", regs.rax);
    printf("RDI: 0x%.8llx\n", regs.rdi);

    /* Set tracee registers values */
    if (ptrace(PTRACE_SETREGS, pid_tracee, &regs, &regs) == -1)
    {
        perror("ptrace");
        return (-1);
    }

    /* Restart tracee (and execute hello function) */
    if (ptrace(PTRACE_CONT, pid_tracee, NULL, NULL) == -1)
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

    printf("%s\n", CALL_HELLO);

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

    printf("%s\n", RESTORE_CODE);

    /* Open tracee address space file (write mode) */
    if ((stream_mem = fopen(path_mem, "w")) == NULL)
    {
        perror("fopen");
        return (-1);
    }

    /* Move file position indicator to target function offset (SEEK_SET denotes beginning of file) */
    if (fseek(stream_mem, offset_func_target, SEEK_SET) == -1)
    {
        perror("fseek");
        return (-1);
    }

    /* Write to tracee address space file (0xCC, 0xFF, 0xDO, 0xCC) */
    if (fwrite(code_origin, 1, sizeof(code_origin), stream_mem) != sizeof(code_origin))
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

    /* Detach tracee */
    if (ptrace(PTRACE_DETACH, pid_tracee, NULL, NULL) == -1)
    {
        perror("ptrace");
        return (-1);
    }

    /* Test return value of hello (should be 42 on success) */
    if (regs.rax != 42)
    {
        fprintf(stderr, ERR_EXEC_HELLO);
        return (-1);
    }

    printf("%s\n", SUCCESS_EXEC_CODE);

    return (0);
}

/*
 * main
 */
int         main(int argc, char **argv)
{
    pid_t   pid_tracee;
    char    *path_bin;
    char    *func_target;

    /* Check arguments */
    if (argc < 4)
    {
        printf("%s\n", USAGE);
        return (EXIT_FAILURE);
    }

    /* Get arguments */
    pid_tracee = atoi(argv[1]);
    path_bin = argv[2];
    func_target = argv[3];

    /* Execute code in process */
    if (exec_code_in_process(pid_tracee, path_bin, func_target) == -1)
    {
        fprintf(stderr, "%s\n", ERR_EXEC_CODE);
        return (EXIT_FAILURE);
    }

    return (EXIT_SUCCESS);
}
