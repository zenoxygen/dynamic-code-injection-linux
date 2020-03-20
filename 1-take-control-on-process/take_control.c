/*
** take_control.c
*/

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define USAGE           "Usage: ./take_control <pid_tracee> <path_bin> <func_target>"

#define INJECT_CODE     "Inject code"
#define SUCCESS_CONTROL "Successfully took control on process"
#define ERR_CONTROL     "Error: could not take control on process"

#define PATH_SIZE       256
#define OFFSET_SIZE     16
#define BASE            16

/*
 * take_control_on_process
 */
int         take_control_on_process(pid_t pid_tracee, char *path_bin, char *func_target)
{
    char    cmd_objdump[PATH_SIZE];
    FILE    *stream_objdump;

    char    buffer[OFFSET_SIZE];
    long    offset_func_target;

    char    path_mem[PATH_SIZE];
    FILE    *stream_mem;

    char    trap[4] = "OxCC";

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

    /* Create custom objdump command */
    memset(cmd_objdump, 0, PATH_SIZE);
    snprintf(cmd_objdump, PATH_SIZE, "objdump -t %s | grep %s", path_bin, func_target);

    /* Open new process with objdump command (read mode) */
    if ((stream_objdump = popen(cmd_objdump, "r")) == NULL)
    {
        perror("popen");
        return (-1);
    }

    /* Parse objdump output to get offset target function */
    memset(buffer, 0, OFFSET_SIZE);
    if (fgets(buffer, OFFSET_SIZE + 1, stream_objdump) == NULL)
    {
        perror("fgets");
        return (-1);
    }

    /* Convert buffer to long integer */
    offset_func_target = strtol(buffer, NULL, BASE);
    printf("Offset of function `%s`: Ox%.8lx\n", func_target, offset_func_target);

    /* Wait process termination */
    if (pclose(stream_objdump) == -1)
    {
        perror("pclose");
        return (-1);
    }

    /* Create path of tracee memory file */
    memset(path_mem, 0, PATH_SIZE);
    snprintf(path_mem, PATH_SIZE, "/proc/%d/mem", pid_tracee);

    /* Open tracee memory file (write mode) */
    if ((stream_mem = fopen(path_mem, "w")) == NULL)
    {
        perror("fopen");
        return (-1);
    }

    /* Set file position indicator to target function offset (SEEK_SET denotes beginning of file) */
    if (fseek(stream_mem, offset_func_target, SEEK_SET) == -1)
    {
        perror("fseek");
        return (-1);
    }

    printf("%s\n", INJECT_CODE);

    /* Write trap instruction (0xCC on one byte) */
    if (fwrite(trap, 1, sizeof(trap), stream_mem) != sizeof(trap))
    {
        perror("fwrite");
        return (-1);
    }

    /* Close stream */
    if (fclose(stream_mem) != 0)
    {
        perror("fclose");
        return (-1);
    }

    /* Detach tracee */
    if (ptrace(PTRACE_DETACH, pid_tracee, NULL, NULL) == -1)
    {
        perror("ptrace");
        return (-1);
    }

    printf("%s\n", SUCCESS_CONTROL);

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

    /* Take control on process */
    if (take_control_on_process(pid_tracee, path_bin, func_target) == -1)
    {
        fprintf(stderr, "%s\n", ERR_CONTROL);
        return (EXIT_FAILURE);
    }

    return (EXIT_SUCCESS);
}
