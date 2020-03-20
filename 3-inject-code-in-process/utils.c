/*
** utils.c
*/

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ERROR_SPLIT_STRING  "Error: could not split string"
#define ERROR_GET_PATH_LIBC "Error: could not get path of libc"
#define ERROR_GET_ADDR_LIBC "Error: could not get address of libc"

#define PATH_SIZE           256
#define BUFFER_SIZE         512
#define ADDR_SIZE           12
#define OFFSET_SIZE         16
#define BASE                16

/*
 * free_two_dim_array
 */
void        free_two_dim_array(char **arr)
{
    int     i;

    i = 0;
    while (arr[i])
    {
        free(arr[i]);
        i++;
    }
    free(arr);
}


/*
 * split_string
 */
char        **split_string(char *str)
{
    int     a;
    int     b;
    int     i;
    char    **arr;

    if ((arr = malloc((strlen(str) + 1) * sizeof(char *))) == NULL)
        return (NULL);
    i = 0;
    a = 0;
    while (str && str[i] && str[i] != '\n')
    {
        while ((str[i] == ' ' || str[i] == '\t' || str[i] == '\n') && str[i])
            i++;
        b = 0;
        if ((arr[a] = malloc((strlen(str) + 1) * sizeof(char))) == NULL)
            return (NULL);
        while (str[i] && str[i] != ' ' && str[i] != '\n' && str[i] != '\t')
            arr[a][b++] = str[i++];
        arr[a][b] = '\0';
        a++;
    }
    arr[a] = NULL;

    return (arr);
}


/*
 * get_path_libc
 */
char        *get_path_libc(pid_t pid_tracee)
{
    int     len_path;
    char    cmd_cat[PATH_SIZE];
    char    buffer[BUFFER_SIZE];
    char    **splitted;
    char    *path_libc;
    FILE    *stream_maps;

    len_path = 0;

    /* Create command to see content of /proc/N/maps where N is pid_tracee */
    memset(cmd_cat, 0, PATH_SIZE);
    snprintf(cmd_cat, PATH_SIZE, "cat /proc/%d/maps | grep libc | grep \"r-x\"", pid_tracee);

    /* Open new process with cat command (read mode) */
    if ((stream_maps = popen(cmd_cat, "r")) == NULL)
    {
        perror("popen");
        return (NULL);
    }

    /* Get cat command output in a buffer */
    memset(buffer, 0, BUFFER_SIZE);
    if (fgets(buffer, BUFFER_SIZE, stream_maps) == NULL)
    {
        perror("fgets");
        return (NULL);
    }

    /* Close stream */
    if (pclose(stream_maps) == -1)
    {
        perror("pclose");
        return (NULL);
    }

    /* Split /proc/N/maps output where N is pid_tracee */
    if ((splitted = split_string(buffer)) == NULL)
    {
        fprintf(stderr, "%s\n", ERROR_SPLIT_STRING);
        return (NULL);
    }

    /* Get libc path */
    len_path = strlen(splitted[5]);
    if ((path_libc = malloc(sizeof(char) * (len_path + 1))) == NULL)
    {
        perror("malloc");
        return (NULL);
    }
    strncpy(path_libc, splitted[5], len_path);
    path_libc[len_path] = '\0';
    printf("Path to libc: %s\n", path_libc);

    /* Free array */
    free_two_dim_array(splitted);

    return (path_libc);
}


/*
 * get_addr_libc
 */
long        get_addr_libc(pid_t pid_tracee)
{
    long    addr_libc;
    char    cmd_cat[PATH_SIZE];
    char    buffer[ADDR_SIZE];
    FILE    *stream_maps;

    addr_libc = -1;

    /* Create command to see content of /proc/N/maps where N is pid_tracee */
    memset(cmd_cat, 0, PATH_SIZE);
    snprintf(cmd_cat, PATH_SIZE, "cat /proc/%d/maps | grep libc | grep \"r-x\"", pid_tracee);

    /* Open new process with cat command (read mode) */
    if ((stream_maps = popen(cmd_cat, "r")) == NULL)
    {
        perror("popen");
        return (-1);
    }

    /* Get cat command output in buffer */
    memset(buffer, 0, ADDR_SIZE);
    if (fgets(buffer, ADDR_SIZE + 1, stream_maps) == NULL)
    {
        perror("fgets");
        return (-1);
    }

    /* Close stream */
    if (pclose(stream_maps) == -1)
    {
        perror("pclose");
        return (-1);
    }

    /* Convert buffer to long integer */
    addr_libc = strtoul(buffer, NULL, BASE);
    printf("Address of libc: 0x%.8lx\n", addr_libc);

    return (addr_libc);
}


/*
 * get_offset_section
 */
long        get_offset_section(char *path_bin, char *section)
{
    long    offset;
    char    cmd_objdump[PATH_SIZE];
    char    buffer[OFFSET_SIZE];
    FILE    *stream_objdump;

    /* Create objdump command */
    memset(cmd_objdump, 0, PATH_SIZE);
    snprintf(cmd_objdump, PATH_SIZE, "objdump -t %s | grep %s", path_bin, section);

    /* Open a new process with objdump command */
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

    /* Convert buffer to a long integer */
    offset = strtoul(buffer, NULL, BASE);

    return (offset);
}


/*
 * open_stream_at_offset
 */
FILE        *open_stream_proc_at_offset(pid_t pid_tracee, long offset, char *mode)
{
    char    path_mem[PATH_SIZE];
    FILE    *stream_mem;

    /* Create path of tracee memory file */
    memset(path_mem, 0, PATH_SIZE);
    snprintf(path_mem, PATH_SIZE, "/proc/%d/mem", pid_tracee);

    /* Read */
    if (strncmp(mode, "r", 1) == 0)
    {
        if ((stream_mem = fopen(path_mem, "r")) == NULL)
        {
            perror("fopen");
            return (NULL);
        }
    }
    /* Write */
    else if (strncmp(mode, "w", 1) == 0)
    {
        if ((stream_mem = fopen(path_mem, "w")) == NULL)
        {
            perror("fopen");
            return (NULL);
        }
    }

    /* Set position indicator to address (SEEK_SET denotes beginning of file) */
    if (fseek(stream_mem, offset, SEEK_SET) == -1)
    {
        perror("fseek");
        return (NULL);
    }

    return (stream_mem);
}

/*
 * get_address_libc_func
 */
long        get_addr_libc_func(pid_t pid_tracee, char *section)
{
    long    addr_libc;
    long    offset_section;
    long    addr_libc_section;
    char    *path_libc;

    /* Get libc path */
    if ((path_libc = get_path_libc(pid_tracee)) == NULL)
    {
        fprintf(stderr, "%s\n", ERROR_GET_PATH_LIBC);
        return (-1);
    }

    /* Get libc address */
    if ((addr_libc = get_addr_libc(pid_tracee)) == -1)
    {
        fprintf(stderr, "%s\n", ERROR_GET_ADDR_LIBC);
        return (-1);
    }

    /* Get section offset in libc */
    offset_section = get_offset_section(path_libc, section);

    /* Add libc address and section offset */
    addr_libc_section = addr_libc + offset_section;
    printf("Address of section `%s` in libc: 0x%.8lx\n", section, addr_libc_section);

    /* Free libc path */
    free(path_libc);

    return (addr_libc_section);
}
