/*
** utils.h
*/

#ifndef UTILS_H
# define UTILS_H

void    free_two_dim_arr(char **arr);
char    **split_string(char *);
long    get_addr_libc_func(pid_t, char *);
char    *get_path_libc(pid_t);
long    get_addr_libc(pid_t);
long    get_offset_section(char *, char *);
FILE    *open_stream_proc_at_offset(pid_t, long, char *);

#endif /* !UTILS_H */
