/*
** target.c
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/*
 * hello
 */
int     hello(int i)
{
    printf("%s\n", "Function: hello");

    return (i);
}

/*
 * add
 */
int     add(int a, int b)
{
    printf("%s\n", "Function: add");

    return (a + b);
}

/*
 * main
 */
int     main()
{
    int result;

    result = 0;

    printf("%s\n", "Function: main");

    while (1)
    {
        printf("PID: %d\n", getpid());
        result = add(result, 1);
        printf("%d\n", result);
        sleep(1);
    }

    return (EXIT_SUCCESS);
}
