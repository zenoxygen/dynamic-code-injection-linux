##
## Makefile
##

CC      =    gcc

CFLAGS  =    -W -Wall -Wextra -Werror

SRC     =    exec_code.c

OBJ     =    $(SRC:.c=.o)

NAME    =    exec_code

all: $(NAME)

$(NAME): $(OBJ)
	$(CC) -no-pie -o $(NAME) $(OBJ) $(CFLAGS)

clean:
	$(RM) $(OBJ)

fclean: clean
	$(RM) $(NAME)

re: fclean all
