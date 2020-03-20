##
## Makefile
##

CC      =    gcc

CFLAGS  =    -W -Wall -Wextra -Werror

SRC     =    target.c

OBJ     =    $(SRC:.c=.o)

NAME    =    target

all: $(NAME)

$(NAME): $(OBJ)
	$(CC) -no-pie -o $(NAME) $(OBJ) $(CFLAGS)

clean:
	$(RM) $(OBJ)

fclean: clean
	$(RM) $(NAME)

re: fclean all
