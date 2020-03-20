##
## Makefile
##

CC      =    gcc

CFLAGS  =    -W -Wall -Wextra -Werror

SRC     =    take_control.c

OBJ     =    $(SRC:.c=.o)

NAME    =    take_control

all: $(NAME)

$(NAME): $(OBJ)
	$(CC) -no-pie -o $(NAME) $(OBJ) $(CFLAGS)

clean:
	$(RM) $(OBJ)

fclean: clean
	$(RM) $(NAME)

re: fclean all
