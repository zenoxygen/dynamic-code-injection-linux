##
## Makefile
##

CC      =    gcc

CFLAGS  =    -W -Wall -Wextra -Werror -g

SRC     =    inject_code.c \
             utils.c

OBJ     =    $(SRC:.c=.o)

NAME    =    inject_code

all: $(NAME)

$(NAME): $(OBJ)
	$(CC) -no-pie -o $(NAME) $(OBJ) $(CFLAGS)

clean:
	$(RM) $(OBJ)

fclean: clean
	$(RM) $(NAME)

re: fclean all
