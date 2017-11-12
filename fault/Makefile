SOURCES_C	= $(wildcard *.c)
TARGETS_C	= $(patsubst %.c, 	%,	${SOURCES_C})

${TARGETS_C} 	: % 	: %.c %.h
	@gcc -Wall -Wextra -std=gnu99 -O3 -o ${@} $(filter %.c, ${^}) -L/usr/local/ssl/lib -lssl -lgmp -lcrypto

.DEFAULT_GOAL = all

all : ${TARGETS_C} ${TARGETS_JAVA}

clean :
	@rm -f core ${TARGETS_C}
