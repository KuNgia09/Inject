all : victim

victim : victim.o
	gcc victim.o -o victim -ldl

victim.o : victim.c
	gcc -c victim.c
