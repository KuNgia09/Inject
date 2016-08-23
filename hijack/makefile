all : hijack

hijack : hijack.o
	gcc hijack.o -o hijack -ldl

hijack.o : hijack.c
	gcc -c hijack.c
