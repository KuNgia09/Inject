all : libexample.so

libexample.so : libexample.o
	gcc libexample.o -shared -o libexample.so

libexample.o : callso.c
	gcc -c callso.c -o libexample.o
