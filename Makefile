all:
	gcc -Wall -o debugger debugger.c
clean:
	rm -f debugger