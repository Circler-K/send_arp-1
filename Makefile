all:
	gcc -o test test.c -lpcap

clean:
	rm test
