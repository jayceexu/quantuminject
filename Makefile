CC=g++
CFLAGS=-g -Wall 
LIBS_1=-lpcap -lnet -lpcre
LIBS_2=-lpcap

obj=conf.o util.o quantuminject.o

all: quantuminject quantumdetect

quantuminject: conf.o util.o quantuminject.o
		$(CC) -o quantuminject $(obj) $(CFLAGS) $(LIBS_1)

quantumdetect: quantumdetect.o
		$(CC) -o quantumdetect quantumdetect.o $(CFLAGS) $(LIBS_2)

.PHONY: clean


clean:
	rm -f *.o quantuminject quantumdetect
