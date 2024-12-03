CC = gcc
obj = main.o arp.o
EXE = main

all: $(obj)
	$(CC) -o $(EXE) $(obj)

%.o : %.c
	$(CC) -c $^ -o $@