# 定義編譯器和編譯選項
CC = gcc
CFLAGS = -Wall -g

# 定義需要的庫
LIBS = -lpcap

# 定義源文件和目標文件
SRC = main.c pcap.c fill_packet.c
OBJ = $(SRC:.c=.o)
TARGET = scanner

# 預設目標
all: $(TARGET)

# 編譯目標
$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET) $(LIBS)

# 編譯 .c 文件為 .o 文件
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# 清理中間檔案和編譯產物
clean:
	rm -f $(OBJ) $(TARGET)

