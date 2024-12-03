CC = gcc                  # 使用 gcc 作為編譯器
CFLAGS = -Wall -g         # 編譯選項：-Wall 開啟所有警告，-g 開啟除錯資訊
TARGET = hw4       # 可執行檔名稱
SRC = ERS.c        # 你的 C 源碼檔案
OBJ = $(SRC:.c=.o)        # 物件檔案

# 編譯規則
all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJ)

# 編譯 C 源檔案
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# 清理目標
clean:
	rm -f $(OBJ) $(TARGET)
