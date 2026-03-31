# 工程配置
TARGET = modbus_ids          # 可执行文件名称
CC = gcc                     # 编译器
CFLAGS = -Wall -Wextra -g    # 编译选项：开启警告、调试模式
INCDIR = include             # 头文件目录
SRCDIR = src                 # 源代码目录
LIBS = -lpcap -lm            # 链接库：libpcap（抓包）、lm（数学库，abs/sqrt）

# 查找所有源文件
SRC = $(wildcard $(SRCDIR)/*.c)
# 生成目标文件列表
OBJ = $(SRC:.c=.o)

# 默认目标：编译可执行文件
all: $(TARGET)
	@echo "编译成功！可执行文件：./$(TARGET)"

# 编译可执行文件：链接所有目标文件
$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -I$(INCDIR) $^ -o $@ $(LIBS)

# 编译目标文件：每个.c文件生成.o文件
%.o: %.c
	$(CC) $(CFLAGS) -I$(INCDIR) -c $< -o $@

# 清理编译产物
clean:
	rm -f $(OBJ) $(TARGET)
	@echo "清理完成！"

# 重编译：先清理再编译
rebuild: clean all

# 伪目标：避免与同名文件冲突
.PHONY: all clean rebuild