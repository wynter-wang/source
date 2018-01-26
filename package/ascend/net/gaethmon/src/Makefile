INCDIR = ./inc

DEFS += -D_GNU_SOURCE

#C编译器选项
CFLAGS += -Wall
CFLAGS += -Werror
CFLAGS += $(DEFS)
CFLAGS += -I$(INCDIR)


#可执行文件名和相关的obj文件
TARGET = gaethmon

#Makefile和*.c放置于同一个目录
SRCS=$(wildcard *.c)

OBJS = $(patsubst %.c, %.o,$(SRCS))

LIBS += -luci

#单独编译的文件部分放在此
$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LIBS)
	rm *.o 
				  
clean:
	@echo "cleanning project"
	$(RM) *.a *.o *~ *.so *.lo $(TARGET)
	@echo "clean completed"

.PHONY: clean
