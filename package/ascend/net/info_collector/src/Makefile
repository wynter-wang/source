
DEFS += -D_GNU_SOURCE


#C编译器选项
CFLAGS += -Wall
CFLAGS += -Werror
#CFLAGS += -O2
#优化级别 O0 -->> O1 -->> O2 -->> O3 默认为O1，O0为无优化
CFLAGS += $(DEFS)
#可执行文件名和相关的obj文件
TARGET = sendinfo

#Makefile和*.c放置于同一个目录
SRCS=$(wildcard *.c)

OBJS = $(patsubst %.c, %.o,$(SRCS))
	
#LIBS += -lm
LIBS += -luci
#LIBS += -lubox
#LIBS += -lssl
#LIBS += -lcrypto


#单独编译的文件部分放在此
$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LIBS)
	rm *.o 
				  
clean:
	@echo "cleanning project"
	$(RM) *.a *.o *~ *.so *.lo $(TARGET)
	@echo "clean completed"

.PHONY: clean
