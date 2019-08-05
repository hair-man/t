CC = gcc  
CFLAGS = -I../../klib -I../../zlog-1.2.14
CFLAGS += -W -Wall

LDFLAGS = -Wl,-Bstatic -L ../../zlog-1.2.14/ -lzlog \
		  -Wl,-Bdynamic -lpthread \
		  -lssl \
		  -lcrypto \
		  -ldl \
		  -lkrb5 \
		  -lk5crypto \
		  -lm \
		  -lz

OBJS    = main.o

TARGET = transF 

$(TARGET) : $(OBJS)
	$(CC) $^ -o $@ $(LDFLAGS) -Ofast
%.o : %.c
	$(CC) -c $< $(CFLAGS) -Ofast

clean:
	$(RM) *.o $(TARGET)
	$(RM) tags

tag:
	ctags -R *

dist:
	cp $(TARGET) ../bin

.PHONY: clean dist tag debug
