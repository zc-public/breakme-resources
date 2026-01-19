CC       ?= gcc
TARGET   := mfulc_des_brute
SRC      := desbrute.c

MYCFLAGS := -D_GNU_SOURCE -O3 -Wno-deprecated-declarations
MYLDLIBS := -lcrypto -lpthread

CFLAGS   += $(MYCFLAGS)
LDLIBS   += $(MYLDLIBS)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -f $(TARGET)
