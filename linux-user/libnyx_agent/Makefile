NYX_INCLUDE_PATH ?= $(EXAMPLES_ROOT)

CFLAGS += -Wall -Werror -I$(NYX_INCLUDE_PATH)
#LIBS += -ldl

TARGET=libnyx_agent

all: debug

# may have to inject via LD_PRELOAD="/lib/x86_64-linux-gnu/libasan.so.5:/fuzz/libnyx_agent.so"
asan: CFLAGS += -g -O0 -DDEBUG -fsanitize=address,undefined
asan: LIBS += -lasan
asan: $(TARGET).so

debug: CFLAGS += -g -O0 -DDEBUG
debug: $(TARGET).so $(TARGET).a

release: CFLAGS += -g -Og
release: $(TARGET).so $(TARGET).a

$(TARGET).o: src/$(TARGET).c
	$(CC) $(CFLAGS) $(LDFLAGS) -fPIC -c $^ -o $@ $(LIBS)

$(TARGET).so: $(TARGET).o
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -fPIC $^ -o $@ $(LIBS)

$(TARGET).a: $(TARGET).o
	ar rcs $@ $^

clean:
	rm -f $(TARGET).so $(TARGET).a $(TARGET).o

tags:
	ctags -R src $(NYX_INCLUDE_PATH)/nyx_api.h

.PHONY: tags test clean
