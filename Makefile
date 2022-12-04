NAME = main

OBJDIR = build
SRCDIR = src
LIBDIR = lib/src
INCLUDEDIR = lib/include

CC = gcc
CFLAGS = -g -O2 -Wall -fsanitize=address
LDFLAGS := -lpcap -fsanitize=address
INCLUDES = -I $(SRCDIR) -I $(INCLUDEDIR)

SRCS = $(wildcard $(SRCDIR)/*.c)
OBJS = $(SRCS:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
LIB_SRCS = $(wildcard $(LIBDIR)/*.c)
LIB_OBJS = $(LIB_SRCS:$(LIBDIR)/%.c=$(OBJDIR)/%.o)
TEST_OBJS = $(OBJDIR)/test.o

.PHONY: all clean

all: $(NAME)
	@echo "Successfully built $(NAME)"

$(NAME): $(OBJS) $(LIB_OBJS)
	$(CC) $(LDFLAGS) $^ -o $@ 

$(OBJDIR):
	mkdir -p $@

$(OBJS): $(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(LIB_OBJS): $(OBJDIR)/%.o: $(LIBDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	- $(RM) -f $(NAME)
	- $(RM) -rf $(OBJDIR)

run: all
	./main

# run this for testing code
testrun:test
	./test

test: $(TEST_OBJS) $(LIB_OBJS)
	$(CC) $(LDFLAGS) $^ -o $@ 
