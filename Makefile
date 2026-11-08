CC      = gcc
CFLAGS  = -Wall -Wextra -Werror -pedantic -std=c11 -O2 -Iinclude
LDFLAGS = -lcrypto -lpthread

TARGET  = fims
SRCDIR  = src
TESTDIR = tests

CORE_SRCS = $(SRCDIR)/config.c \
            $(SRCDIR)/logger.c \
            $(SRCDIR)/hash.c \
            $(SRCDIR)/scanner.c \
            $(SRCDIR)/baseline.c \
            $(SRCDIR)/integrity.c \
            $(SRCDIR)/monitor.c \
            $(SRCDIR)/cli.c

CORE_OBJS = $(CORE_SRCS:.c=.o)
MAIN_OBJ  = $(SRCDIR)/main.o

TEST_BINS = $(TESTDIR)/test_hash \
            $(TESTDIR)/test_scanner \
            $(TESTDIR)/test_baseline \
            $(TESTDIR)/test_integrity

.PHONY: all clean test dirs

all: dirs $(TARGET)

dirs:
	@mkdir -p data logs

$(TARGET): $(CORE_OBJS) $(MAIN_OBJ)
	$(CC) $(CFLAGS) -o $@ $(CORE_OBJS) $(MAIN_OBJ) $(LDFLAGS)

$(SRCDIR)/%.o: $(SRCDIR)/%.c include/fims.h
	$(CC) $(CFLAGS) -c $< -o $@

$(TESTDIR)/test_hash: $(TESTDIR)/test_hash.c $(CORE_OBJS)
	$(CC) $(CFLAGS) -o $@ $< $(CORE_OBJS) $(LDFLAGS)

$(TESTDIR)/test_scanner: $(TESTDIR)/test_scanner.c $(CORE_OBJS)
	$(CC) $(CFLAGS) -o $@ $< $(CORE_OBJS) $(LDFLAGS)

$(TESTDIR)/test_baseline: $(TESTDIR)/test_baseline.c $(CORE_OBJS)
	$(CC) $(CFLAGS) -o $@ $< $(CORE_OBJS) $(LDFLAGS)

$(TESTDIR)/test_integrity: $(TESTDIR)/test_integrity.c $(CORE_OBJS)
	$(CC) $(CFLAGS) -o $@ $< $(CORE_OBJS) $(LDFLAGS)

test: all $(TEST_BINS)
	@echo "============================================================"
	@echo " Executing FIMS Automated Security & Integrity Test Suite"
	@echo "============================================================"
	./$(TESTDIR)/test_hash
	./$(TESTDIR)/test_scanner
	./$(TESTDIR)/test_baseline
	./$(TESTDIR)/test_integrity
	@echo "============================================================"
	@echo " ALL 4 TEST SUITES (12 TEST REQUIREMENTS) PASSED CLEANLY"
	@echo "============================================================"

clean:
	rm -f $(TARGET) $(SRCDIR)/*.o $(TEST_BINS)
	rm -rf data/*.dat data/*.conf data/*.tmp* logs/*.log
