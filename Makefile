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
            $(SRCDIR)/escape.c \
            $(SRCDIR)/ui.c \
            $(SRCDIR)/cli.c

CORE_OBJS = $(CORE_SRCS:.c=.o)
MAIN_OBJ  = $(SRCDIR)/main.o

TEST_SRCS = $(wildcard $(TESTDIR)/test_*.c)
TEST_BINS = $(TEST_SRCS:.c=)

.PHONY: all clean test dirs asan test-asan repro

all: dirs $(TARGET)

dirs:
	@mkdir -p data logs

$(TARGET): $(CORE_OBJS) $(MAIN_OBJ)
	$(CC) $(CFLAGS) -o $@ $(CORE_OBJS) $(MAIN_OBJ) $(LDFLAGS)

$(SRCDIR)/%.o: $(SRCDIR)/%.c include/fims.h
	$(CC) $(CFLAGS) -c $< -o $@

$(TESTDIR)/test_%: $(TESTDIR)/test_%.c $(CORE_OBJS)
	$(CC) $(CFLAGS) -include tests/test_helpers.h -o $@ $< $(CORE_OBJS) $(LDFLAGS)

test: all $(TEST_BINS)
	@echo "============================================================"
	@echo " Executing FIMS Automated Security & Integrity Test Suite"
	@echo "============================================================"
	@for t in $(TEST_BINS); do \
		./$$t || exit 1; \
	done
	@if [ -f $(TESTDIR)/test_cli.sh ]; then \
		bash $(TESTDIR)/test_cli.sh || exit 1; \
	fi
	@echo "============================================================"
	@echo " ALL TEST SUITES PASSED CLEANLY"
	@echo "============================================================"

asan: CFLAGS += -fsanitize=address,undefined -g -fno-omit-frame-pointer
asan: LDFLAGS += -fsanitize=address,undefined
asan: clean all $(TEST_BINS)

test-asan: asan
	@echo "============================================================"
	@echo " Executing FIMS Test Suite under ASan & UBSan"
	@echo "============================================================"
	@for t in $(TEST_BINS); do \
		./$$t || exit 1; \
	done
	@if [ -f $(TESTDIR)/test_cli.sh ]; then \
		bash $(TESTDIR)/test_cli.sh || exit 1; \
	fi
	@echo "============================================================"
	@echo " ASAN & UBSAN TEST RUN PASSED CLEANLY"
	@echo "============================================================"

repro: all
	@echo "============================================================"
	@echo " Executing FIMS Red Team Reproductions (tests/repro/*.sh)"
	@echo "============================================================"
	@for r in tests/repro/*.sh; do \
		if [ -f "$$r" ]; then \
			echo "Running $$r..."; \
			bash "$$r" || exit 1; \
		fi \
	done
	@echo "============================================================"
	@echo " ALL RED TEAM REPRODUCTIONS PASSED (BUGS FIXED)"
	@echo "============================================================"

clean:
	rm -f $(TARGET) $(SRCDIR)/*.o $(TEST_BINS)
	rm -rf data/*.dat data/*.conf data/*.tmp* logs/*.log *.asan* asan.log*
