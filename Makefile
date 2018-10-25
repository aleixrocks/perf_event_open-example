all: test

test: test.c
	gcc $< -o $@
