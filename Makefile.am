ACLOCAL_AMFLAGS = -I m4

SUBDIRS = include src examples

dist_doc_DATA = README.md

check-valgrind: all
	$(MAKE) $(AM_MAKEFLAGS) -C examples check-valgrind

check-code-coverage: all
	$(MAKE) $(AM_MAKEFLAGS) -C examples check-code-coverage
