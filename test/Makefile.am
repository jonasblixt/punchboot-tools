COMMON_TEST_CFLAGS = -I $(top_srcdir)/include \
                     -I $(top_srcdir)/lib \
                     $(LIBUSB_CFLAGS) \
                     $(BPAK_CFLAGS) \
                     $(BPAK_LDFLAGS) \
                     -fsanitize=address \
                     -no-pie -g -O0 \
                     -I /usr/include/uuid

COMMON_TEST_LDADD = libnala.la \
                    $(top_builddir)/lib/libpunchboot.la \
                    $(LIBUSB_LIBS) \
                    $(BPAK_LIBS)

COMMON_SRCS = command.c \
              common.c \
             ../src/uuid/clear.c \
             ../src/uuid/compare.c \
             ../src/uuid/isnull.c \
             ../src/uuid/pack.c \
             ../src/uuid/parse.c \
             ../src/uuid/unpack.c \
             ../src/uuid/unparse.c \
              test_command_loop.c

check_LTLIBRARIES = libnala.la

libnala_la_SOURCES = nala.c

check_PROGRAMS = test_help \
                 test_ctx \
                 test_wire_format \
                 test_magic \
                 test_api \
                 test_authentication \
                 test_slc \
                 test_api_partition \
                 test_error_codes \
                 test_bootloader_version \
                 test_stream \
                 test_boot \
                 test_board

test_help_SOURCES = $(COMMON_SRCS) test_help.c
test_help_LDADD = $(COMMON_TEST_LDADD)
test_help_CFLAGS = $(COMMON_TEST_CFLAGS)

test_ctx_SOURCES = $(COMMON_SRCS) test_ctx.c
test_ctx_LDADD = $(COMMON_TEST_LDADD)
test_ctx_CFLAGS = $(COMMON_TEST_CFLAGS)

test_wire_format_SOURCES = $(COMMON_SRCS) test_wire_format.c
test_wire_format_LDADD = $(COMMON_TEST_LDADD)
test_wire_format_CFLAGS = $(COMMON_TEST_CFLAGS)

test_magic_SOURCES = $(COMMON_SRCS) test_magic.c
test_magic_LDADD = $(COMMON_TEST_LDADD)
test_magic_CFLAGS = $(COMMON_TEST_CFLAGS)

test_api_SOURCES = $(COMMON_SRCS) test_api.c
test_api_LDADD = $(COMMON_TEST_LDADD)
test_api_CFLAGS = $(COMMON_TEST_CFLAGS)

test_authentication_SOURCES = $(COMMON_SRCS) test_authentication.c
test_authentication_LDADD = $(COMMON_TEST_LDADD)
test_authentication_CFLAGS = $(COMMON_TEST_CFLAGS)

test_slc_SOURCES = $(COMMON_SRCS) test_slc.c
test_slc_LDADD = $(COMMON_TEST_LDADD)
test_slc_CFLAGS = $(COMMON_TEST_CFLAGS)

test_api_partition_SOURCES = $(COMMON_SRCS) test_api_partition.c
test_api_partition_LDADD = $(COMMON_TEST_LDADD)
test_api_partition_CFLAGS = $(COMMON_TEST_CFLAGS)

test_error_codes_SOURCES = $(COMMON_SRCS) test_error_codes.c
test_error_codes_LDADD = $(COMMON_TEST_LDADD)
test_error_codes_CFLAGS = $(COMMON_TEST_CFLAGS)

test_bootloader_version_SOURCES = $(COMMON_SRCS) test_bootloader_version.c
test_bootloader_version_LDADD = $(COMMON_TEST_LDADD)
test_bootloader_version_CFLAGS = $(COMMON_TEST_CFLAGS)

test_stream_SOURCES = $(COMMON_SRCS) test_stream.c
test_stream_LDADD = $(COMMON_TEST_LDADD)
test_stream_CFLAGS = $(COMMON_TEST_CFLAGS)

test_boot_SOURCES = $(COMMON_SRCS) test_boot.c
test_boot_LDADD = $(COMMON_TEST_LDADD)
test_boot_CFLAGS = $(COMMON_TEST_CFLAGS)

test_board_SOURCES = $(COMMON_SRCS) test_board.c
test_board_LDADD = $(COMMON_TEST_LDADD)
test_board_CFLAGS = $(COMMON_TEST_CFLAGS)

TESTS =    prepare_bpak_file.sh \
        test_help \
        test_ctx \
        test_wire_format \
        test_magic \
        test_api \
        test_authentication \
        test_slc \
        test_api_partition \
        test_error_codes \
        test_bootloader_version \
        test_stream \
        test_boot \
        test_board
