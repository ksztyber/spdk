SPDK_ROOT_DIR := $(abspath $(CURDIR)/../..)

include $(SPDK_ROOT_DIR)/mk/spdk.common.mk

SO_VER := 1
SO_MINOR := 0

CXX_SRCS = trace.cpp
LIBNAME = trace_parse
LOCAL_SYS_LIBS = -lrt

SPDK_MAP_FILE = $(abspath $(CURDIR)/spdk_trace_parse.map)

include $(SPDK_ROOT_DIR)/mk/spdk.lib.mk
