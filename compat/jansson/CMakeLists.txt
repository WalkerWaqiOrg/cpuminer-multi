
set(JANSSON_INCLUDES ${PROJECT_SOURCE_DIR}/compat/jansson)
include_directories(${JANSSON_INCLUDES})

set(libjansson_a_SOURCES config.h
			  dump.c
			  hashtable.c
			  hashtable.h
			  jansson.h
			  jansson_private.h
			  load.c
			  strbuffer.c
			  strbuffer.h
			  utf.c
			  utf.h
			  util.h
			  value.c
)

add_library(jansson STATIC ${libjansson_a_SOURCES})
#target_include_directories(jansson PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/compat/jansson>)
