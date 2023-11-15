# Based on: https://raw.githubusercontent.com/veyon/veyon/master/cmake/modules/FindLZO.cmake
# Find libzstd
# ZSTD_FOUND - system has the ZSTD library
# ZSTD_INCLUDE_DIR - the ZSTD include directory
# ZSTD_LIBRARIES - The libraries needed to use ZSTD

if(ZSTD_INCLUDE_DIR AND ZSTD_LIBRARIES)
	# in cache already
	set(ZSTD_FOUND TRUE)
else()
	find_path(ZSTD_INCLUDE_DIR NAMES zstd.h)

	find_library(ZSTD_LIBRARIES NAMES zstd)

	if(ZSTD_INCLUDE_DIR AND ZSTD_LIBRARIES)
		 set(ZSTD_FOUND TRUE)
	endif()

	if(ZSTD_FOUND)
		 if(NOT ZSTD_FIND_QUIETLY)
				message(STATUS "Found ZSTD: ${ZSTD_LIBRARIES}")
		 endif()
	else()
		 if(ZSTD_FIND_REQUIRED)
				message(FATAL_ERROR "Could NOT find ZSTD")
		 endif()
	endif()

	mark_as_advanced(ZSTD_INCLUDE_DIR ZSTD_LIBRARIES)
endif()

