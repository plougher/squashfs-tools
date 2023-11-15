cmake_minimum_required(VERSION 3.13.4)

project(
    squashfs-tools
    LANGUAGES C
    VERSION 4.6.1
)

######## User defined variables & options
set(COMP_DEFAULT "zstd" CACHE STRING "Default compressor")
option(GZIP_SUPPORT "Build with gzip support" ON)
option(XZ_SUPPORT "Build with xz support" ON)
option(XZ_EXTENDED_OPTIONS "Build with xz extended option support" ON)
option(LZO_SUPPORT "Build with lzo support" ON)
option(LZ4_SUPPORT "Build with lz4 support" ON)
option(ZSTD_SUPPORT "Build with zstd support" ON)
option(XATTR_SUPPORT "Build with xattr support" ON)
option(XATTR_DEFAULT "xattrs to be stored by Mksquashfs and extracted by Unsquashfs by default" ON)
option(REPRODUCIBLE_DEFAULT "Reproducible builds by default" ON)
option(USE_PREBUILT_MANPAGES "Use the pre-built manpages by default" ON)
# Note: LZMA1 compression support not implemented [FIXME maybe]
################

include(version.cmake)
# Example values for HASH and FULLDATE
#set(HASH "d8cb82d9")
#set(FULLDATE "2023-03-01 20:53:37 +0000")
separate_arguments(FULLDATE)
list(GET FULLDATE 0 DATE)

if(DEFINED ENV{RELEASE_VERSION} AND DEFINED ENV{RELEASE_DATE})
    # GET RELEASE_VERSION AND RELEASE_DATE from environment
    add_definitions(-DDATE="$ENV{RELEASE_DATE}")
    add_definitions(-DVERSION="$ENV{RELEASE_VERSION}")
else()
    if(${HASH} STREQUAL "$Format:%h$")
        execute_process(COMMAND git show -s --pretty=format:%ci OUTPUT_VARIABLE FULLDATE)
        separate_arguments(FULLDATE)
        list(GET FULLDATE 0 DATE)
        execute_process(COMMAND git show -s --pretty=format:%h OUTPUT_VARIABLE HASH)
    endif()
    add_definitions(-DDATE="${DATE}")
    add_definitions(-DVERSION="${PROJECT_VERSION}-${HASH}")
    string(REGEX MATCH ^[0-9]+ YEAR ${DATE})
endif()
add_definitions(-DYEAR="${YEAR}")

include(CheckSymbolExists)
include(GNUInstallDirs)

set(mksquashfs_SOURCES
    mksquashfs.c
    read_fs.c
    action.c
    swap.c
    pseudo.c
    compressor.c
    sort.c
    progressbar.c
    info.c
    restore.c
    process_fragments.c
    caches-queues-lists.c
    reader.c
    tar.c
    date.c
)

set(unsquashfs_SOURCES
    unsquashfs.c
    unsquash-1.c
    unsquash-2.c
    unsquash-3.c
    unsquash-4.c
    unsquash-123.c
    unsquash-34.c
    unsquash-1234.c
    unsquash-12.c
    swap.c
    compressor.c
    unsquashfs_info.c
    date.c
)

set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake/" ${CMAKE_MODULE_PATH})

set(COMPRESSORS "")
if(GZIP_SUPPORT)
    find_package(ZLIB REQUIRED)
    set(mksquashfs_SOURCES ${mksquashfs_SOURCES} gzip_wrapper.c)
    set(unsquashfs_SOURCES ${unsquashfs_SOURCES} gzip_wrapper.c)
    add_definitions(-DGZIP_SUPPORT)
    set(COMPRESSORS ${COMPRESSORS} gzip)
endif()

if(XZ_SUPPORT)
    find_package(LibLZMA REQUIRED)
    if(XZ_EXTENDED_OPTIONS)
        set(mksquashfs_SOURCES ${mksquashfs_SOURCES} xz_wrapper_extended.c)
        set(unsquashfs_SOURCES ${unsquashfs_SOURCES} xz_wrapper_extended.c)
    else()
        set(mksquashfs_SOURCES ${mksquashfs_SOURCES} xz_wrapper.c)
        set(unsquashfs_SOURCES ${unsquashfs_SOURCES} xz_wrapper.c)
    endif()
    add_definitions(-DXZ_SUPPORT)
    set(COMPRESSORS ${COMPRESSORS} xz)
endif()

if(LZO_SUPPORT)
    find_package(LZO REQUIRED)
    set(mksquashfs_SOURCES ${mksquashfs_SOURCES} lzo_wrapper.c)
    set(unsquashfs_SOURCES ${unsquashfs_SOURCES} lzo_wrapper.c)
    add_definitions(-DLZO_SUPPORT)
    set(COMPRESSORS ${COMPRESSORS} lzo)
endif()

if(LZ4_SUPPORT)
    find_package(LZ4 REQUIRED)
    set(mksquashfs_SOURCES ${mksquashfs_SOURCES} lz4_wrapper.c)
    set(unsquashfs_SOURCES ${unsquashfs_SOURCES} lz4_wrapper.c)
    add_definitions(-DLZ4_SUPPORT)
    set(COMPRESSORS ${COMPRESSORS} lz4)
endif()

if(ZSTD_SUPPORT)
    find_package(ZSTD REQUIRED)
    set(mksquashfs_SOURCES ${mksquashfs_SOURCES} zstd_wrapper.c)
    set(unsquashfs_SOURCES ${unsquashfs_SOURCES} zstd_wrapper.c)
    add_definitions(-DZSTD_SUPPORT)
    set(COMPRESSORS ${COMPRESSORS} zstd)
endif()

if(XATTR_SUPPORT)
    find_package(Xattr REQUIRED)
    set(mksquashfs_SOURCES ${mksquashfs_SOURCES} xattr.c read_xattrs.c tar_xattr.c pseudo_xattr.c)
    set(unsquashfs_SOURCES ${unsquashfs_SOURCES} unsquashfs_xattr.c read_xattrs.c)
    add_definitions(-DXATTR_SUPPORT)
    if(XATTR_DEFAULT)
        add_definitions(-DXATTR_DEFAULT)
    endif()
endif()

if(REPRODUCIBLE_DEFAULT)
    add_definitions(-DREPRODUCIBLE_DEFAULT)
endif()

if(USE_PREBUILT_MANPAGES)
    set(USE_PREBUILT_MANPAGES "y")
endif()

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
find_library(MATH_LIBRARY m REQUIRED)

add_definitions(-D_GNU_SOURCE)

if(COMPRESSORS STREQUAL "")
    message(FATAL_ERROR "No compressor selected ! Select one or more of GZIP, LZMA, XZ, LZO, LZ4 or ZSTD !")
endif()

if(COMP_DEFAULT STREQUAL "")
    message(FATAL_ERROR "COMP_DEFAULT must be set to a compressor !")
endif()

if(${COMP_DEFAULT} IN_LIST COMPRESSORS)
    add_definitions(-DCOMP_DEFAULT="${COMP_DEFAULT}")
else()
    message(FATAL_ERROR "COMP_DEFAULT is set to ${COMP_DEFAULT}, which isn't selected to be built !")
endif()

add_executable(mksquashfs ${mksquashfs_SOURCES})
add_executable(unsquashfs ${unsquashfs_SOURCES})

target_include_directories(mksquashfs
    PRIVATE
        ${PROJECT_SOURCE_DIR}
        ${ZLIB_INCLUDE_DIRS}
        ${LIBLZMA_INCLUDE_DIRS}
        ${LZO_INCLUDE_DIR}
        ${LZ4_INCLUDE_DIR}
        ${ZSTD_INCLUDE_DIR}
        ${XATTR_INCLUDE_DIRS}
)

target_include_directories(unsquashfs
    PRIVATE
        ${PROJECT_SOURCE_DIR}
        ${ZLIB_INCLUDE_DIRS}
        ${LIBLZMA_INCLUDE_DIRS}
        ${LZO_INCLUDE_DIR}
        ${LZ4_INCLUDE_DIR}
        ${ZSTD_INCLUDE_DIR}
        ${XATTR_INCLUDE_DIRS}
)

target_link_libraries(mksquashfs
    PRIVATE
        Threads::Threads
        m
        ${ZLIB_LIBRARIES}
        ${LIBLZMA_LIBRARIES}
        ${LZO_LIBRARIES}
        ${LZ4_LIBRARY}
        ${ZSTD_LIBRARIES}
        ${XATTR_LIBRARIES}
)
target_link_libraries(unsquashfs
    PRIVATE
        Threads::Threads
        m
        ${ZLIB_LIBRARIES}
        ${LIBLZMA_LIBRARIES}
        ${LZO_LIBRARIES}
        ${LZ4_LIBRARY}
        ${ZSTD_LIBRARIES}
        ${XATTR_LIBRARIES}
)

install(TARGETS unsquashfs mksquashfs DESTINATION ${CMAKE_INSTALL_BINDIR})
install(CODE "execute_process(COMMAND ln -fs ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}/unsquashfs ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}/sqfscat)")
install(CODE "execute_process(COMMAND ln -fs ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}/mksquashfs ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}/sqfstar)")
install(CODE "execute_process(COMMAND ${CMAKE_SOURCE_DIR}/../generate-manpages/install-manpages.sh ${CMAKE_SOURCE_DIR}/.. ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_MANDIR}/man1 ${USE_PREBUILT_MANPAGES})")

