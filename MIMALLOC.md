# mimalloc Memory Allocator Support

## Overview

squashfs-tools now supports using [mimalloc](https://github.com/microsoft/mimalloc) as an alternative memory allocator. mimalloc is a high-performance, general-purpose memory allocator developed by Microsoft Research with several advantages:

- **Performance**: Often faster than system default allocators, especially in multi-threaded scenarios
- **Memory efficiency**: Better memory utilization with less fragmentation
- **Security**: Includes security features like secure mode, heap initialization, and free list randomization
- **Thread-safe**: Excellent multi-threaded performance without lock contention
- **Production-ready**: Widely tested and used in production systems

## Building with mimalloc

### Prerequisites

Install the mimalloc development package for your distribution:

**Debian/Ubuntu:**
```bash
sudo apt-get install libmimalloc-dev
```

**Fedora/RHEL:**
```bash
sudo dnf install mimalloc-devel
```

**Arch Linux:**
```bash
sudo pacman -S mimalloc
```

**From source:**
```bash
git clone https://github.com/microsoft/mimalloc
cd mimalloc
mkdir -p out/release
cd out/release
cmake ../..
make
sudo make install
```

### Building squashfs-tools with mimalloc

To enable mimalloc support, use the `MIMALLOC_SUPPORT=1` flag when building:

```bash
cd squashfs-tools
make MIMALLOC_SUPPORT=1
```

You can combine this with other build options:

```bash
make MIMALLOC_SUPPORT=1 LZO_SUPPORT=0 LZ4_SUPPORT=0
```

### Alternative: Enable by default

Edit the `Makefile` and uncomment the `MIMALLOC_SUPPORT = 1` line:

```makefile
###############################################
#          Memory allocator options           #
###############################################
# ...
MIMALLOC_SUPPORT = 1  # <-- Uncomment this line
```

Then build normally:
```bash
make
```

## Implementation Details

When `MIMALLOC_SUPPORT` is enabled:

1. The build system links against `-lmimalloc`
2. The `alloc.h` header includes `<mimalloc.h>`
3. Standard memory allocation functions are redirected to mimalloc equivalents:
   - `malloc()` → `mi_malloc()`
   - `calloc()` → `mi_calloc()`
   - `realloc()` → `mi_realloc()`
   - `free()` → `mi_free()`
   - `strdup()` → `mi_strdup()`
   - `strndup()` → `mi_strndup()`

All code that uses the wrapper macros `MALLOC()`, `CALLOC()`, `REALLOC()`, `STRDUP()`, `STRNDUP()`, and direct calls to `free()` will automatically use mimalloc.

## Security Considerations

mimalloc provides several security features that make it suitable for use in squashfs-tools:

1. **Secure mode**: Can be enabled for additional security checks
2. **Heap isolation**: Separate heaps per thread to prevent cross-contamination
3. **Free list randomization**: Makes heap exploitation harder
4. **Double-free detection**: Detects and prevents double-free errors
5. **Overflow detection**: Guard pages and metadata protection
6. **Constant-time free**: Prevents timing attacks

These features align well with the security-focused design of squashfs-tools as documented in `SECURITY_AUDIT.md`.

## Performance

Benefits you may observe when using mimalloc:

- **Faster compression/decompression**: Especially with multi-threaded operations
- **Lower memory fragmentation**: Better memory utilization over long runs
- **Improved scalability**: Better performance with many parallel reader threads
- **Consistent performance**: More predictable allocation times

Actual performance gains depend on your workload, system configuration, and the specific operations being performed.

## Compatibility

- **Backward compatible**: The default build (without `MIMALLOC_SUPPORT`) uses standard allocators
- **ABI compatible**: Binaries built with or without mimalloc are compatible with the same filesystem format
- **No code changes required**: All existing code works without modification
- **Optional dependency**: Users who don't need mimalloc don't need to install it

## Troubleshooting

### Build fails with "mimalloc.h: No such file or directory"

The mimalloc development package is not installed. Install it using your distribution's package manager (see Prerequisites above).

### Runtime error "error while loading shared libraries: libmimalloc.so"

The mimalloc runtime library is not in your library path. Either:
- Install the mimalloc runtime package
- Add the library path to `LD_LIBRARY_PATH`
- Build mimalloc statically

### Performance is worse with mimalloc

This is rare but can happen. Factors to consider:
- System allocator may be highly optimized for your specific platform
- Workload characteristics may not benefit from mimalloc's design
- Try different mimalloc environment variables (see mimalloc documentation)
- Consider running benchmarks to compare

## References

- [mimalloc GitHub repository](https://github.com/microsoft/mimalloc)
- [mimalloc technical report](https://www.microsoft.com/en-us/research/publication/mimalloc-free-list-sharding-in-action/)
- [squashfs-tools security audit](SECURITY_AUDIT.md)
- [squashfs-tools security recommendations](SECURITY_RECOMMENDATIONS.md)
