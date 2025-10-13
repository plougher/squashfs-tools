# Security Recommendations and Remediation Guide

This document provides actionable recommendations to address the security issues identified in the squashfs-tools codebase.

## Quick Reference Table

| Priority | Category | Files Affected | Effort | Impact |
|----------|----------|----------------|--------|--------|
| 🔴 HIGH | Buffer Operations | mksquashfs.c, unsquashfs.c, pseudo.c | Medium | High |
| 🟡 MEDIUM | Integer Overflow | mksquashfs.c, unsquashfs.c | Low | High |
| 🟡 MEDIUM | Memory Safety | mksquashfs.c | Medium | Medium |
| 🟢 LOW | Code Quality | thread.c, various | Low | Low |

## 1. Buffer Overflow Fixes

### Fix 1.1: Replace unsafe string operations globally

**Priority:** 🔴 HIGH  
**Effort:** Medium (2-3 days)  
**Risk:** Low (refactoring existing code)

Create a safe string operations library:

**New File:** `squashfs-tools/safe_string.h`

```c
#ifndef SAFE_STRING_H
#define SAFE_STRING_H

#include <string.h>
#include <stdio.h>
#include "error.h"

/**
 * Safe string copy with bounds checking
 * Returns 0 on success, -1 if truncated
 */
static inline int safe_strcpy(char *dst, const char *src, size_t size)
{
    if(size == 0)
        return -1;
    
    size_t src_len = strlen(src);
    if(src_len >= size) {
        strncpy(dst, src, size - 1);
        dst[size - 1] = '\0';
        return -1;  // Truncated
    }
    
    strcpy(dst, src);
    return 0;
}

/**
 * Safe string concatenation with bounds checking
 * Returns 0 on success, -1 if truncated
 */
static inline int safe_strcat(char *dst, const char *src, size_t size)
{
    size_t dst_len = strlen(dst);
    size_t src_len = strlen(src);
    
    if(dst_len + src_len >= size) {
        strncat(dst, src, size - dst_len - 1);
        return -1;  // Truncated
    }
    
    strcat(dst, src);
    return 0;
}

/**
 * Safe path concatenation
 * Automatically adds '/' separator
 */
static inline int safe_path_concat(char *dst, const char *path, 
                                   const char *name, size_t size)
{
    size_t path_len = strlen(path);
    size_t name_len = strlen(name);
    size_t needed;
    
    // Calculate needed space: path + '/' + name + '\0'
    if(path_len > 0 && path[path_len - 1] == '/')
        needed = path_len + name_len + 1;
    else
        needed = path_len + name_len + 2;
    
    if(needed > size)
        return -1;  // Not enough space
    
    if(safe_strcpy(dst, path, size) < 0)
        return -1;
    
    if(path_len > 0 && path[path_len - 1] != '/') {
        if(safe_strcat(dst, "/", size) < 0)
            return -1;
    }
    
    if(safe_strcat(dst, name, size) < 0)
        return -1;
    
    return 0;
}

/**
 * Safe string formatting with error checking
 */
#define SAFE_SPRINTF(buf, size, fmt, ...) \
    do { \
        int _ret = snprintf(buf, size, fmt, ##__VA_ARGS__); \
        if(_ret < 0 || (size_t)_ret >= size) \
            BAD_ERROR("String formatting overflow\n"); \
    } while(0)

#endif /* SAFE_STRING_H */
```

**Usage Example:**

Replace this:
```c
// OLD - mksquashfs.c:3204
strcat(strcat(b_buffer, "/"), pathname);
```

With this:
```c
// NEW
if(safe_path_concat(b_buffer, b_buffer, pathname, b_size) < 0)
    BAD_ERROR("Path too long in getbase\n");
```

### Fix 1.2: Specific file changes

**File:** `squashfs-tools/mksquashfs.c`

**Line 3204:** 
```c
// BEFORE
strcat(strcat(b_buffer, "/"), pathname);

// AFTER
size_t current_len = strlen(b_buffer);
int ret = snprintf(b_buffer + current_len, b_size - current_len, 
                   "/%s", pathname);
if(ret < 0 || (size_t)ret >= b_size - current_len)
    BAD_ERROR("Path buffer overflow in getbase\n");
```

**Lines 4669-4671:**
```c
// BEFORE
*pathname = MALLOC(size);
strcpy(*pathname, orig);
strcat(*pathname, "/");
strncat(*pathname, path, source - path);

// AFTER
*pathname = MALLOC(size);
int ret = snprintf(*pathname, size, "%s/%.*s", 
                   orig, (int)(source - path), path);
if(ret < 0 || (size_t)ret >= size)
    BAD_ERROR("Path format overflow\n");
```

**File:** `squashfs-tools/unsquashfs.c`

**Lines 1853-1859:**
```c
// BEFORE
pathname = MALLOC(size);
pathname[0] = '\0';
for(i = 1; i < stack->size; i++) {
    strcat(pathname, stack->stack[i].name);
    strcat(pathname, "/");
}
strcat(pathname, name);

// AFTER
pathname = MALLOC(size);
size_t offset = 0;

for(i = 1; i < stack->size; i++) {
    int ret = snprintf(pathname + offset, size - offset, 
                      "%s/", stack->stack[i].name);
    if(ret < 0 || (size_t)ret >= size - offset)
        BAD_ERROR("Path construction overflow\n");
    offset += ret;
}

int ret = snprintf(pathname + offset, size - offset, "%s", name);
if(ret < 0 || (size_t)ret >= size - offset)
    BAD_ERROR("Path construction overflow\n");
```

## 2. Integer Overflow Fixes

### Fix 2.1: Enhanced overflow checking

**File:** `squashfs-tools/unsquashfs.c`

**Lines 1844-1848:**
```c
// BEFORE
int i, size = 0;
char *pathname;

for(i = 1; i < stack->size; i++)
    size += strlen(stack->stack[i].name);

size += strlen(name) + stack->size;

// AFTER
int i;
size_t size = 0;  // Use size_t
char *pathname;

for(i = 1; i < stack->size; i++) {
    size_t name_len = strlen(stack->stack[i].name);
    if(SIZE_MAX - size < name_len)
        BAD_ERROR("Path size overflow (too deep or too long)\n");
    size += name_len;
}

size_t name_len = strlen(name);
if(SIZE_MAX - size < name_len + stack->size)
    BAD_ERROR("Path size overflow\n");
    
size += name_len + stack->size;

// Sanity check
if(size > PATH_MAX)
    BAD_ERROR("Path exceeds system maximum (%zu > %d)\n", 
              size, PATH_MAX);
```

### Fix 2.2: Safe pointer arithmetic

**File:** `squashfs-tools/mksquashfs.c`

**Lines 4665-4672:**
```c
// BEFORE
char *orig = *pathname;
int size = strlen(orig) + (source - path) + 2;

// AFTER
char *orig = *pathname;
size_t orig_len = strlen(orig);
ptrdiff_t diff = source - path;

// Validate pointer difference
if(diff < 0 || diff > PATH_MAX)
    BAD_ERROR("Invalid path component length: %td\n", diff);

// Use compiler builtin for overflow detection
size_t size;
if(__builtin_add_overflow(orig_len, (size_t)diff, &size) ||
   __builtin_add_overflow(size, 2, &size))
    BAD_ERROR("Path size overflow\n");

// Alternative for older compilers:
// size_t size = orig_len;
// if(SIZE_MAX - size < (size_t)diff)
//     BAD_ERROR("Path size overflow\n");
// size += (size_t)diff;
// if(SIZE_MAX - size < 2)
//     BAD_ERROR("Path size overflow\n");
// size += 2;
```

### Fix 2.3: Add overflow checks to cache operations

**File:** `squashfs-tools/mksquashfs.c`

**Lines 682-689:**
```c
// BEFORE
int realloc_size = cache_size == 0 ?
    ((req_size + SQUASHFS_METADATA_SIZE) &
    ~(SQUASHFS_METADATA_SIZE - 1)) : req_size - cache_size;

data_cache = REALLOC(data_cache, cache_size + realloc_size);
cache_size += realloc_size;

// AFTER
// Add compile-time assertion
_Static_assert((SQUASHFS_METADATA_SIZE & (SQUASHFS_METADATA_SIZE - 1)) == 0,
               "SQUASHFS_METADATA_SIZE must be power of 2");

int realloc_size = cache_size == 0 ?
    ((req_size + SQUASHFS_METADATA_SIZE) &
    ~(SQUASHFS_METADATA_SIZE - 1)) : req_size - cache_size;

// Check for overflow before realloc
if(add_overflow(cache_size, realloc_size))
    BAD_ERROR("Cache size overflow\n");

data_cache = REALLOC(data_cache, cache_size + realloc_size);
cache_size += realloc_size;
```

## 3. Memory Safety Fixes

### Fix 3.1: Convert recursive function to iterative

**File:** `squashfs-tools/mksquashfs.c`

**Lines 4246-4264:**

Option A - Add recursion limit (simpler, less code change):

```c
// Add at top of file
#define MAX_DIR_DEPTH 4096

// Add helper function
static void free_dir_impl(struct dir_info *dir, int depth)
{
    struct dir_ent *dir_ent;
    
    if(depth > MAX_DIR_DEPTH)
        BAD_ERROR("Directory nesting exceeds maximum depth (%d)\n",
                  MAX_DIR_DEPTH);
    
    dir_ent = dir->list;
    while(dir_ent) {
        struct dir_ent *tmp = dir_ent;
        
        if((dir_ent->inode->buf.st_mode & S_IFMT) == S_IFDIR)
            if(dir_ent->dir)
                free_dir_impl(dir_ent->dir, depth + 1);
        
        dir_ent = dir_ent->next;
        free_dir_entry(tmp);
    }
    
    free(dir->pathname);
    free(dir->subpath);
    free(dir);
}

void free_dir(struct dir_info *dir)
{
    free_dir_impl(dir, 0);
}
```

Option B - Full iterative conversion (safer, more complex):

```c
void free_dir(struct dir_info *dir)
{
    // Stack for iterative traversal
    struct dir_stack_item {
        struct dir_info *dir;
        struct dir_ent *next_entry;
        int processing;
    };
    
    struct dir_stack_item *stack = NULL;
    int stack_size = 0;
    int stack_capacity = 64;
    
    stack = MALLOC(stack_capacity * sizeof(struct dir_stack_item));
    
    // Push initial directory
    stack[0].dir = dir;
    stack[0].next_entry = dir->list;
    stack[0].processing = 0;
    stack_size = 1;
    
    while(stack_size > 0) {
        struct dir_stack_item *top = &stack[stack_size - 1];
        
        if(!top->processing) {
            // First time processing this directory
            top->processing = 1;
            top->next_entry = top->dir->list;
        }
        
        if(top->next_entry) {
            struct dir_ent *entry = top->next_entry;
            top->next_entry = entry->next;
            
            // If this is a directory, push it onto stack
            if((entry->inode->buf.st_mode & S_IFMT) == S_IFDIR && 
               entry->dir) {
                // Grow stack if needed
                if(stack_size >= stack_capacity) {
                    stack_capacity *= 2;
                    stack = REALLOC(stack, 
                                   stack_capacity * sizeof(struct dir_stack_item));
                }
                
                stack[stack_size].dir = entry->dir;
                stack[stack_size].next_entry = entry->dir->list;
                stack[stack_size].processing = 0;
                stack_size++;
            } else {
                // Not a directory or already processed
                free_dir_entry(entry);
            }
        } else {
            // All entries processed, free this directory
            free(top->dir->pathname);
            free(top->dir->subpath);
            free(top->dir);
            stack_size--;
        }
    }
    
    free(stack);
}
```

### Fix 3.2: Add defensive NULL checks

**File:** `squashfs-tools/mksquashfs.c`

**Lines 3480-3496:**

```c
// BEFORE
void free_dir_entry(struct dir_ent *dir_ent)
{
    if(dir_ent->name)
        free(dir_ent->name);
    // ...
    free(dir_ent);
}

// AFTER
void free_dir_entry(struct dir_ent *dir_ent)
{
    if(dir_ent == NULL)
        return;  // Defensive check
    
    if(dir_ent->name) {
        free(dir_ent->name);
        dir_ent->name = NULL;  // Prevent double-free
    }
    
    if(dir_ent->source_name) {
        free(dir_ent->source_name);
        dir_ent->source_name = NULL;
    }
    
    if(dir_ent->nonstandard_pathname) {
        free(dir_ent->nonstandard_pathname);
        dir_ent->nonstandard_pathname = NULL;
    }
    
    dec_nlink_inode(dir_ent);
    free(dir_ent);
    // Note: Caller should NULL their pointer to dir_ent
}
```

## 4. Thread Safety Fixes

### Fix 4.1: Add mutex assertions

**File:** `squashfs-tools/thread.c`

Add to header:
```c
// thread.h
#ifndef NDEBUG
#define ASSERT_MUTEX_HELD(mtx) assert_mutex_held(mtx, __func__)
void assert_mutex_held(pthread_mutex_t *mutex, const char *func);
#else
#define ASSERT_MUTEX_HELD(mtx)
#endif
```

Add to implementation:
```c
// thread.c
#ifndef NDEBUG
void assert_mutex_held(pthread_mutex_t *mutex, const char *func)
{
    int ret = pthread_mutex_trylock(mutex);
    if(ret == 0) {
        // We got the lock, meaning it wasn't held
        pthread_mutex_unlock(mutex);
        BAD_ERROR("%s: mutex not held (programming error)\n", func);
    }
    // If ret == EBUSY, mutex is held (good)
    // If ret is other error, something is wrong
    if(ret != EBUSY)
        BAD_ERROR("%s: mutex state error: %d\n", func, ret);
}
#endif

// Update functions
void set_thread_idle(int tid)
{
    ASSERT_MUTEX_HELD(&thread_mutex);
    
    if(threads[tid].type == THREAD_BLOCK)
        active_blocks --;
    else
        active_frags --;
    
    if(waiting_threads)
        pthread_cond_signal(&idle);
    
    threads[tid].state = THREAD_IDLE;
}
```

## 5. Input Validation Fixes

### Fix 5.1: Validate fgets() results

Create helper function:

```c
/**
 * Safe line reading with length checking
 * Returns: 1 on success, 0 on EOF, -1 on error or line too long
 */
static int safe_fgets(char *buf, size_t size, FILE *fp, const char *filename)
{
    if(fgets(buf, size, fp) == NULL) {
        if(feof(fp))
            return 0;  // EOF
        else
            return -1;  // Error
    }
    
    size_t len = strlen(buf);
    
    // Check if we got complete line (ends with newline or EOF)
    if(len > 0 && buf[len - 1] != '\n' && !feof(fp)) {
        // Line is too long - read and discard rest of line
        int c;
        while((c = fgetc(fp)) != EOF && c != '\n')
            ;
        
        BAD_ERROR("Line too long in %s (max %zu bytes)\n", 
                  filename, size - 1);
        return -1;
    }
    
    // Remove trailing newline
    if(len > 0 && buf[len - 1] == '\n')
        buf[len - 1] = '\0';
    
    return 1;
}
```

Replace all fgets() usage:
```c
// BEFORE
while(fgets(filename = buffer, MAX_LINE + 1, fd) != NULL) {
    // process line
}

// AFTER
while(safe_fgets(buffer, MAX_LINE + 1, fd, "input file") == 1) {
    filename = buffer;
    // process line
}
```

## 6. Build System Improvements

### Fix 6.1: Add sanitizer support

**File:** `squashfs-tools/Makefile`

Add build options:
```makefile
# Security-hardened build flags
SECURITY_CFLAGS = -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
                  -Wformat -Wformat-security -Werror=format-security

# Sanitizer builds (for development/testing)
ifdef ASAN
    SANITIZER_FLAGS += -fsanitize=address -fno-omit-frame-pointer
endif

ifdef UBSAN
    SANITIZER_FLAGS += -fsanitize=undefined
endif

ifdef MSAN
    SANITIZER_FLAGS += -fsanitize=memory -fno-omit-frame-pointer
endif

CFLAGS += $(SECURITY_CFLAGS) $(SANITIZER_FLAGS)
LDFLAGS += $(SANITIZER_FLAGS)
```

Usage:
```bash
# Normal build with security flags
make

# AddressSanitizer build (detects buffer overflows, use-after-free)
make ASAN=1

# UndefinedBehaviorSanitizer build (detects integer overflow, etc.)
make UBSAN=1

# Both
make ASAN=1 UBSAN=1
```

### Fix 6.2: Add static analysis

Create `.github/workflows/security-analysis.yml`:
```yaml
name: Security Analysis

on: [push, pull_request]

jobs:
  cppcheck:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Install cppcheck
        run: sudo apt-get install -y cppcheck
      - name: Run cppcheck
        run: |
          cppcheck --enable=all --error-exitcode=1 \
            --suppress=missingIncludeSystem \
            squashfs-tools/
  
  clang-tidy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Install clang-tidy
        run: sudo apt-get install -y clang-tidy
      - name: Run clang-tidy
        run: |
          clang-tidy squashfs-tools/*.c -- -I. -D_GNU_SOURCE
```

## 7. Testing Recommendations

### Test 7.1: Fuzzing setup

Create fuzzing harness:

**File:** `squashfs-tools/fuzz/fuzz_unsquash.c`

```c
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// AFL++ fuzzing target
int main(int argc, char **argv)
{
    if(argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }
    
    // Read input file
    FILE *fp = fopen(argv[1], "rb");
    if(!fp) {
        perror("fopen");
        return 1;
    }
    
    // Create temp output directory
    char tmpdir[] = "/tmp/fuzz_XXXXXX";
    if(!mkdtemp(tmpdir)) {
        perror("mkdtemp");
        fclose(fp);
        return 1;
    }
    
    // Call unsquashfs on the input
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "./unsquashfs -d %s %s 2>/dev/null",
             tmpdir, argv[1]);
    system(cmd);
    
    // Cleanup
    snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
    system(cmd);
    
    fclose(fp);
    return 0;
}
```

Build and run:
```bash
# Install AFL++
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus && make && sudo make install

# Build with AFL
cd squashfs-tools
CC=afl-gcc make

# Create seed corpus
mkdir fuzz_in
# Add some valid squashfs files to fuzz_in/

# Run fuzzer
afl-fuzz -i fuzz_in -o fuzz_out -- ./unsquashfs -d /tmp/out @@
```

## Implementation Priority

### Phase 1 (Week 1-2): Critical Fixes
1. ✅ Replace `strcpy()`/`strcat()` in `mksquashfs.c` lines 3204, 4669-4671
2. ✅ Replace `strcpy()`/`strcat()` in `unsquashfs.c` lines 1855-1859
3. ✅ Add integer overflow checks to size calculations

### Phase 2 (Week 3-4): Enhanced Safety
1. ✅ Implement safe string library
2. ✅ Add recursion limits to `free_dir()`
3. ✅ Add mutex assertions to thread code
4. ✅ Enhance input validation

### Phase 3 (Week 5-6): Testing & Infrastructure
1. ✅ Add sanitizer support to Makefile
2. ✅ Set up static analysis CI
3. ✅ Create fuzzing harness
4. ✅ Run comprehensive tests

### Phase 4 (Ongoing): Maintenance
1. ✅ Monitor fuzzing results
2. ✅ Regular static analysis runs
3. ✅ Keep dependencies updated
4. ✅ Security patch reviews

## Success Metrics

- [ ] Zero buffer overflow vulnerabilities detected by ASAN
- [ ] Zero integer overflow warnings from UBSAN
- [ ] Zero critical warnings from cppcheck
- [ ] Zero critical warnings from clang-tidy
- [ ] 24 hours of fuzzing without crashes
- [ ] All test cases pass with sanitizers enabled

## Conclusion

These recommendations provide a comprehensive path to improving the security of squashfs-tools. The fixes are designed to be:

1. **Minimal:** Small, focused changes
2. **Safe:** Low risk of breaking existing functionality
3. **Testable:** Can be validated with automated tools
4. **Maintainable:** Clear, well-documented code

Implementation should proceed in phases, with thorough testing at each stage.
