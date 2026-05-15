# Security Audit Report for squashfs-tools

**Date:** October 2025  
**Scope:** Complete codebase security analysis  
**Focus Areas:** Integer overflow, buffer overflow, memory errors (double-free, use-after-free, dangling pointers)

## Executive Summary

This security audit identified several classes of potential vulnerabilities in the squashfs-tools codebase. The analysis covered integer overflow protection, buffer management, and memory safety. Overall, the codebase shows good security practices with integer overflow protection functions, but there are areas that could benefit from improvements.

## Positive Security Findings

### 1. Integer Overflow Protection

**Location:** `mksquashfs.c`, `unsquashfs.c`, `caches-queues-lists.c`

The codebase implements dedicated overflow checking functions:

```c
// Lines 461-475 in mksquashfs.c
int add_overflow(int a, int b)
{
    return (INT_MAX - a) < b;
}

int shift_overflow(int a, int shift)
{
    return (INT_MAX >> shift) < a;
}

int multiply_overflow(int a, int multiplier)
{
    return (INT_MAX / multiplier) < a;
}
```

These functions are actively used in critical allocation paths:
- Queue initialization (line 222-223 in `unsquashfs.c`)
- Memory allocation calculations (line 5301-5307 in `mksquashfs.c`)
- Thread array allocation (line 5363-5364 in `mksquashfs.c`)

**Status:** ✅ GOOD - Proactive overflow prevention

### 2. Memory Allocation Wrappers

**Location:** `alloc.h`

Safe allocation wrappers that exit on allocation failure:

```c
#define MALLOC(size) _malloc(size, __func__)
#define CALLOC(num, size) _calloc(num, size, __func__)
#define REALLOC(ptr, size) _realloc(ptr, size, __func__)
```

All wrapper functions check for NULL return and call `MEM_ERROR()` macro.

**Status:** ✅ GOOD - Prevents NULL pointer dereferences

## Potential Security Issues

### 1. Unsafe String Operations - Buffer Overflow Risk

**Severity:** HIGH  
**Type:** Buffer Overflow

#### Issue 1.1: strcat() without explicit bounds checking

**Location:** `mksquashfs.c:3204`

```c
// Line 3204 in mksquashfs.c
strcat(strcat(b_buffer, "/"), pathname);
```

**Analysis:** While there is a bounds check on line 3202-3203:
```c
if(result && strlen(pathname) + 2 <= b_size - strlen(b_buffer))
```

The nested `strcat()` calls are risky because:
1. The first `strcat()` modifies `b_buffer`, making the second call's behavior dependent on the first
2. Between the check and the operation, there's a TOCTOU (Time-Of-Check-Time-Of-Use) window
3. More readable and safer alternatives exist

**Recommendation:** Replace with `snprintf()` or use explicit buffer size tracking:
```c
size_t offset = strlen(b_buffer);
snprintf(b_buffer + offset, b_size - offset, "/%s", pathname);
```

#### Issue 1.2: Multiple strcat() operations

**Location:** `unsquashfs.c:1855-1859`

```c
// Lines 1855-1859 in unsquashfs.c
for(i = 1; i < stack->size; i++) {
    strcat(pathname, stack->stack[i].name);
    strcat(pathname, "/");
}
strcat(pathname, name);
```

**Analysis:** Size is pre-calculated on lines 1844-1848, but:
1. If calculation has a bug, buffer overflow occurs
2. No runtime bounds checking during concatenation
3. Vulnerable to integer overflow in size calculation if `stack->size` is very large

**Recommendation:** 
- Add runtime assertions to verify buffer size
- Use `strncat()` with explicit remaining space calculation
- Consider using `snprintf()` for safer concatenation

#### Issue 1.3: strcpy() operations

**Location:** Multiple files

```c
// mksquashfs.c:3208
strcpy(b_buffer, pathname);

// mksquashfs.c:4669-4670
strcpy(*pathname, orig);
strcat(*pathname, "/");

// unsquashfs.c:540
strcpy(str, "----------");  // Fixed size, safe

// unsquashfs.c:3187-3188
strcpy(newpath, "/");
strcat(newpath, name);
```

**Analysis:** Most instances have pre-calculated buffer sizes, but:
- Relies on correct size calculation
- No runtime verification
- Traditional unsafe function usage

**Recommendation:** Replace with safer alternatives:
```c
strncpy(dest, src, size);
dest[size-1] = '\0';  // Ensure null termination
```

### 2. Potential Integer Overflow in Size Calculations

**Severity:** MEDIUM  
**Type:** Integer Overflow

#### Issue 2.1: Unchecked multiplication in buffer size calculation

**Location:** `unsquashfs.c:1844-1848`

```c
// Lines 1844-1848
for(i = 1; i < stack->size; i++)
    size += strlen(stack->stack[i].name);
size += strlen(name) + stack->size;
```

**Analysis:**
- If `stack->size` is large and string names are long, `size` could overflow
- No overflow check before calling `MALLOC(size)`
- Could result in small allocation with large write, causing heap overflow

**Recommendation:** Add overflow checking:
```c
for(i = 1; i < stack->size; i++) {
    size_t name_len = strlen(stack->stack[i].name);
    if (add_overflow(size, name_len))
        BAD_ERROR("Path size overflow\n");
    size += name_len;
}
```

#### Issue 2.2: Shift operations without overflow protection

**Location:** Multiple files

```c
// mksquashfs.c:682, 688
int realloc_size = cache_size == 0 ?
    ((req_size + SQUASHFS_METADATA_SIZE) &
    ~(SQUASHFS_METADATA_SIZE - 1)) : req_size - cache_size;
data_cache = REALLOC(data_cache, cache_size + realloc_size);
```

**Analysis:**
- Bit operations used for size calculations
- Assumes `SQUASHFS_METADATA_SIZE` is a power of 2
- No explicit overflow check before adding to `cache_size`

**Recommendation:** Add overflow check:
```c
if (add_overflow(cache_size, realloc_size))
    BAD_ERROR("Cache size overflow\n");
```

### 3. Memory Management Issues

**Severity:** LOW-MEDIUM  
**Type:** Use-after-free, Double-free potential

#### Issue 3.1: Recursive free operations

**Location:** `mksquashfs.c:4246-4264`

```c
void free_dir(struct dir_info *dir)
{
    struct dir_ent *dir_ent = dir->list;
    
    while(dir_ent) {
        struct dir_ent *tmp = dir_ent;
        
        if((dir_ent->inode->buf.st_mode & S_IFMT) == S_IFDIR)
            if(dir_ent->dir)
                free_dir(dir_ent->dir);  // Recursive call
        
        dir_ent = dir_ent->next;
        free_dir_entry(tmp);
    }
    
    free(dir->pathname);
    free(dir->subpath);
    free(dir);
}
```

**Analysis:**
- Deep recursion could cause stack overflow with deeply nested directories
- If `dir_ent->dir` is shared (aliased), double-free could occur
- No NULL checks after free operations (but not used after free in this function)

**Recommendation:**
- Add recursion depth limit
- Consider iterative approach using explicit stack
- Ensure dir ownership is clear (no aliasing)

#### Issue 3.2: free_dir_entry() without nullification

**Location:** `mksquashfs.c:3480-3496`

```c
void free_dir_entry(struct dir_ent *dir_ent)
{
    if(dir_ent->name)
        free(dir_ent->name);
    
    if(dir_ent->source_name)
        free(dir_ent->source_name);
    
    if(dir_ent->nonstandard_pathname)
        free(dir_ent->nonstandard_pathname);
    
    dec_nlink_inode(dir_ent);
    
    free(dir_ent);
}
```

**Analysis:**
- Freed pointers within the structure are not set to NULL
- If structure is accessed after free (though it shouldn't be), use-after-free occurs
- `dec_nlink_inode()` accesses `dir_ent` after partial free of its members

**Recommendation:**
- While the function itself is safe, callers should NULL their pointers
- Consider defensive programming: NULL out freed pointers

### 4. Race Conditions in Multi-threaded Code

**Severity:** MEDIUM  
**Type:** Race condition, TOCTOU

#### Issue 4.1: Thread state management

**Location:** `thread.c:50-58`

```c
void set_thread_idle(int tid)
{
    if(threads[tid].type == THREAD_BLOCK)
        active_blocks --;
    else
        active_frags --;
    
    if(waiting_threads)
        pthread_cond_signal(&idle);
    
    threads[tid].state = THREAD_IDLE;
}
```

**Analysis:**
- Function assumes mutex is held by caller (documented in comment)
- No explicit assertion to verify mutex is held
- If called without mutex, race conditions on shared state

**Recommendation:**
- Add debug assertion to verify mutex ownership
- Document mutex requirements more prominently

### 5. Input Validation Issues

**Severity:** MEDIUM  
**Type:** Insufficient input validation

#### Issue 5.1: fgets() usage without size validation

**Location:** Multiple files

```c
// action.c:138
err = fgets(line + total, MAX_LINE + 1, fd);

// mksquashfs.c:5652
while(fgets(filename = buffer, MAX_LINE + 1, fd) != NULL) {
```

**Analysis:**
- `MAX_LINE` is presumably defined, but no check if line exceeds limit
- Lines longer than `MAX_LINE` are silently truncated
- Could lead to parsing errors or security issues

**Recommendation:**
- Verify complete line was read
- Return error if line is too long
- Document maximum line length limitations

## Additional Observations

### 1. Good Practices Found

1. **Error handling:** Most functions check return values and use `BAD_ERROR()` macros
2. **Const correctness:** Good use of `const` in function parameters
3. **NULL checks:** Most pointer dereferences are preceded by NULL checks
4. **Documentation:** Functions are well-commented

### 2. Areas for Improvement

1. **Static analysis:** No evidence of regular static analysis tool usage (cppcheck, clang-tidy)
2. **Fuzzing:** No fuzzing infrastructure visible
3. **Unit tests:** No unit test framework found
4. **Bounds checking:** Could use more runtime bounds checking in debug builds
5. **Safe string library:** Consider using safer string handling libraries

## Recommendations Summary

### High Priority

1. Replace all `strcpy()` and `strcat()` with bounds-checked alternatives (`strncpy()`, `strncat()`, or `snprintf()`)
2. Add overflow checks to all size calculations before allocation
3. Audit all array indexing operations for bounds checks
4. Add runtime assertions in debug builds

### Medium Priority

1. Implement recursion depth limits for recursive functions
2. Add static analysis to build process
3. Implement fuzzing tests for file parsing
4. Add mutex ownership assertions in thread code

### Low Priority

1. Add unit test framework
2. Document all security-critical functions
3. Consider using AddressSanitizer and UndefinedBehaviorSanitizer during development
4. Create secure coding guidelines document

## Conclusion

The squashfs-tools codebase demonstrates good awareness of security issues, particularly with integer overflow protection. However, there are opportunities to improve buffer safety and memory management practices. Most identified issues are in the MEDIUM to LOW severity range, as they require specific conditions to trigger.

No immediate critical vulnerabilities were found that would allow remote code execution or privilege escalation under normal usage. The most significant risks are buffer overflows from malformed input files or extremely deep directory structures.

### Testing Recommendations

1. **Fuzzing:** Use AFL or libFuzzer on file parsing functions
2. **Sanitizers:** Build with AddressSanitizer, UndefinedBehaviorSanitizer, and MemorySanitizer
3. **Static Analysis:** Run cppcheck, clang-tidy, and scan-build regularly
4. **Valgrind:** Run all test cases under Valgrind to detect memory leaks and use-after-free

### Compliance

This audit focused on common vulnerability patterns:
- ✅ Buffer overflows: Found potential issues, recommendations provided
- ✅ Integer overflows: Good protection exists, some gaps identified  
- ✅ Use-after-free: No definitive issues found, defensive improvements suggested
- ✅ Double-free: No issues found, code appears safe
- ✅ Dangling pointers: No issues found, proper ownership model

---

**Auditor's Note:** This audit was performed through static code review. Dynamic analysis with fuzzing and sanitizers is strongly recommended to identify runtime issues not visible through static analysis.
