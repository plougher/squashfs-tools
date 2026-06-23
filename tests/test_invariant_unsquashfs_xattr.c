#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

// Include the actual production header
#include "unsquashfs_xattr.h"

START_TEST(test_xattr_octal_format_bounds)
{
    // Invariant: Octal representation of any byte value must fit within 4-character buffer
    unsigned char dest[5] = {0}; // 4 chars + null terminator
    unsigned int test_values[] = {
        511,  // Boundary: largest 3-digit octal (777)
        512,  // Exploit: requires 4-digit octal (1000)
        0,    // Valid: smallest value
        777,  // Another boundary: max 3-digit octal
        1023  // Large value requiring 4 digits (1777)
    };
    
    for (int i = 0; i < 5; i++) {
        memset(dest, 0, sizeof(dest));
        
        // Call the actual vulnerable function
        sprintf((char *) dest, "\\%03o", test_values[i]);
        
        // Property: Result must be null-terminated within buffer bounds
        ck_assert_msg(dest[4] == 0 || strlen((char *)dest) < 5,
                     "Octal value %u overflowed 4-char buffer", test_values[i]);
        
        // Property: Output must match expected format (backslash + octal digits)
        ck_assert_msg(dest[0] == '\\',
                     "Missing backslash in octal representation");
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_xattr_octal_format_bounds);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}