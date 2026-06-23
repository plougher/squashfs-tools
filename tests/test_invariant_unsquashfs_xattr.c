#include <check.h>
#include <stdlib.h>
#include <string.h>

START_TEST(test_xattr_octal_format_bounds)
{
    /* Invariant: snprintf with size 5 must contain any unsigned char octal representation */
    unsigned char dest[6] = {0}; /* 5 bytes + sentinel */
    unsigned char test_values[] = {
        0,    /* smallest value */
        1,    /* low boundary */
        31,   /* last non-printable below space */
        127,  /* DEL */
        255   /* max unsigned char: octal \377 */
    };

    for (int i = 0; i < 5; i++) {
        memset(dest, 0xAA, sizeof(dest));
        dest[5] = 0; /* sentinel must stay 0 */

        snprintf((char *) dest, 5, "\\%03o", test_values[i]);

        ck_assert_msg(dest[5] == 0,
                     "snprintf wrote past 5-byte buffer for value %u", test_values[i]);
        ck_assert_msg(dest[0] == '\\',
                     "Missing backslash for value %u", test_values[i]);
        ck_assert_msg(strlen((char *)dest) == 4,
                     "Expected 4-char output for value %u, got %zu",
                     test_values[i], strlen((char *)dest));
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
