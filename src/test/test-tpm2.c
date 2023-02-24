/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "tpm2-util.h"
#include "tests.h"

static void test_tpm2_parse_pcrs_one(const char *s, uint32_t mask, int ret) {
        uint32_t m;

        assert_se(tpm2_parse_pcrs(s, &m) == ret);

        if (ret >= 0)
                assert_se(m == mask);
}

TEST(tpm2_parse_pcrs) {
        test_tpm2_parse_pcrs_one("", 0, 0);
        test_tpm2_parse_pcrs_one("0", 1, 0);
        test_tpm2_parse_pcrs_one("1", 2, 0);
        test_tpm2_parse_pcrs_one("0,1", 3, 0);
        test_tpm2_parse_pcrs_one("0+1", 3, 0);
        test_tpm2_parse_pcrs_one("0-1", 0, -EINVAL);
        test_tpm2_parse_pcrs_one("0,1,2", 7, 0);
        test_tpm2_parse_pcrs_one("0+1+2", 7, 0);
        test_tpm2_parse_pcrs_one("0+1,2", 7, 0);
        test_tpm2_parse_pcrs_one("0,1+2", 7, 0);
        test_tpm2_parse_pcrs_one("0,2", 5, 0);
        test_tpm2_parse_pcrs_one("0+2", 5, 0);
        test_tpm2_parse_pcrs_one("foo", 0, -EINVAL);
}

/* this test includes TPM2 specific data structures */
TEST(tpm2_get_primary_template) {

        /*
         * Verify that if someone changes the template code, they know they're breaking things.
         * Templates MUST be changed in a backwards compatible way.
         *
         */
        static const TPM2B_PUBLIC templ[] = {
                /* index 0 RSA old */
                [0] = {
                        .publicArea = {
                                .type = TPM2_ALG_RSA,
                                .nameAlg = TPM2_ALG_SHA256,
                                .objectAttributes = TPMA_OBJECT_RESTRICTED|TPMA_OBJECT_DECRYPT|TPMA_OBJECT_FIXEDTPM|TPMA_OBJECT_FIXEDPARENT|TPMA_OBJECT_SENSITIVEDATAORIGIN|TPMA_OBJECT_USERWITHAUTH,
                                .parameters.rsaDetail = {
                                        .symmetric = {
                                                .algorithm = TPM2_ALG_AES,
                                                .keyBits.aes = 128,
                                                .mode.aes = TPM2_ALG_CFB,
                                        },
                                        .scheme.scheme = TPM2_ALG_NULL,
                                        .keyBits = 2048,
                                },
                        },
                },
                /* Index 1 ECC old */
                [TPM2_SRK_TEMPLATE_ECC] = {
                        .publicArea = {
                                .type = TPM2_ALG_ECC,
                                .nameAlg = TPM2_ALG_SHA256,
                                .objectAttributes = TPMA_OBJECT_RESTRICTED|TPMA_OBJECT_DECRYPT|TPMA_OBJECT_FIXEDTPM|TPMA_OBJECT_FIXEDPARENT|TPMA_OBJECT_SENSITIVEDATAORIGIN|TPMA_OBJECT_USERWITHAUTH,
                                .parameters.eccDetail = {
                                        .symmetric = {
                                                .algorithm = TPM2_ALG_AES,
                                                .keyBits.aes = 128,
                                                .mode.aes = TPM2_ALG_CFB,
                                        },
                                        .scheme.scheme = TPM2_ALG_NULL,
                                        .curveID = TPM2_ECC_NIST_P256,
                                        .kdf.scheme = TPM2_ALG_NULL,
                                },
                        },
                },
                /* index 2 RSA SRK */
                [TPM2_SRK_TEMPLATE_NEW_STYLE] = {
                        .publicArea = {
                                .type = TPM2_ALG_RSA,
                                .nameAlg = TPM2_ALG_SHA256,
                                .objectAttributes = TPMA_OBJECT_FIXEDTPM|TPMA_OBJECT_FIXEDPARENT|TPMA_OBJECT_SENSITIVEDATAORIGIN|TPMA_OBJECT_RESTRICTED|TPMA_OBJECT_DECRYPT|TPMA_OBJECT_USERWITHAUTH|TPMA_OBJECT_NODA,
                                .parameters.rsaDetail = {
                                        .symmetric = {
                                                .algorithm = TPM2_ALG_AES,
                                                .keyBits.aes = 128,
                                                .mode.aes = TPM2_ALG_CFB,
                                        },
                                        .scheme.scheme = TPM2_ALG_NULL,
                                        .keyBits = 2048,
                                },
                        },
                },
                /* Index 3 ECC SRK */
                [TPM2_SRK_TEMPLATE_NEW_STYLE | TPM2_SRK_TEMPLATE_ECC] = {
                        .publicArea = {
                                .type = TPM2_ALG_ECC,
                                .nameAlg = TPM2_ALG_SHA256,
                                .objectAttributes = TPMA_OBJECT_FIXEDTPM|TPMA_OBJECT_FIXEDPARENT|TPMA_OBJECT_SENSITIVEDATAORIGIN|TPMA_OBJECT_RESTRICTED|TPMA_OBJECT_DECRYPT|TPMA_OBJECT_USERWITHAUTH|TPMA_OBJECT_NODA,
                                .parameters.eccDetail = {
                                        .symmetric = {
                                                .algorithm = TPM2_ALG_AES,
                                                .keyBits.aes = 128,
                                                .mode.aes = TPM2_ALG_CFB,
                                        },
                                        .scheme.scheme = TPM2_ALG_NULL,
                                        .curveID = TPM2_ECC_NIST_P256,
                                        .kdf.scheme = TPM2_ALG_NULL,
                                },
                        },
                },
        };

        assert_cc(ELEMENTSOF(templ) == _TPM2_SRK_TEMPLATE_MAX + 1);

        for (size_t i = 0; i < ELEMENTSOF(templ); i++) {
                /* the index counter lines up with the flags and the expected template received */
                const TPM2B_PUBLIC *got = tpm2_get_primary_template((Tpm2SRKTemplateFlags)i);
                assert_se(memcmp(&templ[i], got, sizeof(*got)) == 0);
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
