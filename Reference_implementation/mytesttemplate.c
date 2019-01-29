#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../random/random.h"
#include "../../mytest/cpucycles.h"
#include "../../mytest/speed.h"
#include "../api.h"
#include "../poly.h"
#include "../pack.h"
#include "../sample.h"
#include "../params.h"
#include "../sha3/fips202.h"

#if (OS_TARGET == OS_LINUX)
  #include <sys/types.h>
  #include <sys/stat.h>
  #include <fcntl.h>
  #include <unistd.h>
#endif

#define MLEN 450
#define NRUNS 5000
#define NTESTS 50

#ifndef SCHEME_NAME
    #error "SCHEMA_NAME should be setup"
#endif

#define MYCRYPTO_SK_LENGTH CRYPTO_SECRETKEYBYTES
#define MYCRYPTO_PK_LENGTH CRYPTO_PUBLICKEYBYTES
#define MYCRYPTO_MSG_LENGTH MLEN
#define MYCRYPTO_CIPHER_MSG_LENGTH (MLEN + CRYPTO_BYTES)

#define TEST_LOOPS NTESTS

#define TEST_JSON_PLAINTEXT "{\n" \
"        body: {\n" \
"                \"from\": \"pub_key_generated_by_library_in_testing_1\",\n" \
"                \"to\": \"pub_key_generated_by_library_in_testing_2\",\n" \
"                \"amount\": 3,1415,\n" \
"                \"itemHash\": \"bdad5ccb7a52387f5693eaef54aeee6de73a6ada7acda6d93a665abbdf954094\"\n" \
"                \"seed\": \"2953135335240383704\"\n" \
"        },\n" \
"        \"fee\": 0,7182,\n" \
"        \"network_id\": 7,\n" \
"        \"protocol_version\": 0,\n" \
"        \"service_id\": 5,\n" \
"}"

unsigned long long timing_overhead;

int mycryptotest_easy_sign()
{
    unsigned char m[MYCRYPTO_MSG_LENGTH] = {0};
    unsigned char m_[MYCRYPTO_MSG_LENGTH] = {0};
    unsigned char pk[MYCRYPTO_PK_LENGTH] = {0};
    unsigned char ct[MYCRYPTO_CIPHER_MSG_LENGTH] = {0};
    unsigned char sk[MYCRYPTO_SK_LENGTH] = {0};
    unsigned long long ctLen = 0, mLen = 0;
    unsigned int i = 0;
    int valid = 0;
    bool status = true;

    printf("\n\nTESTING EASY SIGNATURE %s\n", SCHEME_NAME);
    printf("--------------------------------------------------------------------------------------------------------\n\n");

    snprintf((char*)m, MYCRYPTO_MSG_LENGTH, "123321");

    for (i = 0; i < TEST_LOOPS; i++) {
        crypto_sign_keypair(pk, sk);
        crypto_sign(ct, &ctLen, m, MYCRYPTO_MSG_LENGTH, sk);
        valid = crypto_sign_open(m_, &mLen, ct, ctLen, pk);

        if (valid != 0) {
            printf("Signature verification FAILED. \n");
            status = false;
            break;
        } else if (mLen != MLEN) {
            printf("crypto_sign_open returned BAD message length. \n");
            status = false;
            break;
        }

        if (memcmp(m, m_, MYCRYPTO_MSG_LENGTH)) {
            printf("ERROR keys\n");
            status = false;
            break;
        }
    }

    if (status != true) {
        printf("  Signature easy tests ... FAILED\n");
        return status;
    }

    printf("  Signature easy tests .................................................... PASSED\n");
    return status;
}

int mycryptotest_sign()
{
    unsigned int i = 0;
    unsigned char sk[MYCRYPTO_SK_LENGTH] = {0};
    unsigned char pk[MYCRYPTO_PK_LENGTH] = {0};
    bool status = true;

    unsigned int encTimes = (strlen(TEST_JSON_PLAINTEXT) + 1) / MYCRYPTO_MSG_LENGTH + 1;
    unsigned int myMsgLen = encTimes * MYCRYPTO_MSG_LENGTH;
    unsigned int myCtLen = encTimes * MYCRYPTO_CIPHER_MSG_LENGTH;
    unsigned long long ctLen = 0, mLen = 0;
    unsigned int encdecIdx = 0;

    unsigned char* myMsg = NULL;
    unsigned char* myMsg_ = NULL;
    unsigned char* myCt = NULL;
    unsigned long long* myCtLens = NULL;
    int valid = 0;

    if (NULL == (myMsg = (unsigned char*)calloc(myMsgLen, sizeof(unsigned char))) ||
        NULL == (myMsg_ = (unsigned char*)calloc(myMsgLen, sizeof(unsigned char))) ||
        NULL == (myCt = (unsigned char*)calloc(myCtLen, sizeof(unsigned char))) ||
        NULL == (myCtLens = (unsigned long long*)calloc(encTimes, sizeof(unsigned long long)))) {
        printf("Cannot get the memory\n");
        return false;
    }

    printf("\n\nTESTING SIGN %s\n", SCHEME_NAME);
    printf("--------------------------------------------------------------------------------------------------------\n\n");

    for (i = 0; i < TEST_LOOPS; i++)
    {
        memset(myMsg, 0, myMsgLen);
        memset(myMsg_, 0, myMsgLen);
        memset(myCt, 0, myCtLen);
        memset(myCtLens, 0, encTimes);

        snprintf((char*)myMsg, myMsgLen, TEST_JSON_PLAINTEXT);

#ifdef JAYPAN_DEBUG
        printf("start test %d\n", i);
#endif
        crypto_sign_keypair(pk, sk);
#ifdef JAYPAN_DEBUG
        printf("start encrypt\n");
#endif
        for (encdecIdx = 0; encdecIdx < encTimes; encdecIdx++) {
            crypto_sign(myCt + encdecIdx * MYCRYPTO_CIPHER_MSG_LENGTH,
                        &myCtLens[encdecIdx],
                        myMsg + encdecIdx * MYCRYPTO_MSG_LENGTH,
                        MYCRYPTO_MSG_LENGTH,
                        sk);
        }
#ifdef JAYPAN_DEBUG
        printf("after encrypt %s\n", (char*)myMsg);
#endif
        for (encdecIdx = 0; encdecIdx < encTimes; encdecIdx++) {
            valid = crypto_sign_open(myMsg_ + encdecIdx * MYCRYPTO_MSG_LENGTH,
                                     &mLen,
                                     myCt + encdecIdx * MYCRYPTO_CIPHER_MSG_LENGTH,
                                     myCtLens[encdecIdx],
                                     pk);
            if (valid != 0) {
                printf("Signature verification FAILED. \n");
                status = false;
                break;
            } else if (mLen != MLEN) {
                printf("crypto_sign_open returned BAD message length. \n");
                status = false;
                break;
            }
        }

#ifdef JAYPAN_DEBUG
        printf("after decrypt %s\n", (char*)myMsg_);
#endif

        if (memcmp(myMsg, myMsg_, myMsgLen) != 0) {
            status = false;
            break;
        }
    }

    if (myMsg) {
        free(myMsg);
    }
    if (myMsg_) {
        free(myMsg_);
    }
    if (myCt) {
        free(myCt);
    }
    if (myCtLens) {
        free(myCtLens);
    }

    if (status != true) {
        printf("  SIGN tests ... FAILED\n");
        return status;
    }

    printf("  SIGN tests .................................................... PASSED\n");
    return status;
}

int mycryptorun_sign()
{
    unsigned int i = 0;
    unsigned char sk[MYCRYPTO_SK_LENGTH] = {0};
    unsigned char pk[MYCRYPTO_PK_LENGTH] = {0};
    bool status = true;

    unsigned int encTimes = (strlen(TEST_JSON_PLAINTEXT) + 1) / MYCRYPTO_MSG_LENGTH + 1;
    unsigned int myMsgLen = encTimes * MYCRYPTO_MSG_LENGTH;
    unsigned int myCtLen = encTimes * MYCRYPTO_CIPHER_MSG_LENGTH;
    unsigned long long ctLen = 0, mLen = 0, allCtLen = 0;
    unsigned int encdecIdx = 0;

    unsigned char* myMsg = NULL;
    unsigned char* myMsg_ = NULL;
    unsigned char* myCt = NULL;
    unsigned long long* myCtLens = NULL;
    int valid = 0;

    unsigned long long tkeygen[TEST_LOOPS], tsign[TEST_LOOPS], tverify[TEST_LOOPS];
    timing_overhead = cpucycles_overhead();

    if (NULL == (myMsg = (unsigned char*)calloc(myMsgLen, sizeof(unsigned char))) ||
        NULL == (myMsg_ = (unsigned char*)calloc(myMsgLen, sizeof(unsigned char))) ||
        NULL == (myCt = (unsigned char*)calloc(myCtLen, sizeof(unsigned char))) ||
        NULL == (myCtLens = (unsigned long long*)calloc(encTimes, sizeof(unsigned long long)))) {
        printf("Cannot get the memory\n");
        return false;
    }

    printf("\n\nTESTING SIGN %s\n", SCHEME_NAME);
    printf("--------------------------------------------------------------------------------------------------------\n\n");

    for (i = 0; i < TEST_LOOPS; i++)
    {
        memset(myMsg, 0, myMsgLen);
        memset(myMsg_, 0, myMsgLen);
        memset(myCt, 0, myCtLen);
        memset(myCtLens, 0, encTimes);

        snprintf((char*)myMsg, myMsgLen, TEST_JSON_PLAINTEXT);

        printf("start genkey\n");
        tkeygen[i] = cpucycles_start();
        crypto_sign_keypair(pk, sk);
        tkeygen[i] = cpucycles_stop() - tkeygen[i] - timing_overhead;

        printf("start encrypt\n");
        tsign[i] = cpucycles_start();
        for (encdecIdx = 0; encdecIdx < encTimes; encdecIdx++) {
            crypto_sign(myCt + encdecIdx * MYCRYPTO_CIPHER_MSG_LENGTH,
                        &myCtLens[encdecIdx],
                        myMsg + encdecIdx * MYCRYPTO_MSG_LENGTH,
                        MYCRYPTO_MSG_LENGTH,
                        sk);
        }
        tsign[i] = cpucycles_stop() - tsign[i] - timing_overhead;

        printf("start decrypt\n");
        tverify[i] = cpucycles_start();
        for (encdecIdx = 0; encdecIdx < encTimes; encdecIdx++) {
            crypto_sign_open(myMsg_ + encdecIdx * MYCRYPTO_MSG_LENGTH,
                             &mLen,
                             myCt + encdecIdx * MYCRYPTO_CIPHER_MSG_LENGTH,
                             myCtLens[encdecIdx],
                             pk);
        }
        tverify[i] = cpucycles_stop() - tverify[i] - timing_overhead;

#ifdef JAYPAN_DEBUG
        printf("after decrypt %s\n", (char*)myMsg_);
#endif

        if (memcmp(myMsg, myMsg_, myMsgLen) != 0) {
            status = false;
            break;
        }
        for (encdecIdx = 0; encdecIdx < encTimes; encdecIdx++) {
            allCtLen += myCtLens[encdecIdx];
        }
    }

    if (myMsg) {
        free(myMsg);
    }
    if (myMsg_) {
        free(myMsg_);
    }
    if (myCt) {
        free(myCt);
    }
    if (myCtLens) {
        free(myCtLens);
    }

    if (status != true) {
        printf("  SIGN tests ... FAILED\n");
        return status;
    }

    printf("  SIGN tests .................................................... PASSED\n");
    print_results("keygen:", tkeygen, TEST_LOOPS);
    print_results("sign: ", tsign, TEST_LOOPS);
    print_results("verify: ", tverify, TEST_LOOPS);
    printf("average length: %llu\n", allCtLen / TEST_LOOPS);
    printf("average length: %u\n", myCtLen);
	printf("my json plaintext %lu\n", strlen(TEST_JSON_PLAINTEXT) + 1);
    return status;
}

int main(void)
{
    int status = -1;
    status = mycryptotest_easy_sign();
    if (status != true) {
        printf("\n\n     Error detected: SIGN_ERROR \n\n");
        return -1;
    }

    status = mycryptotest_sign();
    if (status != true) {
        printf("\n\n     Error detected: SIGN_ERROR \n\n");
        return -1;
    }

    status = mycryptorun_sign();
    if (status != true) {
        printf("\n\n     Error detected: KEM_ERROR \n\n");
        return -1;
    }

    return 0;
}
