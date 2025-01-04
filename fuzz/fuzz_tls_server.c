/* fuzz_tls_server.c
 * TLS server fuzzing harness for wolfSSL using libFuzzer
 */

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfio.h> /* BIO関連の定義のために追加 */

#ifdef OPENSSL_EXTRA /* BIOサポートにはOPENSSL_EXTRAが必要 */

/* Fuzzing entry point */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    WOLFSSL_BIO* bio = NULL;
    int ret;

    /* Initialize wolfSSL */
    wolfSSL_Init();

    /* Create and initialize WOLFSSL_CTX */
    ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method());
    if (!ctx) {
        goto cleanup;
    }

    /* Load test certificates */
    ret = wolfSSL_CTX_use_certificate_file(ctx, "certs/server-cert.pem",
                                         WOLFSSL_FILETYPE_PEM);
    if (ret != WOLFSSL_SUCCESS) {
        goto cleanup;
    }

    ret = wolfSSL_CTX_use_PrivateKey_file(ctx, "certs/server-key.pem",
                                         WOLFSSL_FILETYPE_PEM);
    if (ret != WOLFSSL_SUCCESS) {
        goto cleanup;
    }

    /* Create WOLFSSL object */
    ssl = wolfSSL_new(ctx);
    if (!ssl) {
        goto cleanup;
    }

    /* Set up memory BIO */
    bio = wolfSSL_BIO_new_mem_buf((void*)data, (int)size);
    if (!bio) {
        goto cleanup;
    }
    wolfSSL_set_bio(ssl, bio, bio);

    /* Perform TLS handshake */
    ret = wolfSSL_accept(ssl);
    /* Ignore the result - we only care about crashes */

cleanup:
    /* Note: wolfSSL_free() will free the BIO */
    if (ssl) {
        wolfSSL_free(ssl);
    }
    if (ctx) {
        wolfSSL_CTX_free(ctx);
    }
    wolfSSL_Cleanup();
    return 0;
}

#else
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    return 0;
}
#endif /* OPENSSL_EXTRA */
