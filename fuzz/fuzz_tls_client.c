/* fuzz_tls_client.c
 * TLS client fuzzing harness for wolfSSL using libFuzzer
 */

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfio.h>

/* Fuzzing entry point */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    WOLFSSL_CTX *ctx = NULL;
    WOLFSSL *ssl = NULL;
    WOLFSSL_BIO *bio = NULL;
    int ret;

    /* Initialize wolfSSL */
    wolfSSL_Init();

    /* Create and initialize WOLFSSL_CTX */
    ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    if (!ctx)
    {
        goto cleanup;
    }

    /* Create WOLFSSL object */
    ssl = wolfSSL_new(ctx);
    if (!ssl)
    {
        goto cleanup;
    }

    /* Set up memory BIO */
    bio = wolfSSL_BIO_new_mem_buf((void *)data, (int)size);
    if (!bio)
    {
        goto cleanup;
    }
    wolfSSL_set_bio(ssl, bio, bio);

    /* Perform TLS handshake */
    ret = wolfSSL_connect(ssl);
    /* Ignore the result - we only care about crashes */

cleanup:
    /* Note: wolfSSL_free() will free the BIO */
    if (ssl)
    {
        wolfSSL_free(ssl);
    }
    if (ctx)
    {
        wolfSSL_CTX_free(ctx);
    }
    wolfSSL_Cleanup();
    return 0;
}
