/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#include "OS_Crypto.h"
#include "CryptoServer.h"

#include "LibMacros/Test.h"

#include <camkes.h>
#include <string.h>

static const if_CryptoServer_t cryptoServer =
    IF_CRYPTOSERVER_ASSIGN(cryptoServer_rpc);
static OS_Crypto_Config_t cfgClient =
{
    .mode = OS_Crypto_MODE_CLIENT,
    .rpc = IF_OS_CRYPTO_ASSIGN(
        cryptoServer_rpc,
        cryptoServer_port)
};
static OS_CryptoKey_Data_t aesData =
{
    .type = OS_CryptoKey_TYPE_AES,
    .attribs.keepLocal = true,
    .data.aes = {
        .len   = 24,
        .bytes = {
            0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
            0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
        },
    },
};
#define PT {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a}
#define CT {0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f, 0xf7, 0x12, 0xa2, 0x14, 0x57, 0x1f, 0xa5, 0xcc}

// This is the limit as it is defined in the main.camkes file for this client
#define STORAGE_LIMIT 12*1024

static void
test_CryptoServer_storeKey_pos(
    OS_Crypto_Handle_t hCrypto,
    size_t*            bytesWritten)
{
    char keyName[] = "storeOk";
    OS_CryptoKey_Handle_t hKey;

    TEST_START();

    // Import key into RPC server and store it, then free it
    TEST_SUCCESS(OS_CryptoKey_import(&hKey, hCrypto, &aesData));
    TEST_SUCCESS(CryptoServer_storeKey(&cryptoServer, hKey, keyName));
    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    *bytesWritten += sizeof(aesData);

    TEST_FINISH();
}

static void
test_CryptoServer_storeKey_neg(
    OS_Crypto_Handle_t hCrypto,
    size_t*            bytesWritten)
{
    OS_CryptoKey_Handle_t hKey;

    TEST_START();

    TEST_SUCCESS(OS_CryptoKey_import(&hKey, hCrypto, &aesData));

    // No name
    TEST_INVAL_PARAM(CryptoServer_storeKey(&cryptoServer, hKey, ""));

    // Name too long
    TEST_INVAL_PARAM(CryptoServer_storeKey(&cryptoServer, hKey, "fat-likes-only-8-chars"));

    // Invalid key object
    TEST_INVAL_HANDLE(CryptoServer_storeKey(&cryptoServer, NULL, "okName"));

    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    TEST_FINISH();
}

static void
test_CryptoServer_loadKey_pos(
    OS_Crypto_Handle_t hCrypto,
    size_t*            bytesWritten)
{
    char keyName[] = "loadOk";
    OS_CryptoKey_Handle_t hKey;

    TEST_START();

    // Import key into RPC server and store it, then free it
    TEST_SUCCESS(OS_CryptoKey_import(&hKey, hCrypto, &aesData));
    TEST_SUCCESS(CryptoServer_storeKey(&cryptoServer, hKey, keyName));
    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    *bytesWritten += sizeof(aesData);

    // Load key from RPC server storage back into memory
    TEST_SUCCESS(CryptoServer_loadKey(&cryptoServer, &hKey, hCrypto, CLIENT_ID, keyName));
    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    TEST_FINISH();
}

static void
test_CryptoServer_loadKey_neg(
    OS_Crypto_Handle_t hCrypto,
    size_t*            bytesWritten)
{
    char keyName[] = "loadFail";
    OS_CryptoKey_Handle_t hKey;

    TEST_START();

    TEST_SUCCESS(OS_CryptoKey_import(&hKey, hCrypto, &aesData));
    TEST_SUCCESS(CryptoServer_storeKey(&cryptoServer, hKey, keyName));
    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    *bytesWritten += sizeof(aesData);

    // Empty key handle
    TEST_INVAL_HANDLE(CryptoServer_loadKey(&cryptoServer, NULL, hCrypto, CLIENT_ID, keyName));

    // Empty crypto handle
    TEST_INVAL_HANDLE(CryptoServer_loadKey(&cryptoServer, &hKey, NULL, CLIENT_ID, keyName));

    // Load key from wrong client ID
    TEST_ACC_DENIED(CryptoServer_loadKey(&cryptoServer, &hKey, hCrypto, 101, keyName));

    // Load key with non-existent name
    TEST_NOT_FOUND(CryptoServer_loadKey(&cryptoServer, &hKey, hCrypto, CLIENT_ID, "foo"));

    TEST_FINISH();
}

static void
test_CryptoServer_useKey(
    OS_Crypto_Handle_t hCrypto,
    size_t*            bytesWritten)
{
    char keyName[] = "useOk";
    OS_CryptoKey_Handle_t hKey;
    OS_CryptoCipher_Handle_t hCipher;
    unsigned char buf[16] = PT;
    unsigned char ct[16] = CT;
    size_t ptLen = sizeof(buf);
    size_t ctLen = sizeof(ct);

    TEST_START();

    TEST_SUCCESS(OS_CryptoKey_import(&hKey, hCrypto, &aesData));
    TEST_SUCCESS(CryptoServer_storeKey(&cryptoServer, hKey, keyName));
    TEST_SUCCESS(OS_CryptoKey_free(hKey));
    TEST_SUCCESS(CryptoServer_loadKey(&cryptoServer, &hKey, hCrypto, CLIENT_ID, keyName));

    *bytesWritten += sizeof(aesData);

    // Use newly loaded and re-imported key for some crypto
    TEST_SUCCESS(OS_CryptoCipher_init(&hCipher, hCrypto, hKey,
                                      OS_CryptoCipher_ALG_AES_ECB_ENC,
                                      NULL, 0));
    TEST_SUCCESS(OS_CryptoCipher_process(hCipher, buf, ptLen, buf, &ctLen));
    Debug_ASSERT(ctLen == ptLen);
    Debug_ASSERT(!memcmp(buf, ct, ptLen));
    TEST_SUCCESS(OS_CryptoCipher_free(hCipher));

    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    TEST_FINISH();
}

static void
test_CryptoServer_storageLimit(
    OS_Crypto_Handle_t hCrypto,
    size_t             bytesWritten)
{
    bool keepWriting;
    char keyName[9];
    size_t i;
    OS_CryptoKey_Handle_t hKey;

    TEST_START();

    i = 0;
    keepWriting = true;
    while (keepWriting)
    {
        // Fill up keystore until we reach the limit
        snprintf(keyName, sizeof(keyName), "fill%02zu", i++);
        TEST_SUCCESS(OS_CryptoKey_import(&hKey, hCrypto, &aesData));
        bytesWritten += sizeof(aesData);
        // Expect to receive an error
        if (bytesWritten > STORAGE_LIMIT)
        {
            TEST_INSUFF_SPACE(CryptoServer_storeKey(&cryptoServer, hKey, keyName));
            keepWriting = false;
        }
        else
        {
            TEST_SUCCESS(CryptoServer_storeKey(&cryptoServer, hKey, keyName));
        }
        TEST_SUCCESS(OS_CryptoKey_free(hKey));
    }

    TEST_FINISH();
}

int run()
{
    OS_Error_t err;
    OS_Crypto_Handle_t hCrypto;
    size_t bytesWritten;

    if ((err = OS_Crypto_init(&hCrypto, &cfgClient)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_Crypto_init() failed with %i", err);
        return -1;
    }

    // Keep track of amounts of byte we store, so we know this for the final test
    bytesWritten = 0;

    test_CryptoServer_storeKey_pos(hCrypto, &bytesWritten);
    test_CryptoServer_storeKey_neg(hCrypto, &bytesWritten);

    test_CryptoServer_loadKey_pos(hCrypto, &bytesWritten);
    test_CryptoServer_loadKey_neg(hCrypto, &bytesWritten);

    // No need to test failure of use key, as that should be covered by tests
    // of the Crypto API
    test_CryptoServer_useKey(hCrypto, &bytesWritten);

    // Fill up the keystore until we reach a storage limit
    test_CryptoServer_storageLimit(hCrypto, bytesWritten);

    if ((err = OS_Crypto_free(hCrypto)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_Crypto_free() failed with %i", err);
        return -1;
    }

    Debug_LOG_INFO("All tests successfully completed.");

    return 0;
}
