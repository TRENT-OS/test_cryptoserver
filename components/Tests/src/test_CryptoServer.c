/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#include "SeosCryptoApi.h"

#include "TestMacros.h"

#include <camkes.h>
#include <string.h>

static SeosCryptoApi_Key_Data aesData =
{
    .type = SeosCryptoApi_Key_TYPE_AES,
    .attribs.exportable = true,
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
    SeosCryptoApi* api,
    size_t*        bytesWritten)
{
    char keyName[] = "storeOk";
    SeosCryptoApi_Key key;

    // Import key into RPC server and store it, then free it
    TEST_SUCCESS(SeosCryptoApi_Key_import(api, &key, &aesData));
    TEST_SUCCESS(CryptoServer_storeKey(keyName, key));
    TEST_SUCCESS(SeosCryptoApi_Key_free(&key));

    *bytesWritten += sizeof(aesData);

    TEST_OK();
}

static void
test_CryptoServer_storeKey_neg(
    SeosCryptoApi* api,
    size_t*        bytesWritten)
{
    SeosCryptoApi_Key key;

    TEST_SUCCESS(SeosCryptoApi_Key_import(api, &key, &aesData));

    // No name
    TEST_INVAL_PARAM(CryptoServer_storeKey("", key));

    // Name too long
    TEST_INVAL_PARAM(CryptoServer_storeKey("fat-likes-only-8-chars", key));

    TEST_SUCCESS(SeosCryptoApi_Key_free(&key));

    // Empty key object
    memset(&key, 0, sizeof(key));
    TEST_INVAL_HANDLE(CryptoServer_storeKey("okName", key));

    TEST_OK();
}

static void
test_CryptoServer_loadKey_pos(
    SeosCryptoApi* api,
    size_t*        bytesWritten)
{
    char keyName[] = "loadOk";
    SeosCryptoApi_Key key;
    SeosCryptoApi_Key_Data expData;
    SeosCryptoApi_Key_RemotePtr ptr;

    // Import key into RPC server and store it, then free it
    TEST_SUCCESS(SeosCryptoApi_Key_import(api, &key, &aesData));
    TEST_SUCCESS(CryptoServer_storeKey(keyName, key));
    TEST_SUCCESS(SeosCryptoApi_Key_free(&key));

    *bytesWritten += sizeof(aesData);

    // Load key from RPC server storage into memory, migrate into local API
    // instance and read it back
    TEST_SUCCESS(CryptoServer_loadKey(CLIENT_ID, keyName, &ptr));
    TEST_SUCCESS(SeosCryptoApi_Key_migrate(api, &key, ptr));
    TEST_SUCCESS(SeosCryptoApi_Key_export(&key, &expData));
    Debug_ASSERT(!memcmp(&expData, &aesData, sizeof(SeosCryptoApi_Key_Data)));
    TEST_SUCCESS(SeosCryptoApi_Key_free(&key));

    TEST_OK();
}

static void
test_CryptoServer_loadKey_neg(
    SeosCryptoApi* api,
    size_t*        bytesWritten)
{
    char keyName[] = "loadFail";
    SeosCryptoApi_Key key;
    SeosCryptoApi_Key_RemotePtr ptr;

    TEST_SUCCESS(SeosCryptoApi_Key_import(api, &key, &aesData));
    TEST_SUCCESS(CryptoServer_storeKey(keyName, key));
    TEST_SUCCESS(SeosCryptoApi_Key_free(&key));

    *bytesWritten += sizeof(aesData);

    // Load key from wrong client ID
    TEST_ACC_DENIED(CryptoServer_loadKey(0, keyName, &ptr));

    // Load key with non-existent name
    TEST_NOT_FOUND(CryptoServer_loadKey(CLIENT_ID, "foo", &ptr));

    TEST_OK();
}

static void
test_CryptoServer_useKey(
    SeosCryptoApi* api,
    size_t*        bytesWritten)
{
    char keyName[] = "useOk";
    SeosCryptoApi_Key key;
    SeosCryptoApi_Key_RemotePtr ptr;
    SeosCryptoApi_Cipher cipher;
    unsigned char buf[16] = PT;
    unsigned char ct[16] = CT;
    size_t ptLen = sizeof(buf);
    size_t ctLen = sizeof(ct);

    TEST_SUCCESS(SeosCryptoApi_Key_import(api, &key, &aesData));
    TEST_SUCCESS(CryptoServer_storeKey(keyName, key));
    TEST_SUCCESS(SeosCryptoApi_Key_free(&key));
    TEST_SUCCESS(CryptoServer_loadKey(CLIENT_ID, keyName, &ptr));
    TEST_SUCCESS(SeosCryptoApi_Key_migrate(api, &key, ptr));

    *bytesWritten += sizeof(aesData);

    // Use newly loaded and re-imported key for some crypto
    TEST_SUCCESS(SeosCryptoApi_Cipher_init(api, &cipher,
                                           SeosCryptoApi_Cipher_ALG_AES_ECB_ENC, &key, NULL, 0));
    TEST_SUCCESS(SeosCryptoApi_Cipher_process(&cipher, buf, ptLen, buf, &ctLen));
    Debug_ASSERT(ctLen == ptLen);
    Debug_ASSERT(!memcmp(buf, ct, ptLen));
    TEST_SUCCESS(SeosCryptoApi_Cipher_free(&cipher));

    TEST_SUCCESS(SeosCryptoApi_Key_free(&key));

    TEST_OK();
}

static void
test_CryptoServer_storageLimit(
    SeosCryptoApi* api,
    size_t         bytesWritten)
{
    bool keepWriting;
    char keyName[9];
    size_t i;
    SeosCryptoApi_Key key;

    i = 0;
    keepWriting = true;
    while (keepWriting)
    {
        // Fill up keystore until we reach the limit
        snprintf(keyName, sizeof(keyName), "fill%02d", i++);
        TEST_SUCCESS(SeosCryptoApi_Key_import(api, &key, &aesData));
        bytesWritten += sizeof(aesData);
        // Expect to receive an error
        if (bytesWritten > STORAGE_LIMIT)
        {
            TEST_INSUFF_SPACE(CryptoServer_storeKey(keyName, key));
            keepWriting = false;
        }
        else
        {
            TEST_SUCCESS(CryptoServer_storeKey(keyName, key));
        }
        TEST_SUCCESS(SeosCryptoApi_Key_free(&key));
    }

    TEST_OK();
}

int run()
{
    SeosCryptoApi api;
    size_t bytesWritten;
    SeosCryptoApi_Config cfgClient =
    {
        .mode = SeosCryptoApi_Mode_RPC_CLIENT,
        .mem.malloc = malloc,
        .mem.free = free,
        .impl.client.dataPort = SeosCryptoDataport
    };

    TEST_SUCCESS(SeosCryptoApi_init(&api, &cfgClient));

    // Keep track of amounts of byte we store, so we know this for the final test
    bytesWritten = 0;

    test_CryptoServer_storeKey_pos(&api, &bytesWritten);
    test_CryptoServer_storeKey_neg(&api, &bytesWritten);

    test_CryptoServer_loadKey_pos(&api, &bytesWritten);
    test_CryptoServer_loadKey_neg(&api, &bytesWritten);

    // No need to test failure of use key, as that should be covered by tests
    // of the Crypto API
    test_CryptoServer_useKey(&api, &bytesWritten);

    // Fill up the keystore until we reach a storage limit
    test_CryptoServer_storageLimit(&api, bytesWritten);

    TEST_SUCCESS(SeosCryptoApi_free(&api));

    return 0;
}