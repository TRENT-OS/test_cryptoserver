/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#include "OS_Crypto.h"
#include "CryptoServer.h"

#include "TestMacros.h"

#include <camkes.h>
#include <string.h>
#include <sel4/sel4.h> // needed for seL4_yield()

static OS_CryptoKey_Data_t rsaPrvData =
{
    .type = OS_CryptoKey_TYPE_RSA_PRV,
    .attribs.exportable = false,
    .data.rsa.prv = {
        .dBytes = {
            0x35, 0xe7, 0x4c, 0x80, 0x45, 0x9c, 0x4e, 0x69, 0x83, 0x2c, 0x62, 0xac, 0x26, 0x2d, 0x58, 0xac,
            0x0f, 0xd1, 0x53, 0x45, 0xd2, 0x0a, 0x94, 0x43, 0x0f, 0x29, 0x00, 0x0b, 0x50, 0x63, 0x05, 0x29,
            0x34, 0xa3, 0xaa, 0x1a, 0x1a, 0x4c, 0xea, 0x41, 0x27, 0xe4, 0x83, 0x4b, 0xc8, 0xd6, 0x48, 0x20,
            0xf5, 0xd0, 0x5c, 0x9f, 0x57, 0xad, 0xaf, 0xce, 0xc9, 0x75, 0xcf, 0x6d, 0xe9, 0x6e, 0xbf, 0xcc,
            0xd5, 0xb1, 0xc7, 0x90, 0x5a, 0xcb, 0xd5, 0xe8, 0xa0, 0x5b, 0x39, 0xaa, 0x9a, 0xa6, 0x3c, 0xe5,
            0xf5, 0xca, 0xe0, 0x49, 0x63, 0x90, 0xb5, 0x3b, 0xb0, 0x9c, 0x36, 0xda, 0x66, 0x59, 0x14, 0x97,
            0x76, 0xcb, 0x28, 0x0e, 0x0f, 0xa8, 0x3c, 0xa7, 0x62, 0x81, 0xdb, 0x1a, 0xcb, 0x8d, 0xd1, 0xb7,
            0xc7, 0xec, 0x25, 0xbb, 0x4b, 0xdb, 0x80, 0x07, 0xf7, 0x3c, 0xa5, 0xf1, 0x61, 0x1a, 0x74, 0x99
        },
        .dLen = 128,
        .eBytes = {
            0x01, 0x00, 0x01
        },
        .eLen = 3,
        .pBytes = {
            0xdd, 0x35, 0x19, 0x94, 0xcb, 0xe0, 0x45, 0x43, 0xb8, 0x1f, 0x32, 0xfb, 0xfe, 0xd1, 0x51, 0x2a,
            0xc0, 0xa2, 0xdb, 0x93, 0x80, 0xde, 0xc0, 0x54, 0x90, 0xd5, 0xe2, 0xbd, 0xd3, 0x17, 0xfb, 0x9a,
            0xa5, 0xeb, 0x11, 0x33, 0x49, 0x73, 0xc8, 0xa7, 0x12, 0x69, 0x80, 0x58, 0xb4, 0x01, 0x58, 0xab,
            0x87, 0x38, 0x21, 0x89, 0x0b, 0xc5, 0x0a, 0x06, 0x10, 0x54, 0x62, 0x20, 0xfa, 0xbd, 0x88, 0xa3
        },
        .pLen = 64,
        .qBytes = {
            0xa9, 0x1e, 0xc2, 0x6b, 0x18, 0x0b, 0x23, 0x2a, 0x51, 0x62, 0x12, 0x05, 0x51, 0xe8, 0xe7, 0x66,
            0xcf, 0x33, 0xd1, 0xdb, 0xb3, 0x50, 0x27, 0xde, 0x1c, 0xfe, 0xf1, 0xb8, 0x1c, 0xc8, 0x29, 0x4b,
            0x0d, 0xa5, 0x75, 0x2b, 0x2c, 0x83, 0x19, 0xf8, 0x74, 0xe8, 0xea, 0x37, 0x55, 0x48, 0xe5, 0xc6,
            0xbc, 0x78, 0x74, 0x9d, 0xbb, 0x17, 0x17, 0x76, 0x63, 0xb8, 0x29, 0xe1, 0x8c, 0xe3, 0xe1, 0xeb
        },
        .qLen = 64,
    }
};

static void
test_CryptoServer_access(
    OS_Crypto_Handle_t hCrypto)
{
    OS_CryptoKey_Handle_t hKey;
    char name[16];
    seL4_Word id, my_id = CLIENT_ID;

    TEST_START(my_id);

    snprintf(name, sizeof(name), "KEY_%lu", (long unsigned int) my_id);

    // Import key into RPC server and store it, then free it
    TEST_SUCCESS(OS_CryptoKey_import(&hKey, hCrypto, &rsaPrvData));
    TEST_SUCCESS(CryptoServer_storeKey(hKey, name));
    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    // Wait for all instances to finish importing their keys (see above).
    // TODO: Replace with a signal-based mechanism so we don't waste too much
    //       time here.
    for (size_t t = 0; t < 250; t++)
    {
        seL4_Yield();
    }

    // Check the configured access matrix, see main.cakes. We have configured
    // all AccessTest instances such that they can access their own keys and the
    // keys of all instances with a greater ID, i.e., ID=0 has most access.
    for (id = 0; id < NUM_INSTANCES; id++)
    {
        snprintf(name, sizeof(name), "KEY_%lu", (long unsigned int) id);
        if (id >= my_id)
        {
            // We don't really need the key so get rid of it -- this is just to
            // test that the matrix is correctly defined.
            TEST_SUCCESS(CryptoServer_loadKey(&hKey, hCrypto, id, name));
            TEST_SUCCESS(OS_CryptoKey_free(hKey));
        }
        else
        {
            TEST_ACC_DENIED(CryptoServer_loadKey(&hKey, hCrypto, id, name));
        }
    }

    TEST_FINISH();
}

int run()
{
    OS_Crypto_Handle_t hCrypto;
    OS_Crypto_Config_t cfgClient =
    {
        .mode = OS_Crypto_MODE_CLIENT_ONLY,
        .rpc.client.dataPort = CryptoLibDataport
    };

    TEST_SUCCESS(OS_Crypto_init(&hCrypto, &cfgClient));

    // This test checks that the CryptoServer respects access rights configured
    // for multiple instances of clients (based on this code) trying to access each
    // other's keystores.
    test_CryptoServer_access(hCrypto);

    TEST_SUCCESS(OS_Crypto_free(hCrypto));

    return 0;
}
