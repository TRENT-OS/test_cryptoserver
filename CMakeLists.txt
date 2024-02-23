#
# Test Crypto server
#
# Copyright (C) 2020-2024, HENSOLDT Cyber GmbH
# 
# SPDX-License-Identifier: GPL-2.0-or-later
#
# For commercial licensing, contact: info.cyber@hensoldt.net
#

cmake_minimum_required(VERSION 3.7.2)

#-------------------------------------------------------------------------------
# use the SDK
find_package("os-sdk" REQUIRED)
os_sdk_set_defaults()
os_sdk_setup(CONFIG_FILE "system_config.h" CONFIG_PROJECT "system_config")


#-------------------------------------------------------------------------------
project(test_cryptoserver C)

CryptoServer_DeclareCAmkESComponent(
    CryptoServer
)

DeclareCAmkESComponent(
    test_CryptoServer_access_1
    SOURCES
        components/Tests/src/test_CryptoServer_access.c
    C_FLAGS
        -Wall
        -Werror
        -DCLIENT_ID=101
        -DNUM_INSTANCES=4
    LIBS
        os_core_api
        lib_debug
        lib_macros
        os_crypto
        CryptoServer_client
)

DeclareCAmkESComponent(
    test_CryptoServer_access_2
    SOURCES
        components/Tests/src/test_CryptoServer_access.c
    C_FLAGS
        -Wall
        -Werror
        -DCLIENT_ID=102
        -DNUM_INSTANCES=4
    LIBS
        os_core_api
        lib_debug
        lib_macros
        os_crypto
        CryptoServer_client
)

DeclareCAmkESComponent(
    test_CryptoServer_access_3
    SOURCES
        components/Tests/src/test_CryptoServer_access.c
    C_FLAGS
        -Wall
        -Werror
        -DCLIENT_ID=103
        -DNUM_INSTANCES=4
    LIBS
        os_core_api
        lib_debug
        lib_macros
        os_crypto
        CryptoServer_client
)

DeclareCAmkESComponent(
    test_CryptoServer_access_4
    SOURCES
        components/Tests/src/test_CryptoServer_access.c
    C_FLAGS
        -Wall
        -Werror
        -DCLIENT_ID=104
        -DNUM_INSTANCES=4
    LIBS
        os_core_api
        lib_debug
        lib_macros
        os_crypto
        CryptoServer_client
)

DeclareCAmkESComponent(
    test_CryptoServer
    SOURCES
        components/Tests/src/test_CryptoServer.c
    C_FLAGS
        -Wall
        -Werror
        -DCLIENT_ID=105
    LIBS
        os_core_api
        lib_compiler
        lib_debug
        lib_macros
        os_crypto
        CryptoServer_client
)

EntropySource_DeclareCAmkESComponent(
    EntropySource
)

RamDisk_DeclareCAmkESComponent(
    RamDisk
)

os_sdk_create_CAmkES_system("main.camkes")

