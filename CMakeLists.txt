#
# Test Crypto server
#
# Copyright (C) 2020, Hensoldt Cyber GmbH
#

cmake_minimum_required(VERSION 3.7.2)

os_set_config_file(system_config.h)


#-------------------------------------------------------------------------------
project(system_config C)
add_library(${PROJECT_NAME} INTERFACE)
target_include_directories(${PROJECT_NAME} INTERFACE ${CMAKE_CURRENT_LIST_DIR})


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
        lib_debug
        os_crypto
        CryptoServer_client
)

EntropySource_DeclareCAmkESComponent(
    EntropySource
)

RamDisk_DeclareCAmkESComponent(
    RamDisk
    system_config
)

DeclareAndCreateCamkESSystem(main.camkes)
GenerateSimulateScript()
