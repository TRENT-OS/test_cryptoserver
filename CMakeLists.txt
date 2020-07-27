#
# Test Crypto Server
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

DeclareCAmkESComponent_CryptoServer(
    CryptoServer
)

DeclareCAmkESComponent(
    test_CryptoServer_access_1
    SOURCES
        components/Tests/src/test_CryptoServer_access.c
    C_FLAGS
        -Wall
        -Werror
        -DCLIENT_ID=1
        -DNUM_INSTANCES=4
    LIBS
        os_core_api
        os_libs
        CryptoServer_client
)

DeclareCAmkESComponent(
    test_CryptoServer_access_2
    SOURCES
        components/Tests/src/test_CryptoServer_access.c
    C_FLAGS
        -Wall
        -Werror
        -DCLIENT_ID=2
        -DNUM_INSTANCES=4
    LIBS
        os_core_api
        os_libs
        CryptoServer_client
)

DeclareCAmkESComponent(
    test_CryptoServer_access_3
    SOURCES
        components/Tests/src/test_CryptoServer_access.c
    C_FLAGS
        -Wall
        -Werror
        -DCLIENT_ID=3
        -DNUM_INSTANCES=4
    LIBS
        os_core_api
        os_libs
        CryptoServer_client
)

DeclareCAmkESComponent(
    test_CryptoServer_access_4
    SOURCES
        components/Tests/src/test_CryptoServer_access.c
    C_FLAGS
        -Wall
        -Werror
        -DCLIENT_ID=4
        -DNUM_INSTANCES=4
    LIBS
        os_core_api
        os_libs
        CryptoServer_client
)

DeclareCAmkESComponent(
    test_CryptoServer
    SOURCES
        components/Tests/src/test_CryptoServer.c
    C_FLAGS
        -Wall
        -Werror
        -DCLIENT_ID=5
    LIBS
        os_core_api
        os_libs
        CryptoServer_client
)

DeclareCAmkESComponent_EntropySource(
    EntropySource
)

DeclareCAmkESComponent_RamDisk(
    RamDisk
    system_config
)

DeclareAndCreateCamkESSystem(main.camkes)
GenerateSimulateScript()
