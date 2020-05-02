cmake_minimum_required(VERSION 3.7.2)

seos_set_config_file(system_config.h)

seos_use_libs(
    SEOS_LIBS
    SEOS_CHANMUX
    SEOS_CRYPTO_WITH_RPC_CLIENT
)

project(system_config C)
add_library(${PROJECT_NAME} INTERFACE)
target_include_directories(${PROJECT_NAME} INTERFACE ${CMAKE_CURRENT_LIST_DIR})


project(test_cryptoserver C)

# Set path to src, inc, camkes folders of CryptoServer
SET(SEOS_COMPONENTS_CRYPTOSERVER_DIR "${SEOS_COMPONENTS_DIR}/CryptoServer")

# Include CryptoServer CMakeList
include("${SEOS_COMPONENTS_CRYPTOSERVER_DIR}/CMakeLists.txt")

DeclareCAmkESComponent(test_CryptoServer_access_0
    INCLUDES
        ${SEOS_COMPONENTS_CRYPTOSERVER_DIR}/inc
    SOURCES
        components/Tests/src/test_CryptoServer_access.c
    C_FLAGS
        -Wall -Werror
        -DCLIENT_ID=0
        -DNUM_INSTANCES=4
    LIBS
        seos_core_api
        seos_libs
        seos_crypto_with_rpc_client
)

DeclareCAmkESComponent(test_CryptoServer_access_1
    INCLUDES
        ${SEOS_COMPONENTS_CRYPTOSERVER_DIR}/inc
    SOURCES
        components/Tests/src/test_CryptoServer_access.c
    C_FLAGS
        -Wall -Werror
        -DCLIENT_ID=1
        -DNUM_INSTANCES=4
    LIBS
        seos_core_api
        seos_libs
        seos_crypto_with_rpc_client
)

DeclareCAmkESComponent(test_CryptoServer_access_2
    INCLUDES
        ${SEOS_COMPONENTS_CRYPTOSERVER_DIR}/inc
    SOURCES
        components/Tests/src/test_CryptoServer_access.c
    C_FLAGS
        -Wall -Werror
        -DCLIENT_ID=2
        -DNUM_INSTANCES=4
    LIBS
        seos_core_api
        seos_libs
        seos_crypto_with_rpc_client
)

DeclareCAmkESComponent(test_CryptoServer_access_3
    INCLUDES
        ${SEOS_COMPONENTS_CRYPTOSERVER_DIR}/inc
    SOURCES
        components/Tests/src/test_CryptoServer_access.c
    C_FLAGS
        -Wall -Werror
        -DCLIENT_ID=3
        -DNUM_INSTANCES=4
    LIBS
        seos_core_api
        seos_libs
        seos_crypto_with_rpc_client
)

DeclareCAmkESComponent(test_CryptoServer
    INCLUDES
        ${SEOS_COMPONENTS_CRYPTOSERVER_DIR}/inc
    SOURCES
        components/Tests/src/test_CryptoServer.c
    C_FLAGS
        -Wall -Werror
        -DCLIENT_ID=4
    LIBS
        seos_core_api
        seos_libs
        seos_crypto_with_rpc_client
)

DeclareCAmkESComponent(UartDrv
    SOURCES
        components/Uart/src/UartDrv.c
        components/Uart/src/qemu_uart.c
    C_FLAGS
        -Wall -Werror
)

DeclareCAmkESComponent(ChanMux
    SOURCES
        components/ChanMux/src/ChanMux_Instance.c
    C_FLAGS
        -Wall -Werror
    LIBS
        seos_core_api
        chanmux_server
)

DeclareCAmkESRootserver(main.camkes)
GenerateCAmkESRootServer()
GenerateSimulateScript()
