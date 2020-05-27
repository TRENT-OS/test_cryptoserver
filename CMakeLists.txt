cmake_minimum_required(VERSION 3.7.2)

seos_set_config_file(system_config.h)

seos_use_libs(
    OS_LIBS
    OS_CHANMUX
    OS_CRYPTO_WITH_RPC_CLIENT
)

project(system_config C)
add_library(${PROJECT_NAME} INTERFACE)
target_include_directories(${PROJECT_NAME} INTERFACE ${CMAKE_CURRENT_LIST_DIR})


project(test_cryptoserver C)

# Set path to src, inc, camkes folders of CryptoServer
SET(OS_COMPONENTS_CRYPTOSERVER_DIR "${OS_COMPONENTS_DIR}/CryptoServer")

# Include CryptoServer CMakeList
include("${OS_COMPONENTS_CRYPTOSERVER_DIR}/CMakeLists.txt")

DeclareCAmkESComponent(test_CryptoServer_access_0
    INCLUDES
        ${OS_COMPONENTS_CRYPTOSERVER_DIR}/inc
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
        ${OS_COMPONENTS_CRYPTOSERVER_DIR}/inc
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
        ${OS_COMPONENTS_CRYPTOSERVER_DIR}/inc
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
        ${OS_COMPONENTS_CRYPTOSERVER_DIR}/inc
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
        ${OS_COMPONENTS_CRYPTOSERVER_DIR}/inc
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

DeclareCAmkESComponent_UART(
    UART
)

DeclareCAmkESComponent_ChanMux(
    ChanMux
    components/ChanMux/ChanMux_config.c
    system_config
)

DeclareAndCreateCamkESSystem(main.camkes)
GenerateSimulateScript()
