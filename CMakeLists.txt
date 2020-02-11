cmake_minimum_required(VERSION 3.7.2)

seos_set_config_file(config.h)

seos_use_libs(
    SEOS_LIBS
    SEOS_LIBS_LOGGER
    SEOS_CRYPTO_WITH_RPC_CLIENT
    SEOS_CRYPTO_IMPL_MBEDTLS
)

project(test_cryptoserver C)

DeclareCAmkESComponent(test_CryptoServer_access_0
    INCLUDES
        components/CryptoServer/src
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
        components/CryptoServer/src
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
        components/CryptoServer/src
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
        components/CryptoServer/src
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
        components/CryptoServer/src
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
        seos_libs
)

# This creates a CAmkES component named CryptoServer
include(components/CryptoServer/CMakeLists.txt)

DeclareCAmkESRootserver(main.camkes)
GenerateCAmkESRootServer()
GenerateSimulateScript()