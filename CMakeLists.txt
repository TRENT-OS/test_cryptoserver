cmake_minimum_required(VERSION 3.7.2)

seos_set_config_file(config.h)

seos_use_libs(
    SEOS_LIBS
    SEOS_CHANMUX
    SEOS_CRYPTO_WITH_RPC_CLIENT
    SEOS_CRYPTO_IMPL_MBEDTLS
)


# adds the CryptoServer component. The current implementation uses ChanMUX
# directly and thus expectes to find the file ChanMuxInf.camkes in the CAmkES
# include paths. Actually, the CryptoServer shuld be agnostic of ChanMUX and
# just reqiue a partition manager interface that gives it access to a partition
# that is used for its internal Keystore then.
SET(SEOS_COMPONENTS_CRYPTOSERVER_DIR "${SEOS_COMPONENTS_DIR}/cryptoserver")
CAmkESAddImportPath(${SEOS_COMPONENTS_CRYPTOSERVER_DIR})
CAmkESAddImportPath("components/ChanMux")
include(${SEOS_COMPONENTS_CRYPTOSERVER_DIR}/CMakeLists.txt)


DeclareCAmkESComponent(test_CryptoServer_access_0
    INCLUDES
        ${SEOS_COMPONENTS_CRYPTOSERVER_DIR}/src
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
        ${SEOS_COMPONENTS_CRYPTOSERVER_DIR}/src
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
        ${SEOS_COMPONENTS_CRYPTOSERVER_DIR}/src
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
        ${SEOS_COMPONENTS_CRYPTOSERVER_DIR}/src
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
        ${SEOS_COMPONENTS_CRYPTOSERVER_DIR}/src
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
        chanmux_server
)

DeclareCAmkESRootserver(main.camkes)
GenerateCAmkESRootServer()
GenerateSimulateScript()
