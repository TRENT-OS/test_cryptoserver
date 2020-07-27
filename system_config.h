/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * OS libraries configurations
 *
 */

#pragma once


//-----------------------------------------------------------------------------
// Debug
//-----------------------------------------------------------------------------

#if !defined(NDEBUG)
#   define Debug_Config_STANDARD_ASSERT
#   define Debug_Config_ASSERT_SELF_PTR
#else
#   define Debug_Config_DISABLE_ASSERT
#   define Debug_Config_NO_ASSERT_SELF_PTR
#endif

#define Debug_Config_LOG_LEVEL              Debug_LOG_LEVEL_DEBUG
#define Debug_Config_INCLUDE_LEVEL_IN_MSG
#define Debug_Config_LOG_WITH_FILE_LINE

//-----------------------------------------------------------------------------
// RamDisk
//-----------------------------------------------------------------------------

#define RAMDISK_SIZE_BYTES  (1 * 1024 * 1024)


//-----------------------------------------------------------------------------
// Memory
//-----------------------------------------------------------------------------

#define Memory_Config_USE_STDLIB_ALLOC


//-----------------------------------------------------------------------------
// ChanMUX clients
//-----------------------------------------------------------------------------

#define CHANMUX_ID_CRYPTOSERVER     101


//-----------------------------------------------------------------------------
// Logs
//-----------------------------------------------------------------------------

#define Logs_Config_LOG_STRING_SIZE         128
#define Logs_Config_INCLUDE_LEVEL_IN_MSG    1
#define Logs_Config_SYSLOG_LEVEL            Log_TRACE


//-----------------------------------------------------------------------------
// CryptoServer
//-----------------------------------------------------------------------------

#define CRYPTOSERVER_ID_accessTest_1    1
#define CRYPTOSERVER_ID_accessTest_2    2
#define CRYPTOSERVER_ID_accessTest_3    3
#define CRYPTOSERVER_ID_accessTest_4    4
#define CRYPTOSERVER_ID_unitTest        5