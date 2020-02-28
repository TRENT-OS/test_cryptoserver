/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * SEOS libraries configurations
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
// Memory
//-----------------------------------------------------------------------------

#define Memory_Config_USE_STDLIB_ALLOC


//-----------------------------------------------------------------------------
// ChanMUX
//-----------------------------------------------------------------------------

enum
{
    CHANMUX_CHANNEL_UNUSED_0,   // 0
    CHANMUX_CHANNEL_UNUSED_1,   // 1
    CHANMUX_CHANNEL_UNUSED_2,   // 2
    CHANMUX_CHANNEL_UNUSED_3,   // 3
    CHANMUX_CHANNEL_UNUSED_4,   // 4
    CHANMUX_CHANNEL_UNUSED_5,   // 5
    CHANMUX_CHANNEL_NVM,        // 6

    CHANMUX_NUM_CHANNELS        // 7
};


//-----------------------------------------------------------------------------
// COMMON
//-----------------------------------------------------------------------------
#define DATABUFFER_SIZE                         4096


//-----------------------------------------------------------------------------
// Logs
//-----------------------------------------------------------------------------

#define Logs_Config_LOG_STRING_SIZE         128
#define Logs_Config_INCLUDE_LEVEL_IN_MSG    1
#define Logs_Config_SYSLOG_LEVEL            Log_TRACE


//-----------------------------------------------------------------------------
// Keystore
//-----------------------------------------------------------------------------

#define KEY_INT_PROPERTY_LEN    4       /* Used to initialize the buffers for serialization of the size_t type
                                        key properties - it represents the number of bytes that size_t type
                                        takes up in memory */

#define MAX_KEY_LEN             2048    /* Maximum length of the raw key in bytes */
#define MAX_KEY_NAME_LEN        16      /* Maximum length of the key name (including the null char) */




//-----------------------------------------------------------------------------
// FILESYSTEM
//-----------------------------------------------------------------------------
// Max. partition per disk
#define PARTITION_COUNT                         10

// Max. file handle per partition
#define FILE_HANDLE_COUNT                       10

// FAT config
#define FILE_DIR_ENTRY_COUNT                    16      // only for (FAT12/FAT16)
#define FS_HEADER_SECTOR_COUNT                  1

#define CLUSTER_SIZE_FAT                        0x200   // size of cluster = 512 Byte
#define OFFSET_SECTORS_COUNT_FAT                3

#define FS_FORMAT                               FS_TYPE_FAT12

//-----------------------------------------------------------------------------
// PARTITION MANAGER
//-----------------------------------------------------------------------------
typedef struct
{
    const char *partition_name;
    int partition_size;
} Partition_config_t;

typedef struct
{
    Partition_config_t partition[5];
} Partition_cat_t;

static const Partition_cat_t partition_conf = {
    .partition[0].partition_name = "",
    .partition[0].partition_size = 0x7D000,     
    .partition[1].partition_name = "",
    .partition[1].partition_size = 0x7D000,     
    .partition[2].partition_name = "",
    .partition[2].partition_size = 0x7D000,     
    .partition[3].partition_name = "",
    .partition[3].partition_size = 0x7D000,    
    .partition[4].partition_name = "",
    .partition[4].partition_size = 0x7D000, 
};

// internal defines
#define PM_CONF_ARRAY_SIZE(x)                   (sizeof(x)/sizeof(x[0]))

#define PARTITION_CONFIGURATION_AT(x)           partition_conf.partition[x]

#define GET_PROPERTY_PARTITION_NAME_AT(x)       PARTITION_CONFIGURATION_AT(x).partition_name
#define GET_PROPERTY_PARTITION_SIZE_AT(x)       PARTITION_CONFIGURATION_AT(x).partition_size

// setup disk/partition
#define GET_PROPERTY_PARTITION_COUNT            PM_CONF_ARRAY_SIZE(partition_conf.partition)
#define GET_PROPERTY_BLOCK_SIZE                 512
#define GET_PROPERTY_PARTITION_NAME(x)          GET_PROPERTY_PARTITION_NAME_AT(x)
#define GET_PROPERTY_PARTITION_SIZE(x)          GET_PROPERTY_PARTITION_SIZE_AT(x)