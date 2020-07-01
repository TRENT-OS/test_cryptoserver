/*
 *  Channel MUX
 *
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "system_config.h"
#include "ChanMux/ChanMux.h"
#include <camkes.h>


//------------------------------------------------------------------------------
static unsigned int
resolveChannel(
    unsigned int  sender_id,
    unsigned int  chanNum_local)
{
    switch (sender_id)
    {
    //----------------------------------
    case CHANMUX_ID_CRYPTOSERVER:
        // TODO: check that chanNum_local is 0, reject anything else
        return CHANMUX_CHANNEL_NVM;
    //----------------------------------
    default:
        break;
    }

    return INVALID_CHANNEL;
}


//------------------------------------------------------------------------------
static uint8_t client_fifo_buffer[PAGE_SIZE];
static ChanMux_Channel_t client_channel;

static const ChanMux_ChannelCtx_t channelCtx[] = {
    CHANMUX_CHANNEL_CTX(
        CHANMUX_CHANNEL_NVM,
        &client_channel,
        client_fifo_buffer, // must be the buffer and not a pointer
        CHANMUX_DATAPORT_ASSIGN(cryptoServer_chan_portRead,
                                cryptoServer_chan_portWrite),
        cryptoServer_chan_DataAvailable_emit),
};


const ChanMux_Config_t cfgChanMux =
{
    .resolveChannel = &resolveChannel,
    .numChannels    = ARRAY_SIZE(channelCtx),
    .channelCtx     = channelCtx,
};
