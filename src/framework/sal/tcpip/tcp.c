/*
 * The MIT License (MIT)
 *
 * Copyright (c) [2015] [Marco Russi]
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
*/

/*
 * This file tcp.c represents the TCP layer of the TCP/IP stack.
 *
 * Author : Marco Russi
 *
 * Evolution of the file:
 * 16/08/2015 - File created - Marco Russi
 *
*/


/*
TODO LIST:
    1) RST packet reception;
    2) implement a re-transmission delay. Wait a bit before transmitting again;
    3) implement a proper function for updating the sequence number, see UPDATE_SEQUENCE_NUMBER macro;
    4) verify received packet checksum in TCP_unpackMessage() function;
    5) consider to set these flags: NS, CWR, ECE, URG in prepareAndSendMsg() function;
    6) consider to update checksum field. See UPDATE_HDR_CHECKSUM macro;
    7) evaluate if it is better to create a common checksum function for UDP and TCP;
    8) consider to implement something with FLUSH flag;
    9) consider to clear data buffer in prepareAndSendMsg() function.
*/




/* ------------ Inclusion files --------------- */
#include "../../fw_common.h"
#include "tcp.h"

#include "../../hal/ethmac.h"
#include "ipv4.h"




/* ------------ Local defines --------------- */

/* Num of max TCP connections */
#define UC_NUM_OF_MAX_CONN                      ((uint8)2)

/* Maximum data length allowed in transmission */
#define US_MAX_TX_DATA_LENGTH_ALLOWED           ((uint16)128)

/* Maximum data length allowed in reception */
#define US_MAX_RX_DATA_LENGTH_ALLOWED           ((uint16)512)

/* Maximum data length allowed in reception */
#define TCP_DEFAULT_WINDOW_SIZE                 (US_MAX_RX_DATA_LENGTH_ALLOWED)

/* Minimum length in bytes of TCP header */
#define UC_TCP_HDR_MIN_LENGTH_BYTES             ((uint8)20)

/* Minimum length in bytes of TCP header */
#define UC_TCP_HDR_MIN_LENGTH_WORDS             ((uint8)(UC_TCP_HDR_MIN_LENGTH_BYTES / UC_4))




/* --------------- Local macros definition -------------- */

/* Local macros bit positions definitions */
#define HDR_SRC_PORT_POS            UL_SHIFT_16
#define HDR_DST_PORT_POS            UL_SHIFT_0
#define HDR_SEQ_NUMBER_POS          UL_SHIFT_0
#define HDR_ACK_NUMBER_POS          UL_SHIFT_0
#define HDR_DATA_OFFSET_POS         UL_SHIFT_28
#define HDR_RESERVED_POS            UL_SHIFT_25
#define HDR_NS_BIT_POS              UL_SHIFT_24
#define HDR_CWR_BIT_POS             UL_SHIFT_23
#define HDR_ECE_BIT_POS             UL_SHIFT_22
#define HDR_URG_BIT_POS             UL_SHIFT_21
#define HDR_ACK_BIT_POS             UL_SHIFT_20
#define HDR_PSH_BIT_POS             UL_SHIFT_19
#define HDR_RST_BIT_POS             UL_SHIFT_18
#define HDR_SYN_BIT_POS             UL_SHIFT_17
#define HDR_FIN_BIT_POS             UL_SHIFT_16
#define HDR_WINDOW_POS              UL_SHIFT_0
#define HDR_CHECKSUM_POS            UL_SHIFT_16
#define HDR_URG_PTR_POS             UL_SHIFT_0

/* TCP header fields set macros */
#define SET_HDR_SRC_PORT(x,y)       ((x) |= (((y) & 0xFFFF) << HDR_SRC_PORT_POS))
#define SET_HDR_DST_PORT(x,y)       ((x) |= (((y) & 0xFFFF) << HDR_DST_PORT_POS))
#define SET_HDR_SEQ_NUM(x,y)        ((x) |= (((y) & 0xFFFFFFFF) << HDR_SEQ_NUMBER_POS))
#define SET_HDR_ACK_NUM(x,y)        ((x) |= (((y) & 0xFFFFFFFF) << HDR_ACK_NUMBER_POS))
#define SET_HDR_DATA_OFF(x,y)       ((x) |= (((y) & 0xFF) << HDR_DATA_OFFSET_POS))
#define SET_HDR_NS_BIT(x,y)         ((x) |= (((y) & 0x1) << HDR_NS_BIT_POS))
#define SET_HDR_CWR_BIT(x,y)        ((x) |= (((y) & 0x1) << HDR_CWR_BIT_POS))
#define SET_HDR_ECE_BIT(x,y)        ((x) |= (((y) & 0x1) << HDR_ECE_BIT_POS))
#define SET_HDR_URG_BIT(x,y)        ((x) |= (((y) & 0x1) << HDR_URG_BIT_POS))
#define SET_HDR_ACK_BIT(x,y)        ((x) |= (((y) & 0x1) << HDR_ACK_BIT_POS))
#define SET_HDR_PSH_BIT(x,y)        ((x) |= (((y) & 0x1) << HDR_PSH_BIT_POS))
#define SET_HDR_RST_BIT(x,y)        ((x) |= (((y) & 0x1) << HDR_RST_BIT_POS))
#define SET_HDR_SYN_BIT(x,y)        ((x) |= (((y) & 0x1) << HDR_SYN_BIT_POS))
#define SET_HDR_FIN_BIT(x,y)        ((x) |= (((y) & 0x1) << HDR_FIN_BIT_POS))
#define SET_HDR_WINDOW_SIZE(x,y)    ((x) |= (((y) & 0xFFFF) << HDR_WINDOW_POS))
#define SET_HDR_CHECKSUM(x,y)       ((x) |= (((y) & 0xFFFF) << HDR_CHECKSUM_POS))
#define SET_HDR_URG_PTR(x,y)        ((x) |= (((y) & 0xFFFF) << HDR_URG_PTR_POS))
/* update checksum field. TODO: optimize this operation */
#define UPDATE_HDR_CHECKSUM(x,y)    ((*(x)) = SWAP_BYTES_ORDER_32BIT_(SWAP_BYTES_ORDER_32BIT_(*(x)) | (((y) & 0xFFFF) << HDR_CHECKSUM_POS)))

/* TCP header fields get macros */
#define GET_HDR_SRC_PORT(x)         ((((x) >> HDR_SRC_PORT_POS) & 0xFFFF))
#define GET_HDR_DST_PORT(x)         ((((x) >> HDR_DST_PORT_POS) & 0xFFFF))
#define GET_HDR_SEQ_NUM(x)          ((((x) >> HDR_SEQ_NUMBER_POS) & 0xFFFFFFFF))
#define GET_HDR_ACK_NUM(x)          ((((x) >> HDR_ACK_NUMBER_POS) & 0xFFFFFFFF))
#define GET_HDR_DATA_OFF(x)         ((((x) >> HDR_DATA_OFFSET_POS) & 0xFF))
#define GET_HDR_NS_BIT(x)           ((((x) >> HDR_NS_BIT_POS) & 0x1))
#define GET_HDR_CWR_BIT(x)          ((((x) >> HDR_CWR_BIT_POS) & 0x1))
#define GET_HDR_ECE_BIT(x)          ((((x) >> HDR_ECE_BIT_POS) & 0x1))
#define GET_HDR_URG_BIT(x)          ((((x) >> HDR_URG_BIT_POS) & 0x1))
#define GET_HDR_ACK_BIT(x)          ((((x) >> HDR_ACK_BIT_POS) & 0x1))
#define GET_HDR_PSH_BIT(x)          ((((x) >> HDR_PSH_BIT_POS) & 0x1))
#define GET_HDR_RST_BIT(x)          ((((x) >> HDR_RST_BIT_POS) & 0x1))
#define GET_HDR_SYN_BIT(x)          ((((x) >> HDR_SYN_BIT_POS) & 0x1))
#define GET_HDR_FIN_BIT(x)          ((((x) >> HDR_FIN_BIT_POS) & 0x1))
#define GET_HDR_WINDOW_SIZE(x)      ((((x) >> HDR_WINDOW_POS) & 0xFFFF))
#define GET_HDR_CHECKSUM(x)         ((((x) >> HDR_CHECKSUM_POS) & 0xFFFF))
#define GET_HDR_URG_PTR(x)          ((((x) >> HDR_URG_PTR_POS) & 0xFFFF))




/* ------------ Local macros definitions -------------- */

/* Macro to get sequence number. TODO: implement it properly */
#define UPDATE_SEQUENCE_NUMBER(x)   (x += 0x00000200)





/* ------------ Local structures definitions -------------- */

/* connection states enum */
typedef enum
{
    KE_OPENING,
    KE_WAIT_SYN_ACK,
    KE_ESTABLISHED,
    KE_ESTAB_WAIT_ACK,
    KE_WAIT_FIN_ACK,
    KE_HALF_OPEN,
    KE_HALF_OPEN_WAIT_ACK,
    KE_HALF_CLOSED,
    KE_WAIT_LAST_ACK,
    KE_CLOSED
} keConnStates;


/* connection states enum */
typedef enum
{
    KE_NO_COMMAND,
    KE_COMM_OPEN,
    KE_COMM_CLOSE
} keConnCommands;


/* message type to prepare and send */
typedef enum
{
    KE_MSG_SYN,
    KE_MSG_ACK,
    KE_MSG_FIN,
    KE_MSG_RST,
    KE_MSG_DATA
} ke_MsgType;


/* local structure to store TCP connections info */
typedef struct
{
    uint32          ui32SrcIPAdd;
    uint32          ui32DstIPAdd;
    uint16          ui16SrcPort;
    uint16          ui16DstPort;
    uint32          ui32SeqNumber;
    uint32          ui32AckNumber;
    uint16          ui16SentDataLength;
    uint16          ui16PendingTXDataLength;
    uint8           *pui8TXDataPtr;
    keConnStates    eCurrConnState;
    keConnCommands  ePendingConnCommand;
    uint8           *pui8RXStartDataPtr;
    uint8           *pui8RXDataPtr;
    uint16          ui16RXDataLength;
    boolean         bNewRXAvailData;
    boolean         bKeepHalfOpen;      
} st_OpenConnInfo;




/* ------------ Local variables declaration -------------- */

/* local open connections info array */
LOCAL st_OpenConnInfo stOpenConnInfo[UC_NUM_OF_MAX_CONN];

/* sequence number. TODO: implement it properly */
LOCAL uint32 ui32SequenceNumber = 0x00270b6c;




/* ------------ Local functions prototypes -------------- */

LOCAL void      getReceivedData         (uint8, uint32 *, uint16);
LOCAL boolean   prepareAndSendMsg       (st_OpenConnInfo *, ke_MsgType, uint8 *, uint16);
LOCAL uint8     getSocketIndex          (uint32, uint32, uint16, uint16);
LOCAL uint16    calculateChecksum       (IPv4_st_PacketDescriptor *, uint16 *);




/* ------------ Exported functions prototypes -------------- */

/* open a new connection */
EXPORTED boolean TCP_openConnection( TCP_ke_ConnIndex eConnIndex, uint32 ui32SrcIPAdd, uint32 ui32DstIPAdd, uint16 ui16SrcPort, uint16 ui16DstPort, boolean bKeepHalfOpen )
{
    uint8 *pui8BufPtr;
    boolean bSuccess;

    /* alloc pointer */
    pui8BufPtr = (uint8 *)MEM_MALLOC(US_MAX_RX_DATA_LENGTH_ALLOWED);
    /* check pointer validity */
    if(pui8BufPtr != NULL_PTR)
    {
        if( B_TRUE == bKeepHalfOpen)
        {
            /* keep the connection half open if needed */
            stOpenConnInfo[eConnIndex].bKeepHalfOpen = B_TRUE;
        }
        else
        {
            /* any other values, do not keep the connection half open if needed. Close it. */
            stOpenConnInfo[eConnIndex].bKeepHalfOpen = B_FALSE;
        }
        /* reset pending TX data length */
        stOpenConnInfo[eConnIndex].ui16PendingTXDataLength = US_NULL;
        /* set start RX data buffer pointer */
        stOpenConnInfo[eConnIndex].pui8RXStartDataPtr = pui8BufPtr;
        /* set RX data buffer pointer */
        stOpenConnInfo[eConnIndex].pui8RXDataPtr = pui8BufPtr;
        /* reset data length */
        stOpenConnInfo[eConnIndex].ui16RXDataLength = US_NULL;
        /* reset sent data length */
        stOpenConnInfo[eConnIndex].ui16SentDataLength = US_NULL;
        /* clear data availability flag */
        stOpenConnInfo[eConnIndex].bNewRXAvailData = B_FALSE;
        /* clear ACK number */
        stOpenConnInfo[eConnIndex].ui32AckNumber = UL_NULL;
        /* init the sequence number */
        stOpenConnInfo[eConnIndex].ui32SeqNumber = ui32SequenceNumber;
        /* update next sequence number */
        UPDATE_SEQUENCE_NUMBER(ui32SequenceNumber);

        /* store all connections info in the next free position */
        stOpenConnInfo[eConnIndex].ui16SrcPort = ui16SrcPort;
        stOpenConnInfo[eConnIndex].ui16DstPort = ui16DstPort;
        stOpenConnInfo[eConnIndex].ui32SrcIPAdd = ui32SrcIPAdd;
        stOpenConnInfo[eConnIndex].ui32DstIPAdd = ui32DstIPAdd;

        /* reset to CLOSED state */
        stOpenConnInfo[eConnIndex].eCurrConnState = KE_CLOSED;
        /* request a OPEN command */
        stOpenConnInfo[eConnIndex].ePendingConnCommand = KE_COMM_OPEN;
        
        /* success to open the connection */
        bSuccess = B_TRUE;
    }
    else
    {
        /* fail to open the connection */
        bSuccess = B_FALSE;
    }

    return bSuccess;
}


/* close a connection */
EXPORTED void TCP_closeConnection( TCP_ke_ConnIndex eConnIndex )
{
    /* request a CLOSE command */
    stOpenConnInfo[eConnIndex].ePendingConnCommand = KE_COMM_CLOSE;
}


/* store info to store a new connection */
EXPORTED boolean TCP_sendData( TCP_ke_ConnIndex eConnIndex, uint8 *pui8DataBuf, uint16 ui16DataBufLength )
{
    boolean bSuccessOp = B_FALSE;

    /* if connection is NOT CLOSED */
    if( KE_CLOSED != stOpenConnInfo[eConnIndex].eCurrConnState )
    {
        /* update TX data buffer */
        stOpenConnInfo[eConnIndex].pui8TXDataPtr = pui8DataBuf;

        /* update pending TX data length */
        stOpenConnInfo[eConnIndex].ui16PendingTXDataLength = ui16DataBufLength;
        
        /* success */
        bSuccessOp = B_TRUE;
    }
    else
    {
        /* connection is CLOSED -> FAIL! */
    }

    return bSuccessOp;
}


/* store info to store a new connection */
EXPORTED void TCP_getReceivedData( TCP_ke_ConnIndex eConnIndex, uint8 *pui8DataBuf, uint16 *pui16DataBufLength )
{
    /* if there are available received data */
    if(B_TRUE == stOpenConnInfo[eConnIndex].bNewRXAvailData)
    {
        /* copy received data into given buffer */
        MEM_COPY(pui8DataBuf,
                 stOpenConnInfo[eConnIndex].pui8RXStartDataPtr,
                 stOpenConnInfo[eConnIndex].ui16RXDataLength);

        /* copy RX data length. ATTENTION: it is supposed that data length is greater than zero */
        *pui16DataBufLength = stOpenConnInfo[eConnIndex].ui16RXDataLength;

        /* reset RX data pointer to the start value */
        stOpenConnInfo[eConnIndex].pui8RXDataPtr = stOpenConnInfo[eConnIndex].pui8RXStartDataPtr;

        /* reset RX data length */
        stOpenConnInfo[eConnIndex].ui16RXDataLength = US_NULL;

        /* clear flag */
        stOpenConnInfo[eConnIndex].bNewRXAvailData = B_FALSE;
    }
    else
    {
        /* no data */
        *pui16DataBufLength = US_NULL;
    }
}


/* manage TCP module periodically */
EXPORTED void TCP_PeriodicTask( void )
{
    uint8 ui8ConnCount;

    /* manage all connections */
    for(ui8ConnCount = UC_NULL; ui8ConnCount < UC_NUM_OF_MAX_CONN; ui8ConnCount++)
    {
        if((KE_ESTABLISHED == stOpenConnInfo[ui8ConnCount].eCurrConnState)
        || (KE_HALF_OPEN == stOpenConnInfo[ui8ConnCount].eCurrConnState))
        {
            if( KE_COMM_CLOSE == stOpenConnInfo[ui8ConnCount].ePendingConnCommand )
            {
                /* update next pending sequence number increment */
                stOpenConnInfo[ui8ConnCount].ui16SentDataLength = UC_1;

                prepareAndSendMsg(&stOpenConnInfo[ui8ConnCount], KE_MSG_FIN, NULL_PTR, US_NULL);

                if(KE_ESTABLISHED == stOpenConnInfo[ui8ConnCount].eCurrConnState)
                {
                    stOpenConnInfo[ui8ConnCount].eCurrConnState = KE_WAIT_FIN_ACK;
                }
                else    /* KE_HALF_OPEN */
                {
                    stOpenConnInfo[ui8ConnCount].eCurrConnState = KE_WAIT_LAST_ACK;
                }

                /* clear pending command */
                stOpenConnInfo[ui8ConnCount].ePendingConnCommand = KE_NO_COMMAND;
            }
            else
            {
                /* if there are still pending data */
                if( stOpenConnInfo[ui8ConnCount].ui16PendingTXDataLength > US_NULL )
                {
                    /* update sent data length */
                    if( stOpenConnInfo[ui8ConnCount].ui16PendingTXDataLength > US_MAX_TX_DATA_LENGTH_ALLOWED )
                    {
                        stOpenConnInfo[ui8ConnCount].ui16SentDataLength = US_MAX_TX_DATA_LENGTH_ALLOWED;
                    }
                    else
                    {
                        stOpenConnInfo[ui8ConnCount].ui16SentDataLength = stOpenConnInfo[ui8ConnCount].ui16PendingTXDataLength;
                    }

                    /* prepare and send a data message */
                    prepareAndSendMsg(&stOpenConnInfo[ui8ConnCount], KE_MSG_DATA, stOpenConnInfo[ui8ConnCount].pui8TXDataPtr, stOpenConnInfo[ui8ConnCount].ui16SentDataLength);

                    if(KE_ESTABLISHED == stOpenConnInfo[ui8ConnCount].eCurrConnState)
                    {
                        stOpenConnInfo[ui8ConnCount].eCurrConnState = KE_ESTAB_WAIT_ACK;
                    }
                    else    /* KE_HALF_OPEN */
                    {
                        stOpenConnInfo[ui8ConnCount].eCurrConnState = KE_HALF_OPEN_WAIT_ACK;
                    }
                }
                else
                {
                    /* do nothing */
                }
            }
        }
        else if(KE_CLOSED == stOpenConnInfo[ui8ConnCount].eCurrConnState)
        {
            if( KE_COMM_OPEN == stOpenConnInfo[ui8ConnCount].ePendingConnCommand )
            {
                /* update next pending sequence number increment */
                stOpenConnInfo[ui8ConnCount].ui16SentDataLength = UC_1;

                prepareAndSendMsg(&stOpenConnInfo[ui8ConnCount], KE_MSG_SYN, NULL_PTR, US_NULL);

                stOpenConnInfo[ui8ConnCount].eCurrConnState = KE_WAIT_SYN_ACK;

                /* clear pending command */
                stOpenConnInfo[ui8ConnCount].ePendingConnCommand = KE_NO_COMMAND;
            }
            else
            {
                /* do nothing */
            }
        }
        else
        {
            /* do nothing */
        }
    }
}


/* unpack TCP messages */
EXPORTED void TCP_unpackMessage( uint32 ui32SrcIPAdd, uint32 ui32DstIPAdd, uint8 *pui8DataPtr, uint16 ui16MsgLength )
{
    uint32 *pui32HdrPtr;
    uint32 ui32HdrWord;
    uint8 ui8SocketIndex;
    uint16 ui16SrcPort;
    uint16 ui16DstPort;
    uint32 ui32SeqNumber;
    uint32 ui32AckNumber;
    uint8 ui8DataOffset;
    uint32 ui32FlagsWord;
    //uint32 ui32ChecksumValue;

    /* set 32-bit header pointer */
    pui32HdrPtr = (uint32 *)pui8DataPtr;

    /* get src and dst ports */
    READ_32BIT_AND_NEXT(pui32HdrPtr, ui32HdrWord);
    ui16SrcPort = GET_HDR_SRC_PORT(ui32HdrWord);
    ui16DstPort = GET_HDR_DST_PORT(ui32HdrWord);

    /* ATTENTION: manage open active connections only - NO listeners */
    /* get socket id from src and dst addresses and ports */
    ui8SocketIndex = getSocketIndex(ui32SrcIPAdd, ui32DstIPAdd, ui16SrcPort, ui16DstPort);
    if(ui8SocketIndex < UC_NUM_OF_MAX_CONN)
    {
        /* get the sequence number */
        READ_32BIT_AND_NEXT(pui32HdrPtr, ui32HdrWord);
        ui32SeqNumber = GET_HDR_SEQ_NUM(ui32HdrWord);
        /* get the ACK number */
        READ_32BIT_AND_NEXT(pui32HdrPtr, ui32HdrWord);
        ui32AckNumber = GET_HDR_ACK_NUM(ui32HdrWord);
        /* get data offset, flags and windows size */
        READ_32BIT_AND_NEXT(pui32HdrPtr, ui32HdrWord);
        ui8DataOffset = GET_HDR_DATA_OFF(ui32HdrWord);  /* get data offset */
        ui32FlagsWord = ui32HdrWord;    /* copy word for flags check */
        //ui32ReadValue = GET_HDR_WINDOW_SIZE(ui32HdrWord);   /* get window size */
        /* get checksum and urgent pointer */
        READ_32BIT_AND_NEXT(pui32HdrPtr, ui32HdrWord);
        //ui32ChecksumValue = GET_HDR_CHECKSUM(ui32HdrWord);  /* TODO: checksum not verified at the moment */
        //ui32ReadValue = GET_HDR_URG_PTR(ui32HdrWord);   /* get urgent pointer */

        /* check ACK packet */
        if( UC_1 == GET_HDR_ACK_BIT(ui32FlagsWord) )
        {
            /* check ACK number  */
            if((stOpenConnInfo[ui8SocketIndex].ui32SeqNumber + stOpenConnInfo[ui8SocketIndex].ui16SentDataLength) == ui32AckNumber)
            {
                /* increment the sequence number */
                stOpenConnInfo[ui8SocketIndex].ui32SeqNumber += stOpenConnInfo[ui8SocketIndex].ui16SentDataLength;
                /* if FIN message */
                if( UC_1 == GET_HDR_FIN_BIT(ui32FlagsWord) )
                {
                    /* if connection is in ESTABLISHED state */
                    if(KE_ESTABLISHED == stOpenConnInfo[ui8SocketIndex].eCurrConnState)
                    {
                        /* connection is now HALF OPEN */
                        stOpenConnInfo[ui8SocketIndex].eCurrConnState = KE_HALF_OPEN;
                        /* if connection can not be left in HALF OPEN state */
                        if( B_FALSE == stOpenConnInfo[ui8SocketIndex].bKeepHalfOpen )
                        {
                            /* request to close it */
                            stOpenConnInfo[ui8SocketIndex].ePendingConnCommand = KE_COMM_CLOSE;
                        }
                        else
                        {
                            /* leave it HALF OPEN */
                        }
                    }
                    /* else if connection is HALF CLOSED or it is awaiting for ACK to a FIN message */
                    else if((KE_HALF_CLOSED == stOpenConnInfo[ui8SocketIndex].eCurrConnState)
                         || (KE_WAIT_FIN_ACK == stOpenConnInfo[ui8SocketIndex].eCurrConnState))
                    {
                        /* connection is now CLOSED */
                        stOpenConnInfo[ui8SocketIndex].eCurrConnState = KE_CLOSED;
                    }
                    else
                    {
                        /* unexpected FIN message, ignore it but send back an ACK anyway */
                    }
                    /* update ACK number */
                    stOpenConnInfo[ui8SocketIndex].ui32AckNumber = ui32SeqNumber + UC_1;
                    /* send a ACK message */
                    prepareAndSendMsg(&stOpenConnInfo[ui8SocketIndex], KE_MSG_ACK, NULL_PTR, US_NULL);
                }
                /* else SYN message */
                else if( UC_1 == GET_HDR_SYN_BIT(ui32FlagsWord) )
                {
                    /* if it is awaiting for an ACK of a SYN message */
                    if(KE_WAIT_SYN_ACK == stOpenConnInfo[ui8SocketIndex].eCurrConnState)
                    {
                        /* connection is now ESTABLISHED */
                        stOpenConnInfo[ui8SocketIndex].eCurrConnState = KE_ESTABLISHED;
                        /* update ACK number */
                        stOpenConnInfo[ui8SocketIndex].ui32AckNumber = ui32SeqNumber + UC_1;
                        /* send an ACK message */
                        prepareAndSendMsg(&stOpenConnInfo[ui8SocketIndex], KE_MSG_ACK, NULL_PTR, US_NULL);
                    }
                    else
                    {
                        /* unexpected SYN, ignore it and do NOT send back an ACK */
                    }
                }
                else
                {
                    /* if it was awaiting for a ACK to a previous FYN message */
                    if( KE_WAIT_FIN_ACK == stOpenConnInfo[ui8SocketIndex].eCurrConnState )
                    {
                        /* connection is now HALF CLOSED */
                        stOpenConnInfo[ui8SocketIndex].eCurrConnState = KE_HALF_CLOSED;
                    }
                    /* else if it was awaiting for a last ACK message */
                    else if( KE_WAIT_LAST_ACK == stOpenConnInfo[ui8SocketIndex].eCurrConnState )
                    {
                        /* connection is now CLOSED */
                        stOpenConnInfo[ui8SocketIndex].eCurrConnState = KE_CLOSED;
                    }
                    else
                    {
                        /* calculate data length */
                        ui16MsgLength -= (ui8DataOffset * UC_4);
                        /* call local function to get received data */
                        getReceivedData(ui8SocketIndex, pui32HdrPtr, ui16MsgLength);
                        /* update ACK number */
                        stOpenConnInfo[ui8SocketIndex].ui32AckNumber = (uint32)(ui32SeqNumber + ui16MsgLength);
                        /* if it was a awaiting for an ACK of a previous sent data packet */
                        if((KE_ESTAB_WAIT_ACK == stOpenConnInfo[ui8SocketIndex].eCurrConnState)
                        || (KE_HALF_OPEN_WAIT_ACK == stOpenConnInfo[ui8SocketIndex].eCurrConnState))
                        {
                            /* ACK received. decrement pending data length */
                            stOpenConnInfo[ui8SocketIndex].ui16PendingTXDataLength -= stOpenConnInfo[ui8SocketIndex].ui16SentDataLength;
                            /* move on TX data pointer */
                            stOpenConnInfo[ui8SocketIndex].pui8TXDataPtr += stOpenConnInfo[ui8SocketIndex].ui16SentDataLength;

                            if(KE_ESTAB_WAIT_ACK == stOpenConnInfo[ui8SocketIndex].eCurrConnState)
                            {
                                stOpenConnInfo[ui8SocketIndex].eCurrConnState = KE_ESTABLISHED;
                            }
                            else    /* KE_HALF_OPEN_WAIT_ACK */
                            {
                                stOpenConnInfo[ui8SocketIndex].eCurrConnState = KE_HALF_OPEN;
                            }
                        }
                        /* else a data packet has been received from other end-point */
                        else
                        {
                            /* do nothing in particular */
                        }
                        /* send back a ACK anyway */
                        prepareAndSendMsg(&stOpenConnInfo[ui8SocketIndex], KE_MSG_ACK, NULL_PTR, US_NULL);
                    }
                }
                /* clear sent data length */
                stOpenConnInfo[ui8SocketIndex].ui16SentDataLength = US_NULL;
            }
            else
            {
                /* ACK number is wrong, send a RESET message */
                prepareAndSendMsg(&stOpenConnInfo[ui8SocketIndex], KE_MSG_RST, NULL_PTR, US_NULL);
                /* close connection at the moment */
                stOpenConnInfo[ui8SocketIndex].eCurrConnState = KE_CLOSED;
            }
        }
        else
        {
            /* this packet has not ACK bit set, do nothing. Manage ACK packets only */
        }
    }
    else
    {
        /* related connection doesn't exist */
    }
}




/* ------------------- Local functions declaration ---------------- */

/* get received data from packet */
LOCAL void getReceivedData( uint8 ui8SocketIndex, uint32 * pui32HdrPtr, uint16 ui16DataLengthToCopy )
{
    /* if there are data */
    if(ui16DataLengthToCopy > US_NULL)
    {
        /* if received data are more than available space */
        if((stOpenConnInfo[ui8SocketIndex].ui16RXDataLength + ui16DataLengthToCopy) > US_MAX_RX_DATA_LENGTH_ALLOWED)
        {
            /* maximum RX data length to copy */
            ui16DataLengthToCopy = (uint16)(US_MAX_RX_DATA_LENGTH_ALLOWED - stOpenConnInfo[ui8SocketIndex].ui16RXDataLength);
        }
        else
        {
            /* else there is still enough space in the RX buffer: copy all received data */
        }

        /* copy received data */
        MEM_COPY(stOpenConnInfo[ui8SocketIndex].pui8RXDataPtr,
                 pui32HdrPtr,
                 ui16DataLengthToCopy);

        /* increment RX data length */
        stOpenConnInfo[ui8SocketIndex].ui16RXDataLength += ui16DataLengthToCopy;

        /* increment RX data pointer */
        stOpenConnInfo[ui8SocketIndex].pui8RXDataPtr += ui16DataLengthToCopy;

        /* set flag. ATTENTION: should be an atomic operation */
        stOpenConnInfo[ui8SocketIndex].bNewRXAvailData = B_TRUE;
    }
    else
    {
        /* length is more than maximum available: discard data at the moment */
    }
}


/* prepare and send a SYN message */
LOCAL boolean prepareAndSendMsg( st_OpenConnInfo *pstConnInfo, ke_MsgType eMsgType, uint8 *pui8DataPtr, uint16 ui16DataLength )
{
    boolean bSuccess;
    uint8 *pui8BufferPtr;
    uint32 *pui32HdrWords;
    uint32 ui32HdrWord = UL_NULL;   /* it is very important to clean this variable */
    uint16 ui16Checksum;
    uint8 ui8HdrWordsLength;
    IPv4_st_PacketDescriptor stIPv4PacketDscpt;

    /* get next free buffer pointer from IP */
    pui8BufferPtr = (uint8 *)IPV4_getDataBuffPtr();
    if(pui8BufferPtr != NULL)
    {
        /* perform a 32-bit word alignment */
        ALIGN_32BIT_OF_8BIT_PTR(pui8BufferPtr);
        /* set 32-bit header pointer */
        pui32HdrWords = (uint32 *)pui8BufferPtr;

        /* TODO: consider to clear the buffer */
        /*memset(pui32HdrWords, UC_NULL, (ui16DataLength + UC_TCP_HDR_MIN_LENGTH_BYTES));*/

        SET_HDR_SRC_PORT(ui32HdrWord, pstConnInfo->ui16SrcPort);
        SET_HDR_DST_PORT(ui32HdrWord, pstConnInfo->ui16DstPort);
        WRITE_32BIT_AND_NEXT(pui32HdrWords, ui32HdrWord);
        SET_HDR_SEQ_NUM(ui32HdrWord, pstConnInfo->ui32SeqNumber);
        WRITE_32BIT_AND_NEXT(pui32HdrWords, ui32HdrWord);
        SET_HDR_ACK_NUM(ui32HdrWord, pstConnInfo->ui32AckNumber);
        WRITE_32BIT_AND_NEXT(pui32HdrWords, ui32HdrWord);
        /* set TCP header size in 32-bit words */
        ui8HdrWordsLength = UC_TCP_HDR_MIN_LENGTH_WORDS;
        /* OPTIONS TEST! */
        if(KE_MSG_SYN == eMsgType)
        {
            /* add TEST option length! */
            ui8HdrWordsLength += UC_1;
        }
        else
        {
            /* length is already updated */
        }
        SET_HDR_DATA_OFF(ui32HdrWord, ui8HdrWordsLength);

        /* TODO: consider to set these flags */
        /*SET_HDR_NS_BIT(ui32HdrWord, 1);
        SET_HDR_CWR_BIT(ui32HdrWord, 0);
        SET_HDR_ECE_BIT(ui32HdrWord, 1);
        SET_HDR_URG_BIT(ui32HdrWord, 0);*/

        switch(eMsgType)
        {
            case KE_MSG_ACK:
            {
                /* set ACK */
                SET_HDR_ACK_BIT(ui32HdrWord, 1);
                break;
            }
            case KE_MSG_SYN:
            {
                /* set SYN */
                SET_HDR_SYN_BIT(ui32HdrWord, 1);
                break;
            }
            case KE_MSG_FIN:
            {
                /* set FIN */
                SET_HDR_FIN_BIT(ui32HdrWord, 1);
                SET_HDR_ACK_BIT(ui32HdrWord, 1);    /* ATTENTION: FIN packet contains also the ACK flag */
                break;
            }
            case KE_MSG_RST:
            {
                SET_HDR_RST_BIT(ui32HdrWord, 1);
                break;
            }
            case KE_MSG_DATA:
            {
                SET_HDR_ACK_BIT(ui32HdrWord, 1);
                SET_HDR_PSH_BIT(ui32HdrWord, 1);    /* ATTENTION: push data! */
                break;
            }
            default:
            {
                /* do nothing */
                break;
            }
        }

        /* set window size */
        SET_HDR_WINDOW_SIZE(ui32HdrWord, TCP_DEFAULT_WINDOW_SIZE);
        WRITE_32BIT_AND_NEXT(pui32HdrWords, ui32HdrWord);
        /* set checksum and urgent pointer */
        SET_HDR_CHECKSUM(ui32HdrWord, 0);
        SET_HDR_URG_PTR(ui32HdrWord, 0);
        WRITE_32BIT_AND_NEXT(pui32HdrWords, ui32HdrWord);
        
        
        /* OPTIONS TEST! */
        if(KE_MSG_SYN == eMsgType)
        {
            ui32HdrWord = 0x020405B4;
            WRITE_32BIT_AND_NEXT(pui32HdrWords, ui32HdrWord);
        }
        else
        {
            /* do nothing */
        }


        /* attach data */
        if(KE_MSG_DATA == eMsgType)
        {
            /* attach data */
            MEM_COPY((uint8 *)pui32HdrWords, pui8DataPtr, ui16DataLength);
        }
        else
        {
            /* do nothing */
        }

        /* set IPv4 descriptor */
        stIPv4PacketDscpt.enProtocol = IPV4_PROT_TCP;
        stIPv4PacketDscpt.bDoNotFragment = B_FALSE; /* ATTENTION: this value can change according to application request */
        stIPv4PacketDscpt.ui16DataLength = (ui16DataLength + ((uint16)(ui8HdrWordsLength * UC_4)));
        stIPv4PacketDscpt.ui32IPDstAddress = pstConnInfo->ui32DstIPAdd;
        stIPv4PacketDscpt.ui32IPSrcAddress = pstConnInfo->ui32SrcIPAdd;

        /* calculate and update checksum field */
        pui32HdrWords = (uint32 *)pui8BufferPtr;
        ui16Checksum = calculateChecksum(&stIPv4PacketDscpt, (uint16 *)pui32HdrWords);
        pui32HdrWords += 4;
        UPDATE_HDR_CHECKSUM(pui32HdrWords, ui16Checksum);

        /* send TCP segment through IP and check operation result */
        if(IPV4_OP_OK == IPV4_SendPacket(stIPv4PacketDscpt))
        {
            /* operation success */
            bSuccess = B_TRUE;
        }
        else
        {
            /* IP buffer may be full, return a fail */
            bSuccess = B_FALSE;
        }
    }
    else
    {
        /* IP buffer is full, try later */
        bSuccess = B_FALSE;
    }

    return bSuccess;
}


/* get socket index from src and dst addresses and ports */
LOCAL uint8 getSocketIndex(uint32 ui32SourceAdd, uint32 ui32DestAdd, uint16 ui16SourcePort, uint16 ui16DestPort)
{
    uint8 ui8SktIdx = UC_NULL;

    /* search socket */
    while(  (   (stOpenConnInfo[ui8SktIdx].eCurrConnState == KE_CLOSED) /* socket is still open */
            ||  ((stOpenConnInfo[ui8SktIdx].ui32SrcIPAdd != ui32DestAdd) && (stOpenConnInfo[ui8SktIdx].ui32SrcIPAdd != 0x00000000))     /* this device is the destination or source address is not 0.0.0.0 */
            ||  ((stOpenConnInfo[ui8SktIdx].ui32DstIPAdd != ui32SourceAdd) && (stOpenConnInfo[ui8SktIdx].ui32DstIPAdd != 0xFFFFFFFF))   /* the sender is the expected one or destination address is not a IP broadcast address */
            ||  (stOpenConnInfo[ui8SktIdx].ui16SrcPort != ui16DestPort)     /* destination port is this one */
            ||  (stOpenConnInfo[ui8SktIdx].ui16DstPort != ui16SourcePort))  /* source port is the expected one */
    &&      (ui8SktIdx < UC_NUM_OF_MAX_CONN))

    {
        /* next socket */
        ui8SktIdx++;
    }

    return ui8SktIdx;
}


/* Function to calculate checksum */
LOCAL uint16 calculateChecksum(IPv4_st_PacketDescriptor *stIPv4Header, uint16 *pui16TCPSegment)
{
    uint32 ui32Sum = 0;
    uint16 ui16Length = stIPv4Header->ui16DataLength;

    ui32Sum += ((SWAP_BYTES_ORDER_32BIT_(stIPv4Header->ui32IPSrcAddress) >> UL_SHIFT_16) & 0xFFFF);
    ui32Sum += (SWAP_BYTES_ORDER_32BIT_(stIPv4Header->ui32IPSrcAddress) & 0xFFFF);

    ui32Sum += ((SWAP_BYTES_ORDER_32BIT_(stIPv4Header->ui32IPDstAddress) >> UL_SHIFT_16) & 0xFFFF);
    ui32Sum += (SWAP_BYTES_ORDER_32BIT_(stIPv4Header->ui32IPDstAddress) & 0xFFFF);

    ui32Sum += SWAP_BYTES_ORDER_16BIT_(stIPv4Header->enProtocol);

    ui32Sum += SWAP_BYTES_ORDER_16BIT_(stIPv4Header->ui16DataLength);

    while( ui16Length > 1 )
    {
        ui32Sum += *pui16TCPSegment;
        pui16TCPSegment++;
        ui16Length -= 2;
    }

    if( ui16Length > 0 )
    {
        ui32Sum += ((*pui16TCPSegment) & SWAP_BYTES_ORDER_16BIT_(0xFF00));
    }

    /* Fold 32-bit sum to 16 bits: add carrier to result */
    while( ui32Sum >> 16 )
    {
        ui32Sum = (ui32Sum & 0xFFFF) + (ui32Sum >> 16);
    }
    ui32Sum = ~ui32Sum;

    /* swap bytes order */
    ui32Sum = SWAP_BYTES_ORDER_16BIT_(ui32Sum);

    return (uint16)ui32Sum;
}




/* End of file */
