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
 * This file app_dweet.c represents the DWEET application source file.
 *
 * Author : Marco Russi
 *
 * Evolution of the file:
 * 16/08/2015 - File created - Marco Russi
 *
*/


/* ------------- Inclusion files -------------- */

#include "../framework/fw_common.h"

#include "app_dweet.h"

#include "../framework/hal/port.h"
#include "../framework/sal/dio/inch.h"
#include "../framework/sal/rtos/rtos.h"
#include "../framework/sal/tcpip/tcp.h"
#include "../framework/sal/tcpip/dhcp.h"
#include "../framework/sal/tcpip/ipv4.h"




/* ---------------- Local defines ---------------- */

/* dweet.io IP address: 54.172.56.193 */
#define UL_DWEET_IP_ADDRESS             ((uint32)0x36AC38C1)

/* dweet.io listening port: HTTP port 80 */
#define US_DWEET_LISTENING_PORT         ((uint16)80)

/* local source port */
#define US_LOCAL_SOURCE_PORT            ((uint16)56068)

/* RX data buffer length in bytes */
#define US_RX_DATA_BUFFER_LENGTH        ((uint16)512)

/* TX data buffer length in bytes */
#define US_TX_DATA_BUFFER_LENGTH        ((uint16)128)

/* RTOS callback iD used for periodic requests */
#define PERIODIC_REQ_CALLBACK_ID        (RTOS_CB_ID_1)

/* ON/OFF switch button */
#define ON_OFF_PUSH_BUTTON_CH           (INCH_KE_CHANNEL_2)

/* ON/OFF LED port ID */
#define ON_OFF_LED_PORT_ID              (PORT_ID_D)

/* ON/OFF LED port pin ID */
#define ON_OFF_LED_PIN_ID               (PORT_PIN_1)

/* TEST LED port ID */
#define TEST_LED_PORT_ID                (PORT_ID_D)

/* TEST LED port pin ID */
#define TEST_LED_PIN_ID                 (PORT_PIN_0)




/* ---------------- Local typedef definitions ---------------- */

/* connection states enum */
typedef enum
{
    KE_FIRST_STATE,
    KE_INIT_STATE = KE_FIRST_STATE,
    KE_OPEN_CONN_STATE,
    KE_REQ_INFO_STATE,
    KE_WAIT_INFO_STATE,
    KE_CLOSE_STATE,
    KE_WAIT_NEXT_REQ_STATE,
    KE_IDLE_STATE,
    KE_LAST_STATE = KE_IDLE_STATE
} ke_ConnectionStatus;




/* ---------------- Local variables declaration ------------------ */

/* Const strings for Dweet operation */
LOCAL uint8 dweetHostString[] = "dweet.io";
//LOCAL uint8 dweetPathString[] = "dweet/for/{prova_sens}?temp=bassa&pioggia=nulla";
LOCAL uint8 dweetPathString[] = "get/latest/dweet/for/{prova_sens}";




/* ---------------- Local variables declaration ------------------ */

/* store current connection status */
LOCAL ke_ConnectionStatus enConnStatus;

/* IP address */
LOCAL uint32 ui32IPAddress = UL_NULL;

/* TCP connection index number. Fixed at TCP_KE_CONN_1 */
LOCAL TCP_ke_ConnIndex eTCPConnIndex = TCP_KE_CONN_1;

/* TX data buffer pointer */
LOCAL uint8 *pui8TXDataBufPtr = NULL_PTR;

/* RX data buffer pointer */
LOCAL uint8 *pui8RXDataBufPtr = NULL_PTR;

/* TCP connection open success flag */
LOCAL boolean bTCPOpenConnSuccess = B_FALSE;

/* Flag to store application state */
LOCAL boolean bDweetAppConnectionReq = B_FALSE;




/* -------------- Local functions prototypes --------------------- */

LOCAL void manageAppButton                  ( void );
LOCAL void checkDweetResponse               ( uint8 * );
LOCAL void triggerNextReqInfoCallBack       ( void );




/* --------------- Exported functions declaration --------------- */

/* Dweet app init */
EXPORTED void APP_DWEET_Init( void )
{
    boolean bInitSuccess = B_TRUE;

    /* init ETHMAC */
    bInitSuccess &= ETHMAC_Init();
    /* init IPv4 */
    bInitSuccess &= IPV4_Init();
    /* init DHCP */
    bInitSuccess &= DHCP_Init();

    if(bInitSuccess != B_TRUE)
    {
        /* TCP/IP module init fail! */
    }
    else
    {
        /* TCP/IP module init success! */

        /* allocate TX and RX data buffers */
        pui8TXDataBufPtr = (uint8 *)MEM_MALLOC(US_TX_DATA_BUFFER_LENGTH);
        pui8RXDataBufPtr = (uint8 *)MEM_MALLOC(US_RX_DATA_BUFFER_LENGTH);

        /* connection status is in IDLE */
        enConnStatus = KE_IDLE_STATE;
    }
}




/* Dweet app periodic task */
EXPORTED void APP_DWEET_PeriodicTask( void )
{
    uint16 ui16RXDataLength;

    /* manage app ON/OFF button */
    manageAppButton();
   
    /* manage connection */
    switch(enConnStatus)
    {
        case KE_INIT_STATE:
        {
            /* get obtained IP address via DHCP */
            ui32IPAddress = IPV4_getObtainedIPAdd();
            if(ui32IPAddress != UL_NULL)
            {
                /* prepare a HTTP string for dweet operation */
                sprintf(pui8TXDataBufPtr,
                        "GET /%s HTTP/1.1\r\nHost: %s\r\nConnection: Keep-Alive\r\n\r\n",
                        dweetPathString,
                        dweetHostString);

                /* go into OPEN CONNECTION state */
                enConnStatus = KE_OPEN_CONN_STATE;
            }
            else
            {
                /* remain in this state and wait for a valid IP address */
                break;
            }
            /* ATTENTION: fall-through only if a valid IP address is ready */
        }
        case KE_OPEN_CONN_STATE:
        {
            /* open a TCP connection */
            bTCPOpenConnSuccess = TCP_openConnection(   eTCPConnIndex,
                                                        ui32IPAddress,
                                                        UL_DWEET_IP_ADDRESS,
                                                        US_LOCAL_SOURCE_PORT,
                                                        US_DWEET_LISTENING_PORT,
                                                        B_FALSE);
            /* if TCP connection index is valid */
            if( B_TRUE == bTCPOpenConnSuccess )
            {
                /* go into REQUEST INFO state */
                enConnStatus = KE_REQ_INFO_STATE;
            }
            else
            {
                /* fail to open a TCP connection: try on next run */
                break;
            }
            /* ATTENTION: fall-through if success only */
        }
        case KE_REQ_INFO_STATE:
        {
            /* require to send dweet string */
            if( B_TRUE == TCP_sendData(eTCPConnIndex, pui8TXDataBufPtr, MEM_GET_LENGTH(pui8TXDataBufPtr)))
            {
                /* go into WAIT INFO state */
                enConnStatus = KE_WAIT_INFO_STATE;
            }
            else
            {
                /* fail to open a TCP connection: try on next run */
            }
            break;
        }
        case KE_WAIT_INFO_STATE:
        {
            /* check received TCP data */
            TCP_getReceivedData(eTCPConnIndex, pui8RXDataBufPtr, &ui16RXDataLength);
            if( ui16RXDataLength != US_NULL )
            {
                /* check TCP received data */
                checkDweetResponse(pui8RXDataBufPtr);

                /* trigger next request later */
                RTOS_SetCallback(PERIODIC_REQ_CALLBACK_ID, RTOS_CB_TYPE_SINGLE, 2000, &triggerNextReqInfoCallBack);

                /* go into KE_WAIT_NEXT_REQ_STATE state */
                enConnStatus = KE_WAIT_NEXT_REQ_STATE;
            }
            else
            {
                /* do nothing. remain in this state */
            }
            break;
        }
        case KE_CLOSE_STATE:
        {
            /* stop any eventual pending data request callback */
            RTOS_StopCallback(PERIODIC_REQ_CALLBACK_ID);
            /* close the TCP connection */
            TCP_closeConnection(eTCPConnIndex);
            /* reset connection success flag */
            bTCPOpenConnSuccess = B_FALSE;
            /* go into IDLE state */
            enConnStatus = KE_IDLE_STATE;
            break;
        }
        case KE_IDLE_STATE:
        {
            /* if dweet app is turned ON */
            if( B_TRUE == bDweetAppConnectionReq )
            {
                /* if a valid IP address has not been obtained */
                if( UL_NULL == ui32IPAddress )
                {
                    /* start a IP address request via DHCP */
                    DHCP_StartIPAddReq();
                }
                else
                {
                    /* IP address is already valid */
                }
    
                /* request connection init: go into KE_INIT_STATE state */
                enConnStatus = KE_INIT_STATE;
            }
            else
            {
                /* app is already ON: do nothing */
            }
            break;
        }
        case KE_WAIT_NEXT_REQ_STATE:
        {
            /* if dweet app is turned OFF */
            if( B_FALSE == bDweetAppConnectionReq )
            {
                /* request connection closure: go into KE_CLOSE_STATE state */
                enConnStatus = KE_CLOSE_STATE;
            }
            else
            {
                /* app is already ON: do nothing */
            }
            break;
        }
        default:
        {
            /* do nothing */
            break;
        }
    }
}




/* -------------- Local functions declaration ------------------ */

/* callback for trigging next info request */
LOCAL void triggerNextReqInfoCallBack( void )
{
    /* go into KE_REQ_INFO_STATE state */
    enConnStatus = KE_REQ_INFO_STATE;
}


/* check the button for turning the aplication ON or OFF */
/* Toggle app state ( ON or OFF ) at every button pressure */
LOCAL void manageAppButton ( void )
{
    INCH_ke_ChannelTrans eTrans;

    /* get button transition */
    eTrans = INCH_GetChannelTransition(ON_OFF_PUSH_BUTTON_CH);
    /* if rising edge */
    if(INCH_KE_RISING_EDGE == eTrans)
    {
        /* if dweet appilcation is OFF */
        if( B_FALSE == bDweetAppConnectionReq )
        {
            /* turn dweet app ON */
            bDweetAppConnectionReq = B_TRUE;
            /* set related LED */
            PORT_SetPortPin(ON_OFF_LED_PORT_ID, ON_OFF_LED_PIN_ID);
        }
        /* else dweet app is already ON */
        else
        {
            /* turn dweet app OFF */
            bDweetAppConnectionReq = B_FALSE;
            /* clear related LED */
            PORT_ClearPortPin(ON_OFF_LED_PORT_ID, ON_OFF_LED_PIN_ID);
        }
    }
    else
    {
        /* do nothing */
    }
}


/* check the result into received buffer */
LOCAL void checkDweetResponse(uint8 *pui8Buffer)
{
    uint8 ui8ResultValue;
    char read_value[10];
    char fieldToFind[] = "temp";
    char value1[] = "bassa";
    char value2[] = "alta";
    char * pos;

    pos = strstr(pui8Buffer, &fieldToFind[0]);

    if(NULL != pos)
    {
        pos += strlen(fieldToFind) + 3;
        strncpy(&read_value[0], pos, 5);

        if(strstr(&read_value[0], &value1[0]))
        {
            ui8ResultValue = 1;
            PORT_ClearPortPin(TEST_LED_PORT_ID, TEST_LED_PIN_ID);
        }
        else if(strstr(&read_value[0], &value2[0]))
        {
            ui8ResultValue = 2;
            PORT_SetPortPin(TEST_LED_PORT_ID, TEST_LED_PIN_ID);
        }
        else
        {
            ui8ResultValue = 3;
        }
    }
    else
    {
        /* what I'm looking for is missing in this buffer */
        ui8ResultValue = 3;
    }
}




/* End of file */
