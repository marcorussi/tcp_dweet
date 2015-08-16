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
 * This file tcp.h represents the TCP layer inclusion file of the TCP/IP stack.
 *
 * Author : Marco Russi
 *
 * Evolution of the file:
 * 16/08/2015 - File created - Marco Russi
 *
*/


/* ------------ Inclusion files --------------- */

#include "../../fw_common.h"



/* ------------ Exported enums --------------- */

/* TCP connection indexes */
typedef enum
{
    TCP_KE_FIRST_CONN,
    TCP_KE_CONN_1 = TCP_KE_FIRST_CONN,
    TCP_KE_CONN_2,
    TCP_KE_CONN_3,
    TCP_KE_CONN_4,
    TCP_KE_LAST_CONN = TCP_KE_CONN_4,
    TCP_KE_CONN_MAX_NUM,
    TCP_KE_NULL_CONN_INDEX = 0xFF  
} TCP_ke_ConnIndex;


/* ------------ Exported functions prototypes */

EXTERN boolean  TCP_openConnection  (TCP_ke_ConnIndex, uint32, uint32, uint16, uint16, boolean);
EXTERN void     TCP_closeConnection (TCP_ke_ConnIndex);
EXTERN boolean  TCP_sendData        (TCP_ke_ConnIndex, uint8 *, uint16);
EXTERN void     TCP_getReceivedData (TCP_ke_ConnIndex, uint8 *, uint16 *);
EXTERN void     TCP_PeriodicTask    (void);
EXTERN void     TCP_unpackMessage   (uint32, uint32, uint8 *, uint16);




/* End of file */
