/*

Code taken and modified from:
A PAINLESS GUIDE TO CRC ERROR DETECTION ALGORITHMS

Where the following copyright appears:

Status  : Copyright (C) Ross Williams, 1993. However, permission is
          granted to make and distribute verbatim copies of this
          document provided that this information block and copyright
          notice is included. Also, the C code modules included
          in this document are fully public domain.
*/

/******************************************************************************/
/*                             Start of crcmodel.c                            */
/******************************************************************************/
/*                                                                            */
/* Author : Ross Williams (ross@guest.adelaide.edu.au.).                      */
/* Date   : 3 June 1993.                                                      */
/* Status : Public domain.                                                    */
/*                                                                            */
/* Description : This is the implementation (.c) file for the reference       */
/* implementation of the Rocksoft^tm Model CRC Algorithm. For more            */
/* information on the Rocksoft^tm Model CRC Algorithm, see the document       */
/* titled "A Painless Guide to CRC Error Detection Algorithms" by Ross        */
/* Williams (ross@guest.adelaide.edu.au.). This document is likely to be in   */
/* "ftp.adelaide.edu.au/pub/rocksoft".                                        */
/*                                                                            */
/* Note: Rocksoft is a trademark of Rocksoft Pty Ltd, Adelaide, Australia.    */
/*                                                                            */
/******************************************************************************/
/*                                                                            */
/* Implementation Notes                                                       */
/* --------------------                                                       */
/* To avoid inconsistencies, the specification of each function is not echoed */
/* here. See the header file for a description of these functions.            */
/* This package is light on checking because I want to keep it short and      */
/* simple and portable (i.e. it would be too messy to distribute my entire    */
/* C culture (e.g. assertions package) with this package.                     */
/*                                                                            */
/******************************************************************************/

#include "crc.h"
#include <stdio.h>

#ifndef _MSC_VER
#include <stdint.h>
#endif
/******************************************************************************/

/* The following definitions make the code more readable. */

#define BITMASK(X) (1L << (X))
#define MASK32 0xFFFFFFFFL
#define LOCAL static

/******************************************************************************/

LOCAL ulong reflect P_((ulong v,int b));
LOCAL ulong reflect (v,b)
/* Returns the value v with the bottom b [0,32] bits reflected. */
/* Example: reflect(0x3e23L,3) == 0x3e26                        */
ulong v;
int   b;
{
 int   i;
 ulong t = v;
 for (i=0; i<b; i++)
   {
    if (t & 1L)
       v|=  BITMASK((b-1)-i);
    else
       v&= ~BITMASK((b-1)-i);
    t>>=1;
   }
 return v;
}

/******************************************************************************/

LOCAL ulong widmask P_((p_cm_t));
LOCAL ulong widmask (p_cm)
/* Returns a longword whose value is (2^p_cm->cm_width)-1.     */
/* The trick is to do this portably (e.g. without doing <<32). */
p_cm_t p_cm;
{
 return (((1L<<(p_cm->cm_width-1))-1L)<<1)|1L;
}

/******************************************************************************/

void cm_ini (p_cm)
p_cm_t p_cm;
{
 p_cm->cm_reg = p_cm->cm_init;
}

/******************************************************************************/

void cm_nxt (p_cm,ch)
p_cm_t p_cm;
int    ch;
{
 int   i;
 ulong uch  = (ulong) ch;
 ulong topbit = BITMASK(p_cm->cm_width-1);
 
  
 if (p_cm->cm_refin) uch = reflect(uch,8);
 p_cm->cm_reg ^= (uch << (p_cm->cm_width-8));
 for (i=0; i<8; i++)
   {
    if (p_cm->cm_reg & topbit)
       p_cm->cm_reg = (p_cm->cm_reg << 1) ^ p_cm->cm_poly;
    else
       p_cm->cm_reg <<= 1;
    p_cm->cm_reg &= widmask(p_cm);
   }
}

/******************************************************************************/

void cm_blk (p_cm,blk_adr,blk_len)
p_cm_t   p_cm;
p_ubyte_ blk_adr;
ulong    blk_len;
{
 while (blk_len--) cm_nxt(p_cm,*blk_adr++);
}

/******************************************************************************/

ulong cm_crc (p_cm)
p_cm_t p_cm;
{
 if (p_cm->cm_refot)
    return p_cm->cm_xorot ^ reflect(p_cm->cm_reg,p_cm->cm_width);
 else
    return p_cm->cm_xorot ^ p_cm->cm_reg;
}


/******************************************************************************/
/*                             End of crcmodel.c                              */
/******************************************************************************/

void crc16(p_cm_t crc_context, unsigned char const *buff, unsigned int size)
{
    while(size > 0)
    {
        cm_nxt(crc_context, *buff++);
        size--;
    }   
}


#ifdef TEST_CRC

main()
{
    cm_t TestCRC;

    TestCRC.cm_width = 16;
    TestCRC.cm_poly = 0x8005L;
    TestCRC.cm_init = 0x0000;
//    TestCRC.cm_init = 0xFFFF;
    TestCRC.cm_refin = TRUE;
    TestCRC.cm_refot = TRUE;
    TestCRC.cm_xorot = 0x0000;
//    TestCRC.cm_xorot = 0xFFFF;

    cm_ini(&TestCRC);
    char TestString[]="123456789";
    char *finger = NULL;
    int i = 0;
    for(i = 0; i <strlen(TestString); i++)
    {
        finger = &TestString[i];
        printf("%c-", *finger);
        cm_nxt(&TestCRC, *finger);
    }
        printf("\n");
    printf("crc: 0x%04X\n", TestCRC.cm_reg);
    printf("crc: 0x%04X\n", cm_crc(&TestCRC));
 
}

#endif
