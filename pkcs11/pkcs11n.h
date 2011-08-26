/* ***** BEGIN COPYRIGHT BLOCK ***** 
 * The contents of this file are subject to the Mozilla Public
 * License Version 1.1 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.mozilla.org/MPL/
 * 
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 * 
 * The Original Code is the Netscape security libraries.
 * 
 * The Initial Developer of the Original Code is Netscape
 * Communications Corporation.  Portions created by Netscape are 
 * Copyright (C) 1994-2000 Netscape Communications Corporation.  All
 * Rights Reserved.
 * 
 * Alternatively, the contents of this file may be used under the
 * terms of the GNU General Public License Version 2 or later (the
 * "GPL"), in which case the provisions of the GPL are applicable 
 * instead of those above.  If you wish to allow use of your 
 * version of this file only under the terms of the GPL and not to
 * allow others to use your version of this file under the MPL,
 * indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by
 * the GPL.  If you do not delete the provisions above, a recipient
 * may use your version of this file under either the MPL or the
 * GPL.
 * ***** END COPYRIGHT BLOCK *****/

#ifndef _PKCS11N_H_
#define _PKCS11N_H_

#ifdef DEBUG
static const char CKT_CVS_ID[] = "@(#) $RCSfile: pkcs11n.h,v $ $Revision: 1.1 $ $Date: 2006/06/09 18:39:11 $ $Name:  $";
#endif /* DEBUG */

/*
 * pkcs11n.h
 *
 * This file contains the NSS-specific type definitions for Cryptoki
 * (PKCS#11).
 */

/*
 * NSSCK_VENDOR_NETSCAPE
 *
 * Cryptoki reserves the high half of all the number spaces for
 * vendor-defined use.  I'd like to keep all of our Netscape-
 * specific values together, but not in the oh-so-obvious
 * 0x80000001, 0x80000002, etc. area.  So I've picked an offset,
 * and constructed values for the beginnings of our spaces.
 *
 * Note that some "historical" Netscape values don't fall within
 * this range.
 */
#define NSSCK_VENDOR_NETSCAPE 0x4E534350 /* NSCP */

/*
 * Netscape-defined object classes
 * 
 */
#define CKO_NETSCAPE (CKO_VENDOR_DEFINED|NSSCK_VENDOR_NETSCAPE)
#define CKO_NETSCAPE_TRUST              (CKO_NETSCAPE + 3)
#define CKO_MOZ_READER			(CKO_NETSCAPE + 5)

/*
 * Netscape-defined object attributes
 *
 */
#define CKA_NETSCAPE (CKA_VENDOR_DEFINED|NSSCK_VENDOR_NETSCAPE)
#define CKA_MOZ_IS_COOL_KEY          (CKA_NETSCAPE +  24)
#define CKA_MOZ_ATR                     (CKA_NETSCAPE +  25)
#define CKA_MOZ_TPS_URL                 (CKA_NETSCAPE +  26)

/*
 * Trust info
 *
 * This isn't part of the Cryptoki standard (yet), so I'm putting
 * all the definitions here.  Some of this would move to nssckt.h
 * if trust info were made part of the standard.  In view of this
 * possibility, I'm putting my (NSS) values in the NSS
 * vendor space, like everything else.
 */

typedef CK_ULONG          CK_TRUST;

/* If trust goes standard, these'll probably drop out of vendor space. */
#define CKT_VENDOR_DEFINED     0x80000000
#define CKT_NETSCAPE (CKT_VENDOR_DEFINED|NSSCK_VENDOR_NETSCAPE)

#define CK_TRUSTED            (CKT_NETSCAPE + 1)
#define CK_TRUSTED_DELEGATOR  (CKT_NETSCAPE + 2)
#define CK_MUST_VERIFY_TRUST  (CKT_NETSCAPE + 3)
#define CK_NOT_TRUSTED        (CKT_NETSCAPE + 10)
#define CK_TRUST_UNKNOWN      (CKT_NETSCAPE + 5) /* default */

#define CKA_TRUST (CKA_NETSCAPE + 0x2000)
#define CKA_TRUST_DIGITAL_SIGNATURE     (CKA_TRUST + 1)
#define CKA_TRUST_NON_REPUDIATION       (CKA_TRUST + 2)
#define CKA_TRUST_KEY_ENCIPHERMENT      (CKA_TRUST + 3)
#define CKA_TRUST_DATA_ENCIPHERMENT     (CKA_TRUST + 4)
#define CKA_TRUST_KEY_AGREEMENT         (CKA_TRUST + 5)
#define CKA_TRUST_KEY_CERT_SIGN         (CKA_TRUST + 6)
#define CKA_TRUST_CRL_SIGN              (CKA_TRUST + 7)
#define CKA_CERT_SHA1_HASH	        (CKA_TRUST + 0x64)
#define CKA_CERT_MD5_HASH		(CKA_TRUST + 0x65)

#ifndef CKA_TRUST_SERVER_AUTH
#  define CKA_TRUST_SERVER_AUTH 0xce536358
#endif
#ifndef CKA_TRUST_CLIENT_AUTH
#  define CKA_TRUST_CLIENT_AUTH 0xce536359
#endif
#ifndef CKA_TRUST_CODE_SIGNING
#  define CKA_TRUST_CODE_SIGNING 0xce53635a
#endif
#ifndef CKA_TRUST_EMAIL_PROTECTION
#  define CKA_TRUST_EMAIL_PROTECTION 0xce53635b
#endif

#endif /* _PKCS11N_H_ */
