
/*****************************************************************************
 * Constants for c-base identity app                                         *
 *****************************************************************************/

/* Mifare AID */
#define CBID_APP  0x00637270

#define CBID_NUMKEYS 2

/* Key identifiers */
#define CBID_KID_MASTER 0
#define CBID_KID_SHARED 1

/* File numbers */
#define CBID_FNO_ORGANIZATION 0x00
#define CBID_FNO_DESCRIPTION 0x01
#define CBID_FNO_MEMBER_UID 0x02
#define CBID_FNO_MEMBER_NAME 0x03
#define CBID_FNO_CARD_UID 0x10

/* Configuration constants */
#define CBID_ORGANIZATION "c-base e.V."
#define CBID_DESCRIPTION  "member id"

/*****************************************************************************
 * Constants for NDEF mapping version 2                                      *
 *****************************************************************************/

/* Mifare AID */
#define NDEF_APP 0x00000001
/* ISO7616 AID */
#define NDEF_AID { 0xd2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01 }

#define NDEF_NUMKEYS 2

/* Key identifiers */
#define NDEF_KID_MASTER 0
#define NDEF_KID_SHARED 1

/* File numbers */
#define NDEF_FNO_CC   0x01
#define NDEF_FNO_DATA 0x02

/* ISO file identifiers */
#define NDEF_FID_APP  0xE110
#define NDEF_FID_CC   0xE103
#define NDEF_FID_DATA 0xE104

/* Configuration constants */
#define NDEF_MAXDATA 256
