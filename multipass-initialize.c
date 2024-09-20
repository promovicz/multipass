
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <gcrypt.h>

#undef WITH_DEBUG
#include <freefare.h>

#define MAX_DEVICES 32

#define NEED_LIBGCRYPT_VERSION "1.10.1"

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

/*****************************************************************************
 * Globals                                                                   *
 *****************************************************************************/

/* AID objects */
MifareDESFireAID aid_cbid;
MifareDESFireAID aid_ndef;

/* Default keys (all zero) */
MifareDESFireKey key_default_des;
MifareDESFireKey key_default_aes;

/* Actual keys */
MifareDESFireKey key_card_master;
MifareDESFireKey key_cbid_master;
MifareDESFireKey key_cbid_shared;
MifareDESFireKey key_ndef_master;
MifareDESFireKey key_ndef_shared;

/*****************************************************************************
 * Shared functions                                                          *
 *****************************************************************************/

/* Select and authenticate to an application */
int multipass_authselect(FreefareTag tag, MifareDESFireAID aid, uint8_t kid, MifareDESFireKey key) {
  int res;

  /* Select the application */
  res = mifare_desfire_select_application(tag, aid);
  if(res<0) {
    fprintf(stderr, "Error: failed to select\n");
    return -1;
  }

  /* Authenticate using given key */
  res = mifare_desfire_authenticate_aes(tag, kid, key);
  if(res<0) {
    fprintf(stderr, "Error: failed to authenticate\n");
    return -1;
  }

  /* Done */
  return 0;
}

/* Select and authenticate to the master application */
int multipass_authselect_master(FreefareTag tag, MifareDESFireKey key) {
  return multipass_authselect(tag, NULL, 0, key);
}

/* Create and write a simple file */
int multipass_create_simple_file(FreefareTag tag, uint8_t fno, uint8_t fcm, uint16_t far, size_t maxlen, const char *buf, size_t len) {
  int res;

  /* Create the file */
  res = mifare_desfire_create_std_data_file(tag, fno, fcm, far, len);
  if(res<0) {
    fprintf(stderr, "Error: failed to create simple file %02x\n", fno);
    freefare_perror(tag, "create_std_data_file");
    return -1;
  }

  /* Write contents */
  res = mifare_desfire_write_data(tag, fno, 0, len, buf);
  if(res<0) {
    fprintf(stderr, "Error: failed to write simple file %02x\n", fno);
    freefare_perror(tag, "write_data");
    return -1;
  }

  /* Done */
  return 0;
}

int multipass_create_simple_string(FreefareTag tag, uint8_t fno, uint8_t fcm, uint16_t far, size_t maxlen, const char *str) {
  int res;
  size_t len;

  /* Check size */
  len = strlen(str);
  if(len>maxlen) {
    return -1;
  }

  /* Create the file */
  res = multipass_create_simple_file(tag, fno, fcm, far, maxlen, str, len);
  if(res<0) {
    return -1;
  }

  /* Done */
  return 0;
}

/*****************************************************************************
 * Provisioning functions                                                    *
 *****************************************************************************/

/* Verify that the card is blank */
int multipass_card_verify_blank(FreefareTag tag) {
  int res;

  /* Select master */
  res = mifare_desfire_select_application(tag, NULL);
  if(res<0) {
    fprintf(stderr, "Error: failed to select master\n");
    return -1;
  }

  /* Authenticate using default key */
  res = mifare_desfire_authenticate(tag, 0, key_default_des);
  if(res<0) {
    fprintf(stderr, "Error: failed to authenticate using default key\n");
    return -1;
  }

  /* Check applications */
  MifareDESFireAID *aids;
  size_t aidcount;
   res = mifare_desfire_get_application_ids(tag, &aids, &aidcount);
  if(res<0) {
    fprintf(stderr, "Error: could not list applications\n");
    return -1;
  }
  if(aidcount>0) {
    fprintf(stderr, "Error: there are applications on the card\n");
    return -1;
  }

  /* Done */
  return 0;
}

/* Configure card/master application */
int multipass_card_configure(FreefareTag tag) {
  int res;

  uint8_t settings = MDMK_SETTINGS(1/*CMK settings not frozen*/,
				   0/*CMK required for create/delete*/,
				   0/*CMK required for listing*/,
				   1/*CMK not frozen*/);

  /* Select master */
  res = mifare_desfire_select_application(tag, NULL);
  if(res<0) {
    fprintf(stderr, "Error: failed to select master\n");
    return -1;
  }

  /* Authenticate using default key */
  res = mifare_desfire_authenticate(tag, 0, key_default_des);
  if(res<0) {
    fprintf(stderr, "Error: failed to authenticate using default key\n");
    return -1;
  }

  /* Change master key settings */
  res = mifare_desfire_change_key_settings(tag, settings);
  if(res<0) {
    fprintf(stderr, "Error: failed to change master key settings\n");
    return -1;
  }

  /* Done */
  return 0;
}

/* Verify card/master application */
int multipass_card_verify_configured(FreefareTag tag) {
  int res;

  uint16_t settings = 0x09;

  /* Select master */
  res = mifare_desfire_select_application(tag, NULL);
  if(res<0) {
    fprintf(stderr, "Error: failed to select master\n");
    return -1;
  }

  /* Authenticate using default key */
  res = mifare_desfire_authenticate(tag, 0, key_default_des);
  if(res<0) {
    fprintf(stderr, "Error: failed to authenticate using default key\n");
    return -1;
  }

  /* Verify master settings */
  uint8_t vsettings, vnumkeys;
  res = mifare_desfire_get_key_settings(tag, &vsettings, &vnumkeys);
  if(res<0) {
    fprintf(stderr, "Error: failed to read master settings\n");
    return -1;
  }
  if(vsettings != settings) {
    fprintf(stderr, "Error: wrong master settings\n");
    return -1;
  }
  if(vnumkeys != 1) {
    fprintf(stderr, "Error: wrong number of keys\n");
    return -1;
  }

  return 0;
}

/* Finalize card/master application */
int multipass_card_finalize(FreefareTag tag, MifareDESFireKey cmk) {
  int res;

  /* Select master */
  res = mifare_desfire_select_application(tag, NULL);
  if(res<0) {
    fprintf(stderr, "Error: failed to select master\n");
    return -1;
  }

  /* Authenticate using default key */
  res = mifare_desfire_authenticate(tag, 0, key_default_des);
  if(res<0) {
    fprintf(stderr, "Error: failed to authenticate using default key\n");
    return -1;
  }

  /* Set master key */
  res = mifare_desfire_change_key(tag, 0, cmk, NULL);
  if(res<0) {
    fprintf(stderr, "Error: failed to change CMK\n");
    freefare_perror(tag, "change_ask");
    return -1;
  }

  return 0;
}

/* Verify card/master application */
int multipass_card_verify_finalized(FreefareTag tag) {
  int res;
  return 0;
}

/* Create c-base identity application */
int multipass_create_cbid(FreefareTag tag, MifareDESFireKey amk, MifareDESFireKey ask,
			  const char *member_uid, const char *card_uid) {
  int res;

  uint8_t settings = MDAPP_SETTINGS(0/*AMK required for key change*/,
				    1/*CFG not frozen*/,
				    0/*AMK required for create/delete*/,
				    0/*AMK required for listing */,
				    1/*AMK not frozen*/);
  uint16_t access_public = MDAR(MDAR_FREE/*read*/,
				MDAR_KEY0/*write*/,
				MDAR_KEY0/*read-write*/,
				MDAR_KEY0/*change*/);
  uint16_t access_private = MDAR(MDAR_KEY1/*read*/,
				 MDAR_KEY0/*write*/,
				 MDAR_KEY0/*read-write*/,
				 MDAR_KEY0/*change*/);

  /* Select and authenticate to master */
  res = mifare_desfire_select_application(tag, NULL);
  if(res<0) {
    fprintf(stderr, "Error: failed to select master\n");
    return -1;
  }
  res = mifare_desfire_authenticate(tag, 0, key_default_des);
  if(res<0) {
    fprintf(stderr, "Error: failed to authenticate to master\n");
    return -1;
  }

  /* Create CBID application */
  res = mifare_desfire_create_application_aes(tag, aid_cbid, settings, CBID_NUMKEYS);
  if(res<0) {
    fprintf(stderr, "Error: failed to create CBID application\n");
    return -1;
  }

  /* Select and authenticate using default AMK */
  res = mifare_desfire_select_application(tag, aid_cbid);
  if(res<0) {
    fprintf(stderr, "Error: failed to select application\n");
    return -1;
  }
  res = mifare_desfire_authenticate_aes(tag, 0, key_default_aes);
  if(res<0) {
    fprintf(stderr, "Error: failed to authenticate to application using default key\n");
    return -1;
  }

  /* Create organization file */
  res = multipass_create_simple_string(tag, CBID_FNO_ORGANIZATION, MDCM_PLAIN, access_public, 16, CBID_ORGANIZATION);
  if(res<0) {
    fprintf(stderr, "Error: failed to create organization tag\n");
    return -1;
  }

  /* Create description file */
  res = multipass_create_simple_string(tag, CBID_FNO_DESCRIPTION, MDCM_PLAIN, access_public, 16, CBID_DESCRIPTION);
  if(res<0) {
    fprintf(stderr, "Error: failed to create description tag\n");
    return -1;
  }

  /* Create member uid file */
  res = multipass_create_simple_string(tag, CBID_FNO_MEMBER_UID, MDCM_ENCIPHERED, access_private, 32, member_uid);
  if(res<0) {
    fprintf(stderr, "Error: failed to create member uid\n");
    return -1;
  }

  /* Create card uid file */
  res = multipass_create_simple_string(tag, CBID_FNO_CARD_UID, MDCM_ENCIPHERED, access_private, 32, card_uid);
  if(res<0) {
    fprintf(stderr, "Error: failed to create member uid\n");
    return -1;
  }

  /* Change ASK */
  res = mifare_desfire_change_key(tag, CBID_KID_SHARED, ask, key_default_aes);
  if(res<0) {
    fprintf(stderr, "Error: failed to change ASK\n");
    freefare_perror(tag, "change_ask");
    return -1;
  }

  /* Change AMK */
  res = mifare_desfire_change_key(tag, CBID_KID_MASTER, amk, NULL);
  if(res<0) {
    fprintf(stderr, "Error: failed to change AMK\n");
    return -1;
  }

  /* Done */
  return 0;
}

int multipass_verify_cbid(FreefareTag tag,
			  MifareDESFireKey amk, MifareDESFireKey ask) {
  int res;

  uint8_t settings = 0x09;

  /* Authenticate using ASK */
  res = multipass_authselect(tag, aid_cbid, CBID_KID_SHARED, ask);
  if(res<0) {
    fprintf(stderr, "Error: failed to authenticate using ASK\n");
    return -1;
  }

  /* Authenticate using AMK */
  res = multipass_authselect(tag, aid_cbid, CBID_KID_MASTER, amk);
  if(res<0) {
    fprintf(stderr, "Error: failed to authenticate using AMK\n");
    return -1;
  }

  /* Verify app settings */
  uint8_t vsettings, vnumkeys;
  res = mifare_desfire_get_key_settings(tag, &vsettings, &vnumkeys);
  if(res<0) {
    fprintf(stderr, "Error: failed to read app settings\n");
    return -1;
  }
  if(vsettings != settings) {
    fprintf(stderr, "Error: wrong app settings\n");
    return -1;
  }
  if(vnumkeys != CBID_NUMKEYS) {
    fprintf(stderr, "Error: wrong number of keys\n");
    return -1;
  }

  /* Verify key versions */
  uint8_t vversion;
  res = mifare_desfire_get_key_version(tag, CBID_KID_MASTER, &vversion);
  if(res<0) {
    fprintf(stderr, "Error: failed to read AMK version\n");
    return -1;
  }
  if(vversion != mifare_desfire_key_get_version(amk)) {
    fprintf(stderr, "Error: wrong AMK version\n");
    return -1;
  }
  res = mifare_desfire_get_key_version(tag, CBID_KID_SHARED, &vversion);
  if(res<0) {
    fprintf(stderr, "Error: failed to read ASK version\n");
    return -1;
  }
  if(vversion != mifare_desfire_key_get_version(ask)) {
    fprintf(stderr, "Error: wrong ASK version\n");
    return -1;
  }

  /* Done */
  return 0;
}

/* Create NDEF application */
int multipass_create_ndef(FreefareTag tag, MifareDESFireKey cmk, MifareDESFireKey amk, MifareDESFireKey ask, size_t maxdata) {
  int res;

  uint8_t settings = MDAPP_SETTINGS(0/*AMK required for key change*/,
				    1/*CFG not frozen*/,
				    0/*AMK required for create/delete*/,
				    1/*AMK not required for listing */,
				    1/*AMK not frozen*/);
  uint16_t access_cc = MDAR(MDAR_FREE,MDAR_DENY,MDAR_KEY0,MDAR_KEY0);
  uint16_t access_data = MDAR(MDAR_FREE,MDAR_KEY1,MDAR_KEY0,MDAR_KEY0);

  uint8_t ccdata[15] = {
    0x00, 0x0F,                 // CCLEN: Size of this capability container.CCLEN values are between 000Fh and FFFEh
    0x20,                       // Mapping version
    0x00, 0x3B,                 // MLe: Maximum data size that can be read using a single ReadBinary command. MLe = 000Fh-FFFFh
    0x00, 0x34,                 // MLc: Maximum data size that can be sent using a single UpdateBinary command. MLc = 0001h-FFFFh
    0x04, 0x06,                 // T & L of NDEF File Control TLV, followed by 6 bytes of V:
    0xE1, 0x04,                 //   File Identifier of NDEF File
    0x04, 0x00,                 //   Maximum NDEF File size of 1024 bytes (will be patched below)
    0x00,                       //   free read access
    0x80                        //   proprietary write acces
  };

  /* Patch size into ccdata */
  ccdata[11] = maxdata >> 8;
  ccdata[12] = maxdata & 0xFF;

  /* Authenticate to master */
  res = multipass_authselect_master(tag, cmk);
  if(res<0) {
    fprintf(stderr, "Error: failed to authenticate to master\n");
    return -1;
  }

  /* Create NDEF application */
  uint8_t isoaid[] = NDEF_AID;
  res = mifare_desfire_create_application_aes_iso(tag, aid_ndef, settings, NDEF_NUMKEYS, 0, NDEF_FID_APP, isoaid, sizeof(isoaid));
  if(res<0) {
    fprintf(stderr, "Error: failed to create NDEF application\n");
    return -1;
  }

  /* Authenticate using default AMK */
  res = multipass_authselect(tag, aid_ndef, NDEF_KID_MASTER, key_default_aes);
  if(res<0) {
    fprintf(stderr, "Error: failed to authenticate using default AMK\n");
    return -1;
  }

#if 0
  /* Create and write CC */
  res = mifare_desfire_create_std_data_file_iso(tag, NDEF_FNO_CC, MDCM_PLAIN, access_cc, 16, NDEF_FID_CC);
  if(res<0) {
    fprintf(stderr, "Error: failed to create CC\n");
    freefare_perror(tag, "X");
    return -1;
  }

  /* Create DATA file */
  res = mifare_desfire_create_std_data_file_iso(tag, NDEF_FNO_DATA, MDCM_PLAIN, access_data, maxdata, NDEF_FID_DATA);
  if(res<0) {
    fprintf(stderr, "Error: failed to create DATA\n");
    freefare_perror(tag, "Y");
    return -1;
  }
#endif

  /* Change ASK */
  res = mifare_desfire_change_key(tag, CBID_KID_SHARED, ask, key_default_aes);
  if(res<0) {
    fprintf(stderr, "Error: failed to change ASK\n");
    return -1;
  }

  /* Change AMK */
  res = mifare_desfire_change_key(tag, CBID_KID_MASTER, amk, NULL);
  if(res<0) {
    fprintf(stderr, "Error: failed to change AMK\n");
    return -1;
  }

  /* Done */
  return 0;
}


int multipass_verify_ndef(FreefareTag tag,
			  MifareDESFireKey amk, MifareDESFireKey ask,
			  size_t maxdata) {
  int res;

  uint8_t settings = 0x0b;

  /* Authenticate using ASK */
  res = multipass_authselect(tag, aid_ndef, NDEF_KID_SHARED, ask);
  if(res<0) {
    fprintf(stderr, "Error: failed to authenticate using ASK\n");
    return -1;
  }

  /* Authenticate using AMK */
  res = multipass_authselect(tag, aid_ndef, NDEF_KID_MASTER, amk);
  if(res<0) {
    fprintf(stderr, "Error: failed to authenticate using AMK\n");
    return -1;
  }

  /* Verify app settings */
  uint8_t vsettings, vnumkeys;
  res = mifare_desfire_get_key_settings(tag, &vsettings, &vnumkeys);
  if(res<0) {
    fprintf(stderr, "Error: failed to read app settings\n");
    return -1;
  }
  if(vsettings != settings) {
    fprintf(stderr, "Error: wrong app settings\n");
    return -1;
  }
  if(vnumkeys != NDEF_NUMKEYS) {
    fprintf(stderr, "Error: wrong number of keys\n");
    return -1;
  }

  /* Verify key versions */
  uint8_t vversion;
  res = mifare_desfire_get_key_version(tag, CBID_KID_MASTER, &vversion);
  if(res<0) {
    fprintf(stderr, "Error: failed to read AMK version\n");
    return -1;
  }
  if(vversion != mifare_desfire_key_get_version(amk)) {
    fprintf(stderr, "Error: wrong AMK version\n");
    return -1;
  }
  res = mifare_desfire_get_key_version(tag, CBID_KID_SHARED, &vversion);
  if(res<0) {
    fprintf(stderr, "Error: failed to read ASK version\n");
    return -1;
  }
  if(vversion != mifare_desfire_key_get_version(ask)) {
    fprintf(stderr, "Error: wrong ASK version\n");
    return -1;
  }

  /* Done */
  return 0;
}

int util_read_file(const char *path, uint8_t *buf, size_t len) {
  int res;
  struct stat st;
  FILE *fs;
  size_t done;

  /* Check file size */
  res = stat(path,&st);
  if(res<0) {
    fprintf(stderr,"Error: failed to read file %s\n", path);
    perror("stat");
    return -1;
  }
  if(st.st_size!=(off_t)len) {
    fprintf(stderr,"Error: file %s should be %zu bytes in size\n",path,len);
    return -1;
  }

  /* Open */
  fs = fopen(path, "r");
  if(!fs) {
    fprintf(stderr,"Error: could not open file %s\n",path);
    return -1;
  }

  /* Read */
  done = fread(buf,1,len,fs);
  if(done!=len) {
    fprintf(stderr,"Error: could not read file %s\n",path);
    return -1;
  }

  /* Close */
  fclose(fs);

  /* Done */
  return 0;
}

int util_write_file(const char *path, const uint8_t *buf, size_t len) {
  int res;
  struct stat st;
  FILE *fs;
  size_t done;

  /* Check file size */
  res = stat(path,&st);
  if(res==0) {
    fprintf(stderr,"Error: file %s exists already\n", path);
    return -1;
  }

  /* Open */
  fs = fopen(path, "w");
  if(!fs) {
    fprintf(stderr,"Error: could not open file %s\n",path);
    return -1;
  }

  /* Read */
  done = fwrite((void*)buf,1,len,fs);
  if(done!=len) {
    fprintf(stderr,"Error: could not write file %s\n",path);
    return -1;
  }

  /* Close */
  fclose(fs);

  /* Done */
  return 0;
}

int main(int argc, char **argv) {
  nfc_context *nctx;
  nfc_device  *ndev;
  nfc_target  *ntgt;
  size_t ndevcount;
  nfc_connstring ndevs[MAX_DEVICES];
  FreefareTag *tags;
  int res, i, j;
  char fn[1024];

  /* Initialize gcrypt */
  if (!gcry_check_version (NEED_LIBGCRYPT_VERSION)) {
    fprintf (stderr, "libgcrypt is too old (need %s, have %s)\n",
             NEED_LIBGCRYPT_VERSION, gcry_check_version (NULL));
    exit (1);
  }
  gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
  if (!gcry_control (GCRYCTL_INITIALIZATION_FINISHED_P)) {
    fputs ("libgcrypt has not been initialized\n", stderr);
    abort ();
  }

  /* Initialize libnfc */
  nfc_init(&nctx);
  if(!nctx) {
    fprintf(stderr, "Error: could not initialize libnfc\n");
    exit(1);
  }

  /* Lock all memory */
  res = mlockall(MCL_FUTURE);
  if(res<0) {
    fprintf(stderr, "Error: could not lock memory\n");
    exit(1);
  }

  /* Create AID objects */
  uint8_t ndefaid[] = NDEF_AID;
  aid_cbid = mifare_desfire_aid_new(CBID_APP);
  aid_ndef = mifare_desfire_aid_new(NDEF_APP);

  /* Create default keys */
  const uint8_t defkey64[8] = {0,0,0,0,0,0,0,0};
  const uint8_t defkey128[16] = {0,0,0,0,0,0,0,0,
				 0,0,0,0,0,0,0,0};
  key_default_des = mifare_desfire_des_key_new_with_version(defkey64);
  key_default_aes = mifare_desfire_aes_key_new_with_version(defkey128, 0);

  /* Read shared keys */
  uint8_t shared_cbid[16];
  uint8_t shared_ndef[16];
  snprintf(fn, sizeof(fn),"keys/common/cbid-ask-1.bin");
  res = util_read_file(fn,shared_cbid,sizeof(shared_cbid));
  if(res<0) {
    fprintf(stderr, "Error: could not read CBID ASK\n");
    exit(1);
  }
  snprintf(fn, sizeof(fn),"keys/common/ndef-ask-1.bin");
  res = util_read_file(fn,shared_ndef,sizeof(shared_ndef));
  if(res<0) {
    fprintf(stderr, "Error: could not read NDEF ASK\n");
    exit(1);
  }
  key_cbid_shared = mifare_desfire_aes_key_new_with_version(shared_cbid,1);
  key_ndef_shared = mifare_desfire_aes_key_new_with_version(shared_ndef,1);

  /* List NFC devices/interfaces */
  ndevcount = nfc_list_devices(nctx, ndevs, MAX_DEVICES);
  if(ndevcount <= 0) {
    fprintf(stderr, "Error: no NFC device\n");
    exit(1);
  }

  /* Iterate NFC devices */
  for(i=0; i<(int)ndevcount; i++) {
    /* Open one device */
    ndev = nfc_open(nctx, ndevs[i]);
    /* List tags seen by device */
    tags = freefare_get_tags(ndev);
    /* Iterate tags, if any */
    if(tags) {
      for(j=0; tags[j]; j++) {
	FreefareTag tag = tags[j];
	/* Check tag type, skip unsupported tags */
	if(freefare_get_tag_type(tag)!=MIFARE_DESFIRE) {
	  continue;
	}
	/* Try opening the tag, skip on error */
	char *uid = freefare_get_tag_uid(tag);
	res = mifare_desfire_connect(tag);
	if(res<0) {
	  fprintf(stderr, "Error: could not connect mifare target\n");
	  continue;
	}
	/* Check version of the tag, skip on wrong version */
	struct mifare_desfire_version_info version;
	res = mifare_desfire_get_version(tag, &version);
	if(res<0) {
	  fprintf(stderr, "Error: could not get mifare version\n");
	  continue;
	}
	if(version.software.version_major!=2) {
	  fprintf(stderr, "Error: wrong mifare version\n");
	  continue;
	}
	/* Say something */
	fprintf(stderr, "Found mifare with UID %s and version %d.%d...\n", uid,
		version.software.version_major,
		version.software.version_minor);
	/* Verify that we have a blank card, abort if not blank */
	fprintf(stderr, "  Verifying that card is blank...");
	res = multipass_card_verify_blank(tag);
	if(res<0) {
	  fprintf(stderr, "Error: card is not blank, formatting advised\n");
	  break;
	}
	fprintf(stderr, "okay.\n");

        /* Generate card-specific keys */
        fprintf(stderr, "  Generating keys...");
        uint8_t *private_card = gcry_random_bytes_secure(16,GCRY_VERY_STRONG_RANDOM);
        uint8_t *private_cbid = gcry_random_bytes_secure(16,GCRY_VERY_STRONG_RANDOM);
        uint8_t *private_ndef = gcry_random_bytes_secure(16,GCRY_VERY_STRONG_RANDOM);
        key_card_master = mifare_desfire_aes_key_new_with_version(private_card,1);
        key_cbid_master = mifare_desfire_aes_key_new_with_version(private_cbid,1);
        key_ndef_master = mifare_desfire_aes_key_new_with_version(private_ndef,1);
        fprintf(stderr, "okay.\n");
        /* Write keys, before changing the card */
        fprintf(stderr, "  Saving keys...");
        snprintf(fn, sizeof(fn),"keys/card-%s",uid);
        res = mkdir(fn,0700);
        if(res<0) {
	  fprintf(stderr, "Error: failed to create directory %s\n", fn);
          perror("mkdir");
	  break;
        }
        snprintf(fn, sizeof(fn),"keys/card-%s/card-cmk-1.bin",uid);
        res = util_write_file(fn,private_card,16);
        if(res<0) {
	  fprintf(stderr, "Error: failed to write file %s\n", fn);
          break;
        }
        snprintf(fn, sizeof(fn),"keys/card-%s/cbid-amk-1.bin",uid);
        res = util_write_file(fn,private_cbid,16);
        if(res<0) {
	  fprintf(stderr, "Error: failed to write file %s\n", fn);
          break;
        }
        snprintf(fn, sizeof(fn),"keys/card-%s/ndef-amk-1.bin",uid);
        res = util_write_file(fn,private_ndef,16);
        if(res<0) {
	  fprintf(stderr, "Error: failed to write file %s\n", fn);
          break;
        }
        fprintf(stderr, "okay.\n");
        /* Free key buffers */
        gcry_free(private_card);
        gcry_free(private_cbid);
        gcry_free(private_ndef);
	/* Configure the card */
	fprintf(stderr, "  Configuring card...");
	res = multipass_card_configure(tag);
	if(res<0) {
	  fprintf(stderr, "Error: failed to change card configuration\n");
	  break;
	}
	fprintf(stderr, "okay.\n");
	/* Verify card configuration */
	fprintf(stderr, "  Verifying card...");
	res = multipass_card_verify_configured(tag);
	if(res<0) {
	  fprintf(stderr, "Error: failed to verify card configuration\n");
	  break;
	}
	fprintf(stderr, "okay.\n");
	/* Create CBID application */
	fprintf(stderr, "  Creating CBID application...");
	res = multipass_create_cbid(tag, key_cbid_master, key_cbid_shared,
				    "00000000", uid);
	if(res<0) {
	  fprintf(stderr, "Error: failed to create CBID application\n");
	  break;
	}
	fprintf(stderr, "okay.\n");
	/* Verify CBID application */
	fprintf(stderr, "  Verifying CBID application...");
	res = multipass_verify_cbid(tag, key_cbid_master, key_cbid_shared);
	if(res<0) {
	  fprintf(stderr, "Error: failed to verify CBID application\n");
	  break;
	}
	fprintf(stderr, "okay.\n");
#if 0
	/* Create NDEF application */
	fprintf(stderr, "  Creating NDEF application...");
	res = multipass_create_ndef(tag, key_card_master, key_ndef_master, key_ndef_shared, NDEF_MAXDATA);
	if(res<0) {
	  fprintf(stderr, "Error: failed to create NDEF application\n");
	  break;
	}
	fprintf(stderr, "okay.\n");
	/* Verify NDEF application */
	fprintf(stderr, "  Verifying NDEF application...");
	res = multipass_verify_ndef(tag, key_ndef_master, key_ndef_shared, NDEF_MAXDATA);
	if(res<0) {
	  fprintf(stderr, "Error: failed to verify NDEF application\n");
	  break;
	}
#endif
	fprintf(stderr, "okay.\n");
	/* Done with one card, so we are finished*/
	break;
      }
      /* Done processing tags, free the list */
      freefare_free_tags(tags);
    }
    /* Close the device */
    nfc_close(ndev);
  }
  /* Done */
  return 0;
}
