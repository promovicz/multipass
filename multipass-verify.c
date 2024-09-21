
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <freefare.h>

#include "multipass.h"
#include "multipass-util.c"

#define MAX_DEVICES 32

/* AID objects */
MifareDESFireAID aid_cbid;
MifareDESFireAID aid_ndef;

/* Default keys (all zero) */
MifareDESFireKey key_default_des;
MifareDESFireKey key_default_aes;

/* Shared keys */
MifareDESFireKey key_cbid_shared;
MifareDESFireKey key_ndef_shared;

/* Card-specific keys */
MifareDESFireKey key_card_master;
MifareDESFireKey key_cbid_master;
MifareDESFireKey key_ndef_master;

int main(int argc, char **argv) {
  nfc_context *nctx;
  nfc_device  *ndev;
  nfc_target  *ntgt;
  size_t ndevcount;
  nfc_connstring ndevs[MAX_DEVICES];
  FreefareTag *tags;
  int res, i, j;
  char fn[1024];
  uint8_t kv;
  char member_uid[64];

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

        /* Read card-specific keys */
        fprintf(stderr,"Reading keys...");
        uint8_t secret_card[16];
        uint8_t secret_cbid[16];
        uint8_t secret_ndef[16];
        snprintf(fn, sizeof(fn),"keys/card-%s/card-cmk-1.bin",uid);
        res = util_read_file(fn,secret_card,sizeof(secret_card));
        if(res<0) {
          fprintf(stderr, "Error: could not read Card CMK\n");
          exit(1);
        }
        snprintf(fn, sizeof(fn),"keys/card-%s/cbid-amk-1.bin",uid);
        res = util_read_file(fn,secret_cbid,sizeof(secret_cbid));
        if(res<0) {
          fprintf(stderr, "Error: could not read CBID AMK\n");
          exit(1);
        }
        snprintf(fn, sizeof(fn),"keys/card-%s/ndef-amk-1.bin",uid);
        res = util_read_file(fn,secret_ndef,sizeof(secret_ndef));
        if(res<0) {
          fprintf(stderr, "Error: could not read NDEF AMK\n");
          exit(1);
        }
        key_card_master = mifare_desfire_aes_key_new_with_version(secret_card,1);
        key_cbid_master = mifare_desfire_aes_key_new_with_version(secret_cbid,1);
        key_ndef_master = mifare_desfire_aes_key_new_with_version(secret_ndef,1);
        fprintf(stderr, "done,\n");

        /* Select master */
        res = mifare_desfire_select_application(tag, NULL);
        if(res<0) {
          fprintf(stderr, "Error: failed to select master\n");
          return -1;
        }

        /* Check key version and authenticate using appropriate key */
        res = mifare_desfire_get_key_version(tag, 0, &kv);
        if(res<0) {
          fprintf(stderr, "Error: failed to get master key version\n");
          exit(1);
        }
        if(kv == 0) {
          fprintf(stderr, "Error: card has default keys\n");
          exit(1);
        } else {
          /* Read master key */
          fprintf(stderr,"Reading key for card %s version %d...", uid, kv);
          uint8_t secret[16];
          snprintf(fn, sizeof(fn),"keys/card-%s/card-cmk-%d.bin",uid,kv);
          res = util_read_file(fn,secret,sizeof(secret));
          if(res<0) {
            fprintf(stderr, "Error: could not read CMK\n");
            exit(1);
          }
          key_card_master = mifare_desfire_aes_key_new_with_version(secret,1);
          fprintf(stderr, "done.\n");
          /* Authenticate using master key */
          fprintf(stderr, "Authenticating with master key...");
          res = mifare_desfire_authenticate_aes(tag, 0, key_card_master);
        }
        if(res<0) {
          fprintf(stderr, "Error: failed to authenticate to master\n");
          return -1;
        }
        fprintf(stderr, "done.\n");

        /* Select CBID */
        res = mifare_desfire_select_application(tag, aid_cbid);
        if(res<0) {
          fprintf(stderr, "Error: failed to select CBID\n");
          return -1;
        }

        /* Authenticate using master key */
        fprintf(stderr, "Authenticating with CBID AMK...");
        res = mifare_desfire_authenticate_aes(tag, CBID_KID_MASTER, key_cbid_master);
        if(res<0) {
          fprintf(stderr, "Error: failed to authenticate using CBID AMK\n");
          return -1;
        }
        fprintf(stderr, "done.\n");

#if 0
        /* Authenticate using shared key */
        fprintf(stderr, "Authenticating with CBID ASK...");
        res = mifare_desfire_authenticate_aes(tag, CBID_KID_SHARED, key_cbid_shared);
        if(res<0) {
          fprintf(stderr, "Error: failed to authenticate using CBID ASK\n");
          return -1;
        }
        fprintf(stderr, "done.\n");
#endif

        /* Read and show member UID */
        fprintf(stderr, "Reading member UID...");
        memset(member_uid, 0, sizeof(member_uid));
        res = mifare_desfire_read_data(tag, CBID_FNO_MEMBER_UID, 0, 32, member_uid);
        if(res<0) {
          fprintf(stderr, "Error: failed to read member UID\n");
          freefare_perror(tag, "read_data");
          return -1;
        }
        fprintf(stderr, "done, uid: '%s'\n", member_uid);

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
