
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

int main(int argc, char **argv) {
  nfc_context *nctx;
  nfc_device  *ndev;
  nfc_target  *ntgt;
  size_t ndevcount;
  nfc_connstring ndevs[MAX_DEVICES];
  FreefareTag *tags;
  int res, i, j;
  char fn[1024];
  MifareDESFireKey key_default;
  MifareDESFireKey key_master;

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

  /* Create default key */
  const uint8_t defkey[8] = {0,0,0,0,0,0,0,0};
  key_default = mifare_desfire_des_key_new_with_version(defkey);

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
        uint8_t kv;

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
          return -1;
        }
        if(kv == 0) {
          /* Authenticate using default key */
          fprintf(stderr, "Authenticating with default key...");
          res = mifare_desfire_authenticate(tag, 0, key_default);
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
          key_master = mifare_desfire_aes_key_new_with_version(secret,1);
          fprintf(stderr, "done.\n");
          /* Authenticate using master key */
          fprintf(stderr, "Authenticating with master key...");
          res = mifare_desfire_authenticate_aes(tag, 0, key_master);
        }
        if(res<0) {
          fprintf(stderr, "Error: failed to authenticate to master\n");
          return -1;
        }
        fprintf(stderr, "done.\n");

        /* Reset master key settings */
        fprintf(stderr,"Resetting master settings...");
        res = mifare_desfire_change_key_settings(tag, 0x0F);
        if(res<0) {
          fprintf(stderr, "Error: failed to reset master settings\n");
          return -1;
        }
        fprintf(stderr, "done.\n");

        /* Set default key */
        fprintf(stderr,"Resetting master key...");
        res = mifare_desfire_change_key(tag, 0, key_default, NULL);
        if(res<0) {
          fprintf(stderr, "Error: failed to reset master key\n");
          return -1;
        }
        fprintf(stderr, "done.\n");

        /* Check key version, and re-authenticate using appropriate key */
        res = mifare_desfire_get_key_version(tag, 0, &kv);
        if(res<0) {
          fprintf(stderr, "Error: failed to get key version\n");
          return -1;
        }
        if(kv == 0) {
          fprintf(stderr, "Re-authenticating with default key...");
          res = mifare_desfire_authenticate(tag, 0, key_default);
        } else {
          fprintf(stderr, "Re-authenticating with master key...");
          res = mifare_desfire_authenticate_aes(tag, 0, key_master);
        }
        if(res<0) {
          fprintf(stderr, "Error: failed to re-authenticate\n");
          return -1;
        }
        fprintf(stderr, "done.\n");

        /* Format the card */
        fprintf(stderr,"Formatting card...");
        res = mifare_desfire_format_picc(tag);
        if(res<0) {
          fprintf(stderr, "Error: failed to format card\n");
          return -1;
        }
        fprintf(stderr, "done.\n");

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
