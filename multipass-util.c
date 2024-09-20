
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
