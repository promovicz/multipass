gcc -g -O0 -Wall -Wextra -Wno-unused -o multipass-initialize multipass-initialize.c $(pkg-config --cflags --libs libfreefare libnfc libgcrypt)
