gcc -g -O0 -Wall -Wextra -Wno-unused -o multipass-initialize multipass-initialize.c $(pkg-config --cflags --libs libfreefare libnfc libgcrypt)
gcc -g -O0 -Wall -Wextra -Wno-unused -o multipass-format multipass-format.c $(pkg-config --cflags --libs libfreefare libnfc)
gcc -g -O0 -Wall -Wextra -Wno-unused -o multipass-verify multipass-verify.c $(pkg-config --cflags --libs libfreefare libnfc)

