1.Extra Library
PBC library and GMP library.

2.Compile the code
(1) gcc ibe_basic_ident.c sha1.c utils.c -o basic_ident -I /usr/local/include/ -I /usr/local/include/pbc/ -L /usr/local/lib/ -Wl,-rpath /usr/local/lib -l pbc -l gmp

(2) gcc ibe_full_ident.c sha1.c utils.c -o full_ident -I /usr/local/include/ -I /usr/local/include/pbc/ -L /usr/local/lib/ -Wl,-rpath /usr/local/lib -l pbc -l gmp

