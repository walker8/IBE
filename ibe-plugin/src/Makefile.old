objects = ibe_full_ident.o sha1.o utils.o
full_ident: $(objects)
	gcc -o full_ident $(objects) -L /usr/local/lib -Wl,-rpath /usr/local/lib -l gmp -l pbc

ibe_full_ident.o: ibe_full_ident.c ibe_full_ident.h utils.h sha1.h
	gcc -c ibe_full_ident.c -I /usr/local/include -I /usr/local/include/pbc/

sha1.o: sha1.h sha1.c
	gcc -c sha1.c

utils.o: utils.h utils.c sha1.h
	gcc -c utils.c

.PHONY: clean
clean:
	-rm full_ident $(objects)
