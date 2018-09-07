all:
	cd c-secp256k1 && ./autogen.sh && ./configure && make clean && make -j4
	if grep -q lgmp Makefile; then sed -i.bak "/LDFLAGS/{s/$$/ -lgmp/;}" secp256k1.go; fi 

test:
	go test

clean:
	cd c-secp256k1 && make clean
	mv secp256k1.go.bak secp256k1.go 
