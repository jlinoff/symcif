# This is the where to find the openssl headers and libraries.
RTF_DIR ?= /Users/jlinoff/work/openssl/openssl-1.1.0c/rtf

define hdr
	@echo
	@echo "# ========================================================================"
	@echo "# $1"
	@echo "# ========================================================================"
endef

# Build the optimized version by default.
all: symcif.exe

# Debug version.
dbg: symcif.dbg

# Clean.
clean:
	find . -type f -name '*~' -delete
	rm -f symcif.exe symcif.dbg test*

# Compile/link an exe file from a c source file in opt mode.
%.exe : %.c
	$(CC) -std=c99 -o $@ -Wall -O2 $< -I$(RTF_DIR)/include $(RTF_DIR)/lib/libcrypto.a $(RTF_DIR)/lib/libssl.a -lpthread -ldl

# Compile/link an exe file from a c source file in debug mode.
%.dbg : %.c
	$(CC) -std=c99 -o $@ -Wall -g -pg $< -I$(RTF_DIR)/include $(RTF_DIR)/lib/libcrypto.a $(RTF_DIR)/lib/libssl.a -lpthread -ldl

# Test stuff.
test: test01 test02 test03 test04 test05
	$(call hdr,"done")

test01: ./symcif.exe text
	$(call hdr,$@)
	./symcif.exe -c aes-256-cbc -m sha256 -s feedbead -k 12345 -i text -a -e | \
		./symcif.exe -c aes-256-cbc -m sha256 -k 12345 -a -d

test02: ./symcif.exe text
	$(call hdr,$@)
	./symcif.exe -c aes-256-cbc -m sha1 -s feedbead -k 12345 -i text -a -e | \
		./symcif.exe -c aes-256-cbc -m sha1 -k 12345 -a -d

test03: ./symcif.exe text
	$(call hdr,$@)
	cat text
	wc text
	sum text
	./symcif.exe -c aes-256-cbc -m sha1 -s feedbead -k 12345 -i text -a -e -o $@.enc
	cat $@.enc
	./symcif.exe -c aes-256-cbc -m sha1 -k 12345 -i $@.enc -a -d -o $@.dec
	cat $@.dec
	wc $@.dec
	sum $@.dec
	diff text $@.dec
	rm -f $@.dec $@.enc

test04: ./symcif.exe text
	$(call hdr,$@)
	./symcif.exe -l

test05: ./symcif.exe text
	$(call hdr,$@)
	./symcif.exe -c aes-256-cbc -m sha1 -s feedbead -k 12345 -i text -a -e -v
