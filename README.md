# symcif
C program that demonstrates how to interface to the openssl library to encrypt or decrypt data.

You can also list the available ciphers and digests.

The name symcif derives loosely from symmetric cipher.

It is of no practical use since these functions are already
available from the command line openssl tool but it might be useful
for learning purposes.

## Compiling and linking
Compiling and linking will vary by platform. I did not spend any
time on it because the goal was to understand the idioms so you
may run into issues on different platforms.

I have compiled and linked it on Mac OS X and CentOS 7.2 linux using
the openssl-1.1.0c library just released.

## License

I am not sure how to license this. None of the code was taken
directly from the openssl source but it has similarities because I
read it carefully to understand how to use the system. That is
especially true for BIO idioms so I have decided to preserve the
license of the original software which is quite reasonable.

Copyright 2016 Joe Linoff. All Rights Reserved.

Licensed under the OpenSSL license (the "License"). You may not use
this file except in compliance with the License. You can obtain a copy
in the file LICENSE in the source distribution or at
https://www.openssl.org/source/license.html

## Help
This is the program help.
```bash

USAGE
    symcif.exe [OPTIONS]

DESCRIPTION
    Encrypts or decrypts a file using the openssl library.

OPTIONS
    -a, --ascii        Output ASCII, convert to base64.

    -c CIPHER, --cipher CIPHER
                       The cipher algorithm. The default is aes-256-cbc.

    -d DIGEST, --digest DIGEST
                       The digest algorithm. The default is sha256.

    -h, --help         This help message.

    -i FILE, --input FILE
                       The input file name. Default is stdin.

    -m DIGEST, --message-digest DIGEST, --digest DIGEST
                       Specify the message digest to use. The default is sha256.
                       See the --list output for the available message digests.

    -o FILE, --output FILE
                       The output file name. Default is stdout.

    -p PASS, --pass PASS, -k PASS
                       Passphrase. Added -k (key) for openssl compatibility.
                       If this is not specified, you will be prompted.

    -r ROUNDS, --rounds ROUNDS
                       Number of rounds. Default is 1.

    -s SALT, --salt SALT
                       8 character salt used for encryption only.
                       The decryption algorithm figures out the correct salt but
                       you can specify it manually. If you do specify it manually
                       it must match the salt used for encryption.

    -v, --verbose      Increase the level of verbosity.

    -V, --version      Print the program version and exit.

EXAMPLES
    # Example 1. help
    $ symcif.exe -h

    # Example 2. simple encrypt/decrypt example using a pipe
    $ cat >text <<EOF
    Lorem ipsum dolor sit amet, graeco propriae volutpat eum ei, eam id
    fierent conceptam. No per choro tation. Id ipsum zril omnium duo.
    EOF
    $ symcif.exe -s feedbeef -k password -i text -a -e | \
      symcif.exe -s feedbeef -k password -a -d
    Lorem ipsum dolor sit amet, graeco propriae volutpat eum ei, eam id
    fierent conceptam. No per choro tation. Id ipsum zril omnium duo.

    # Example 3. encrypt, then decrypt using files
    $ symcif.exe -c aes-256-cbc -m sha512 -s dadafeed -a -e -i text -o text.enc
    $ symcif.exe -c aes-256-cbc -m sha512 -s dadafeed -a -d -i text.enc -o text.dec
    $ ls text*
    text text.dec text.enc
    $ diff text text.dec

VERSION
    0.1

```
