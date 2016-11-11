# symcif
C program that demonstrates how to interface to the openssl library to encrypt or decrypt data.

You can also list the available ciphers and digests.

The name symcif derives loosely from symmetric cipher.

It is of no practical use since these functions are already
available from the command line openssl tool but it might be useful
for learning purposes.

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
