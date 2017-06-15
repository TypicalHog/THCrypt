# THCrypt
C++ console application that features symmetric key based file encryption.

### Some facts
-It is possible to encrypt the file with another file.

-Key can be up to 65536 characters long. (16 is more than enough though :O)

-Time complexity is linear, but every new character added to the key makes the brute-force 2^8 times harder.

-Before encryption and decryption, lookup tables are created if they are not present already. (Which is both good and bad because it makes the whole process a tiny bit faster but adds 2 extra files to the parent directory)

## Command line
Usage:

**THCrypt \<-e | -d\> \<key filename\> \<input filename\> \<output filename\>**

Encryption example:

**THCrypt -e password.txt image.jpg image-enc.jpg**

Decryption example:

**THCrypt -d password.txt image-enc.jpg image-dec.jpg**

## Drag & drop
Just simply drag the file onto the THCrypt.exe

Note: You should create key.txt file beforehand. (16 characters long key should be sufficient)

### Demo
https://goo.gl/HsVj3S

I didn't have time to test it on any other platform but Windows :/

I want to add the ability to pack multiple files/folders into 1 file and then encrypt it.

Also wanted to encrypt the file names and convert them to base64.

I'm aware there is a possibility to recover deleted key.txt file and stuff but this is just a hobby project I made for fun so I don't really care.
