# THCrypt
C++ console application that features symmetric key based file encryption.

### Some facts
-It is possible to encrypt the file with another file.

-Key can be up to 65536 characters long. (16 is more then enough though :O)

-Time complexity is linear, but every new character added to the key makes the time needed to brute-force the file 2^8 times longer.

-Before encryption and decryption lookup tables are created if they are already not present. (Which is both good and bad because it makes the whole process a tiny bit faster but adds extra 2 files to the parent directory)


## Command line
Usage:

**THCrypt \<-e | -d\> \<key filename\> \<input filename\> \<output filename\>**

Encryption example:

**THCrypt -e password.txt image.jpg image-enc.jpg**

Decryption example:

**THCrypt -d password.txt image-enc.jpg image-dec.jpg**

## Drag & drop
Smply just drag the file onto the THCrypt.exe

Note: You should create key.txt file beforehand. (16 characters should be sufficient)

### Demo
https://goo.gl/HsVj3S
