# THCrypt
C++ console application that features unique symmetric key based file encryption algorithm.

### Some facts
-It is possible to encrypt the file with another file.

-Key can be up to 256 characters long. (16 is more than enough though :O)

-Time complexity is linear, but every new character added to the key makes the brute-force attack 256 (2^8) times harder.

-Before encryption and decryption, lookup tables are generated if they are not present already. (Which is a compromise because it makes the whole process a tiny bit faster but adds 2 extra files to the working directory)

## Command line
Usage:

**THCrypt \<-e | -d\> \<key filename\> \<input filename\> \<output filename\>**

Encryption example:

**THCrypt -e password.txt image.jpg image-enc.jpg**

Decryption example:

**THCrypt -d password.txt image-enc.jpg image-dec.jpg**

## Drag & drop
Just simply drag the file onto the THCrypt.exe (encrypted files will be given extension .enc)

Note: You should create key.txt file beforehand. (16 characters long key should be sufficient)

### Demo
https://goo.gl/HsVj3S

(Includes 64 and 32-bit Windows executables, source code, README.md, LICENSE, ROADMAP.txt and demonstration files)

### Other stuff

Linux release is planned for the future.

32-bit version is significantly slower than the 64-bit version at the moment. (Fixed in the upcoming release)

I'm aware there is a possibility to recover the deleted key.txt file.
This will be resolved in the future alongside some other things. (Check the roadmap for more info)
https://github.com/TypicalHog/THCrypt/blob/master/ROADMAP.txt
