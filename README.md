# THCrypt
C++ console application that features unique (at least I think so) symmetric key based file encryption algorithm.

### Some facts
-It is possible to encrypt the file with another file. (Key size was recently limited to 256 bytes, thus, only the first 256 bytes from the file are being used as a key at the moment. This is very INSECURE since different files could sometimes begin with a similar sequence of bytes. However, SHA-256 hash of the file could and will be used as a key in the future.)

-Key can be up to 256 bytes (2048-bit) long, which is overkill. (I think 16 bytes (128-bit) is enough for almost any purpose.)

-Time complexity is O(n) (linear) and dependent on the size of they key, but every new byte added to the key makes the brute-force attack 2^8 (256) times harder.

-Before encryption or decryption, lookup tables are generated if they are not present already. (Which is a compromise because it makes the whole process a tiny bit faster but adds 2 extra files to the working directory.)

## Command line
Usage:

**THCrypt \<-e | -d\> \<key filename\> \<input filename\> \<output filename\>**

Encryption example:

**THCrypt -e password.txt image.jpg image-enc.jpg**

Decryption example:

**THCrypt -d password.txt image-enc.jpg image-dec.jpg**

## Drag & drop
Just simply drag and drop the file onto the "THCrypt.exe". (Encrypted files will be given extension ".enc".)

Note: You should create "key.txt" file beforehand and put the key inside.

### Demo
https://goo.gl/HsVj3S

(Includes 64-bit and 32-bit Windows executables, source code, README.md, LICENSE, ROADMAP.txt and demonstration files.)

### Other stuff

Linux release is planned in the future.

The 32-bit version is currently significantly slower than the 64-bit version. (Fixed in the upcoming release.)

I'm aware there is a possibility deleted "key.txt" could be recovered after it has been deleted from the drive.
This will be resolved in the future alongside many other things. (Check the roadmap for more info.)
https://github.com/TypicalHog/THCrypt/blob/master/ROADMAP.txt
