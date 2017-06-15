# THCrypt
C++ console application that features symmetric key based file encryption.


## Command line
Usage:
<!-- language: lang-none -->
THCrypt <-e | -d> <key filename> <input filename> <output filename>
<!-- language: lang-none -->

Encryption example:
THCrypt -e password.txt image.jpg image-enc.jpg

Decryption example:
THCrypt -d password.txt image-enc.jpg image-dec.jpg

## Drag & drop
Smply just drag the file onto the THCrypt.exe
Note: You should create key.txt file beforehand. (16 characters should be sufficient)
