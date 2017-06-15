# THCrypt
C++ console application that features symmetric key based file encryption.


# Command line
Usage:
Crypter <-e | -d> <key filename> <input filename> <output filename>

Encryption example:
Crypter -e password.txt image.jpg image-enc.jpg

Decryption example:
Crypter -d password.txt image-enc.jpg image-dec.jpg

# Drag & drop
Or just simply just drag the file into the Crypter.exe. (Default key is key.txt)
