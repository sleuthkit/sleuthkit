# Encryption and Encrypted File Systems with The Sleuth Kit

* TSK supports APFS and NTFS volume level encryption.

## APFS Encryption Pipeline: 
* TSK provides some support for encrypted APFS file systems, however, as it currently stands there are a number of limitations that make it difficult to use. 

* As demonstrated during APFS support release, `mmls` must be run on the disk image to determine the offset required by `pstat`.

* `pstat` returns the APSB super block number which is required for calling tools like `fls`, `istat` and `icat` with the `-k` flag and a supplied password.

* An example encrypted APFS `fls` call may be as follows:
`fls -f apfs -o 40 -B 386 -k 'password' my_disk_image.img`

### Notes: 
* This is one specific use-case that is based on the demonstration in [APFS Support and Demo](https://www.youtube.com/watch?v=k1XPillJ7aw&t=424s). 
* This is based on an APFS disk image that was created and encrypted using macOS Disk Utility.

## Issues Requiring Resolution:
* `mmls` provides no output when working with APFS encrypted disk images.
* There is limited support for retrieving the APSB super block number that is required for calling TSK tools with APFS disk images.
    * As it currently stands `pstat` does not have support for encrypted filesystems, this means that we must decrypt the disk image outside of TSK and call `pstat` on the decrypted disk image. This limits the benefit native encryption support.





