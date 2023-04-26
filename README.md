# Assignment: Encrypted Filesystem
## Due May 3

In this assignment, we'll use the fuse-t library to implement an encrypted filesystem!

fuse-t library that allows users to write filesystems completely in user space!  Basically, we provide functions to implement the various filesystem related system calls, and FUSE hooks things up so that the OS calls our functions as appropriate:  

user program system call -> kernel -> fuse-t library -> userspace FS code.

Because we're running in user space, we can be less concerned about security, don't need extra permissions to use/test our filesystems, and don't have to deal with kernel-space development (we can use all the user-space tools/libraries we know and love, and can even write our FS in Python!).  The python wrapper for FUSE stuff is [here](fuse.py), and is a small modification from the offical version from [here](https://github.com/fusepy/fusepy)
 

The version of FUSE we'll use on our macs is called Fuse-T which you can install with homebrew following the instruction [here](https://www.fuse-t.org/#h.um98i4ngslfa).  We used to use a library called MacFuse (which should also work), but MacFUSE installs kernel extensions which require you to jump through a bunch of security hoops on modern MacOS.

If you're interested, you should be able to do the assignment in a linux virtual machine (which will make some aspects easier, actually).

The related tool sshfs that is also available is very useful (not necessary for this assignment, but it lets you manipulate the filesystem of a machine you're SSH'd into like it's local... very handy sometimes).

The python bindings for FUSE are contained in a single file (linked at the end of the description).  You should just need to place them in the same directory as your code (encfs.py, for example).

We'll need one additional python library called cryptography.  You can install it via pip (or pip3, depending on which version(s) of python you have installed.  I found it easiest to `brew install python3`, then `/opt/homebrew/bin/pip3 install cryptography` and make sure to run your python code with `/opt/homebrew/bin/python3 ...` to make sure I was using the version of pip and python from homebrew.  (Note: homebrew puts x86 versions of stuff in `/usr/local/bin`, and the M1 ARM versions of stuff in `/opt/homebrew/bin`, so if you see instructions specifying `/usr/local/bin/whatever`, that's like 1+ years old, you may have to adjust the paths).  
 

## Instructions

Complete the provided skeleton code to implement an "encrypted" filesystem.

We're going to create a normal directory on our machine that contains encrypted files.  Using FUSE, we can create a filesystem that automatically decrypts the files from that directory as needed!  Any files written to our filesystem are automatically encrypted as well.  For the rest of the discussion, I'll call the directory containing encrypted files (that will exist after our program exits) the "physical filesystem," and the decrypted view of it that we'll create with FUSE the "virtual filesystem"

 

Example usage:

```
#just do this stuff once:
mkdir encrypted mountpoint #make folders for the physical + encrypted FSs
cp testFile encrypted/testFile #put the test file I gave you in the physical FS

#to test your code:
python3 encfs.py encrypted mountpoint   #encrypted is the physical filesystem, mountpoint is the virtual filesystem
enter the password which is just password

#lots of spam from FUSE logger
```
 

In another terminal:

```
$ cat mountpoint/testFile 
hello
#reading from the virtual filesystem opens the encrypted version 
#from the physical filesystem, and decrypts the contents for us

#make your own encrypted file
$ echo hello > mountpoint/somefile  
#writing plaintext to the virtual filesystem.  
#the FS stores the encrypted version in the physical filesystem



# this is the only data that's stored on disk.  It's in the physical filesystem and is encrypted
$ cat encrypted/hello 
B���t���]��b����gAAAAABaxTxhrkpLlcm5wm22dbaUYkMaKEHVXKEKiMAq17uQAg1UVlYQkJEjtZc5kQ0DbEjVrotMtCaIw7kuW4Li3sqfA8_8TQ==% 
``` 

(or similar)

If Ctrl-C doesn't seem to reliably kill the python script, you can kill it (I think safely) from another terminal by running `umount <path to your decrypted view mountpoint, so "mountpoint" in the examble above>`
 

Once I stop the encfs.py script (the fuse filesystem), mountpoint is empty.  The directory `encrypted` preserves encrypted copies of all files there, and I can remount it (run `encfs.py` again) using the correct password to recover the files again.

The general strategy is this: any normal files (we'll leave directories alone) in the physical filesystem contain 16 bytes of random salt, then the encrypted version of the file.  When we read from the virtual filesystem, we will decrypt the corresponding file from the physical filesystem and return the uncrypted data requested by the user.  When we close a file, we'll pick a new random salt, encrypt the file, then write the salt and the encrypted file to physical filesystem.  Any other filesystem operations should simply perform the requested operation on the physical filesystem. 

 

We're going to adapt the "pass through filesystem" example by Stephen Holsapple from [here](https://github.com/sholsapp/fusepy-base/blob/master/fusepybase/passthrough.py).  A "pass through" filesystem is one where the virtual filesystem is basically an alias for the physical filesystem.  Any system calls directed at the virtual filestystem are simple intercepted and called on the physical filesystem.

 

We'll need to modify/implement the following system calls (hopefully it should be clear why):

* `open()`, `create()` -- what do we do when we open an existing file or create a new one?
* `read()`, `write()` -- should be self explanatory
* `truncate()` -- used when a file is opened for writing, but already exists and contains data.  It resizes the file
* `release()` -- this will be automatically called for us when the user calls `close()`
* `getattr()` -- the getattr system call is used to determine the size of the file.  If we leave this as a pass through method, the file size will be wrong (an extra 16 bytes of random salt + any padding needed to round the file size up to a multiple of the block size).  We can leave this as a pass through for all the info, but we have to update the size field to be the length of the unencrypted data, rather than the physical file.
 

While a file is open (that is, between a call to `open()` or `create()` and `release()`), we'll store the entire file, unencrypted, in memory.  I suggest using a dictionary to map the filename to the data (stored as a bytes object).  When the user calls read or write, we'll either return the appropriate chunk of that array, or we'll overwrite/append to the in-memory version.

It's unclear if it matters, but we'll return a new file descriptor (an integer, like the `open()` syscall does) each time we `open()` or create() a file, so we'll want to store a `nextFD` member variable too.

 

Here's some more detail on the functions you'll need to fill in:

### `__init__`

Init should take 1 parameter: the path to the physical filesystem (which is the root of the virtual filesystem), which we'll need in various places.

Create and empty dictionary to store in memory files

Use the `getpass` function to read in the user's password (getpass prevents the console from echoing what the user types) and store it

Note, production grade software would NOT keep the unencrypted files + password in RAM longer than necessary, but we'll be less careful.  

 

### `open`

We're going to ignore the flags the user provides, basically opening everything in rw mode...

If the file doesn't exist, or it's already open, return -1 (an error)

Otherwise, read it, and store the decrypted version in your in-memory dictionary.  See this section for how to encrypt/decrypt using the cryptography library [here](https://cryptography.io/en/latest/fernet/#using-passwords-with-fernet).  Note, that example picks a random salt, which we'll do when we write out a file.  When decrypting an existing file, the first 16 bytes are the salt, and the rest of the file is the encrypted contents.  

You should return a new file descriptor (an int that you haven't returned before).  It's easiest to just increment an integer member variable and return that.

**You should be sure to close the encrypted file before you return from this method.**

### `create`

Create an empty file (easy to do with os.open and os.close), and add an empty entry to your dictionary of open files.

This is necessary so that future system calls that expect the file to actually exist work properly.

Return a new file descriptor.  

**Be sure not to keep this new file open when you return!  We won't keep the physical files open between any method calls!**

### `read/write/truncate`  

These should manipulate the entry in the in-memory dictionary.  read/write take the offset and length, so they're easy to use with your in-memory array!  Python's slice operations for array-like types should make this pretty easy to do!  https://stackoverflow.com/questions/509211/understanding-pythons-slice-notation

Read should return an array-like type with the appropriate data.  Write should return the number of bytes written (which should be the number of bytes requested to be written)

 

### `release`

Release will be called when the last open copy of the file is closed (mostly when a user calls `close()`)

This method should:

* generate a new random salt
* encrypt the contents of the file (see the above link to the crypto lib documentation)
* store the salt + encrypted file on disk.  
* remove this file from the dictionary of "open" files.

### `getattr`

Adjust the st_size field in the results to be the size of the buffer you're storing in your dictionary.

If the file is open (i.e. in your dictionary) you can just set it to the length of the byte array in the dictionary.  If it's not already open, then open it, decrypt it, use the length of the decrypted content, and then close it.  
 

## Notes:

The logging facility for FUSE is very noisy.  It logs every filesystem operations (your shell may make a lot of calls to access or getattr, etc).  It also tries calling some functions that we won't support.  You can safely ignore any of those errors/warnings.  Macos will also try to open a bunch of files that probably don't exist such as `.DS_store` or `.hidden` so you'll want to ignore errors related to those files as well.  **However, the output WILL provide you valuable information about bugs in your own code.**  You can comment out the "@logged" decorator before methods you're not working with to disable output for them.  

Be VERY careful when you test this.  If you screw up, it's possible to corrupt any of the files in the "physical filesystem" you use.  I strongly advise against using a folder you care about for either the physical or virtual filesystem!

If you implement `open()` and `read()` (or actually, just open, if you use some print statements), you should be able to decrypt the example file "hello" below if it's placed in your physical filesystem.


When you finish, submit your code via github.  Note, you should be using python 3 for this.
 

Provided files:

* [encfsStarterCode.py](encfsStarterCode.py)
* [fuse.py](fuse.py)
* [testFile](testFile) : this file should be decryptable if you use the password "password"