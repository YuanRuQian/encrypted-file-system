# Encrypted Filesystem

The purpose of the project is to implement an encrypted filesystem using the [fusepy library](https://github.com/fusepy/fusepy), which allows users to write filesystems with encryption completely in user space. 

## Important Notice

> This code was developed and tested on a machine running Ubuntu 22.04 LTS Jammy Jellyfish, so it may not work seamlessly on other operating systems such as OS X.

## Setup

To install all the required packages for this program, run the following command in your terminal:

```shell
 pip install -r requirements.txt
```

This will install all the packages listed in the [requirements.txt](requirements.txt) file.

## Test

```shell
# run the program
python3 encfs.py encrypted mountpoint 

# test cat from physical file folder
cat encrypted/testFile

# it should show some encrypted text like: “ w�fB�#_� OYv�4G;gAAAAABkOXIieZ20NDeY8u05GLTb5vJECvix0-muv-Oy54QwsEdfqdH8YTDMmMihe7XXEAZq7Nx15vJu0ZrlzTqs-JwalQ06QMSiOfBQFjdebrvBuAk6H9A= “


# in the same terminal, enter the password when the password prompt appears ( yes the password is just "password" , purely for testing purpose )

# open another terminal, try to get the decrypted file

cat mountpoint/testFile 

# it should show "hello MSD student"


# try to write to a new file

echo hello from Lydia > mountpoint/lydia 

# try to read from the new file

cat mountpoint/lydia

# it should show “hello from Lydia”

# attempt to read twice from the same file
cat mountpoint/lydia

# it should show “hello from Lydia” again


# test cat a file does not exist in the physical folder

cat encrypted/testingFile

# console output: cat: encrypted/testingFile: No such file or directory

# test cat a file does not exist in the virtual filesystem folder

cat mountpoint/testingFile

# cat: mountpoint/testingFile: Numerical result out of range

```