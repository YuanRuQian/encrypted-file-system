# Encrypted Filesystem

The purpose of the project is to implement an encrypted filesystem using the [fusepy library](https://github.com/fusepy/fusepy), which allows users to write filesystems with encryption completely in user space. 

## Important Notice

**This code was developed and tested on a Linux machine running Ubuntu 22.04 LTS Jammy Jellyfish, so it may not work seamlessly on other operating systems such as OS X.**

## Setup

To install all the required packages for this program, run the following command in your terminal:

```shell
 pip install -r requirements.txt
```

This will install all the packages listed in the [requirements.txt](requirements.txt) file.

## Test with the Correct Password

```shell
#make folders for the physical + encrypted FSs
mkdir encrypted mountpoint 

# run the program
python3 encfs.py encrypted mountpoint 

# enter the password ( just "password" ! )

# open another terminal so the previous one coould show logger info 

# try to cat a file does not exist form the physical folder

cat encrypted/lydia

# cat: encrypted/lydia: No such file or directory

# try to cat a file does not exist form the virtual filesystem folder

cat mountpoint/lydia

# cat: mountpoint/lydia: No such file or directory

# try to write info to the testFile

echo hello from Lydia > mountpoint/lydia 

# cat the file from the physical folder

cat encrypted/lydia

# it should print out some encrypted data

# cat the file from the virtual filesystem folder

cat mountpoint/lydia

# it should print out "hello from Lydia"

# cat the file from the virtual filesystem folder again

cat mountpoint/lydia

# it should print out "hello from Lydia" again

```

Any files placed in the `encrypted` folder should be automatically encrypted, and no files should ever exist in the `mountpoint` folder at any time.

## Test with the Incorrect Password


```shell

# run the program
python3 encfs.py encrypted mountpoint 

# enter a wrong password ( anything but "password", like "testing123" ! )

# open another terminal so the previous one coould show logger info 

# try to cat an existing file form the physical folder

cat encrypted/lydia

# print out the encrypted content

# try to cat an existing file form the virtual filesystem folder

cat mountpoint/lydia

# cat: mountpoint/lydia: Invalid argument

# If you go to the previous console which shows logger info, you show see a cryptography.fernet.InvalidToken error

```

