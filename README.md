# Encrypted Filesystem
## Test

```python
# run the program
python3 encfs.py encrypted mountpoint 

# in the same terminal, enter the password when the password prompt appears ( yes the password is just "password" , purely for testing purpose )

# open another terminal, try to get the decrypted file
# it should show "hello MSD student"
cat mountpoint/testFile 


# try to write to a new file
echo hello > mountpoint/hello 

# try to read from the new file
cat mountpoint/hello

```