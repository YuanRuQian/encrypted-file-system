"""
Adapted from https://github.com/sholsapp/fusepy-base/blob/master/fusepybase/passthrough.py
WHo provided a naive passthrough FUSE filesystem.

You'll need to modify the constructor (__init__), open(), create(), 
read(), write(), truncate(), and release() methods.  See the assignment description for
what to do
"""

from __future__ import with_statement

from functools import wraps
import os
import stat
import errno
import logging

from fuse import FUSE, FuseOSError, Operations


import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import getpass

log = logging.getLogger(__name__)

def logged(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        log.info('%s(%s)', f.__name__, ','.join([str(item) for item in args[1:]]))
        return f(*args, **kwargs)
    return wrapped


class EncFS(Operations):
    """A simple passthrough interface.

    Initialize the filesystem. This function can often be left unimplemented, but
    it can be a handy way to perform one-time setup such as allocating
    variable-sized data structures or initializing a new filesystem. The
    fuse_conn_info structure gives information about what features are supported
    by FUSE, and can be used to request certain capabilities (see below for more
    information). The return value of this function is available to all file
    operations in the private_data field of fuse_context. It is also passed as a
    parameter to the destroy() method.

    """
    def __init__(self, root):
        self.root = root
        self.saltSize = 16

        # Create an empty dictionary to store in-memory files
        self.openFiles = {}
        self.fd = 0
        self.key = Fernet.generate_key()

        # Read in the user's password and store it
        self.password = getpass.getpass(prompt="Enter password: ")
        log.info('init password: %s', self.password)
        self.password = bytes(self.password, 'utf-8')
           
    @logged
    def destroy(self, path):
        """Clean up any resources used by the filesystem.
        
        Called when the filesystem exits.
        
        """
        pass

    #NOTE THIS MIGHT BE USEFUL IN SEVERAL PLACES!
    def _full_path(self, partial):
        """Calculate full path for the mounted file system.

          .. note::

            This isn't the same as the full path for the underlying file system.
            As such, you can't use os.path.abspath to calculate this, as that
            won't be relative to the mount point root.

        """
        if partial.startswith("/"):
            partial = partial[1:]
        path = os.path.join(self.root, partial)
        return path

    @logged
    def access(self, path, mode):
        """Access a file.

        This is the same as the access(2) system call. It returns -ENOENT if
        the path doesn't exist, -EACCESS if the requested permission isn't
        available, or 0 for success. Note that it can be called on files,
        directories, or any other object that appears in the filesystem. This
        call is not required but is highly recommended.

        """
        full_path = self._full_path(path)
        if not os.access(full_path, mode):
            raise FuseOSError(errno.EACCES)

    @logged
    def chmod(self, path, mode):
        """Change a file's permissions.

        Change the mode (permissions) of the given object to the given new
        permissions. Only the permissions bits of mode should be examined. See
        chmod(2) for details.

        """
        full_path = self._full_path(path)
        return os.chmod(full_path, mode)

    @logged
    def chown(self, path, uid, gid):
        """Change a file's owernship.


        Change the given object's owner and group to the provided values. See
        chown(2) for details. NOTE: FUSE doesn't deal particularly well with
        file ownership, since it usually runs as an unprivileged user and this
        call is restricted to the superuser. It's often easier to pretend that
        all files are owned by the user who mounted the filesystem, and to skip
        implementing this function.

        """
        full_path = self._full_path(path)
        return os.chown(full_path, uid, gid)

    @logged
    def getattr(self, path, fh=None):
        """Return file or directory attributes."""
        # ignore .git , .gitignore, etc.

        if path.startswith('/.'):
            # ENOENT error indicates the file or directory does not exist
            return None

        log.info("getattr path : %s", path)
        full_path = self._full_path(path)

        if not os.path.exists(full_path):
            raise FuseOSError(errno.ENOENT)

        st = os.lstat(full_path)
        log.info("getattr st : %s", st)

        if os.path.isdir(full_path):
            props = dict((key, getattr(st, key)) for key in ('st_atime', 'st_ctime',
                                                         'st_gid', 'st_mode', 'st_mtime', 'st_nlink', 'st_size', 'st_uid'))
            props['st_mode'] |= stat.S_IFDIR
        else:
            decrypted_data = self.decrypt_file(full_path)
            props = dict((key, getattr(st, key)) for key in ('st_atime', 'st_ctime',
                                                         'st_gid', 'st_mode', 'st_mtime', 'st_nlink', 'st_size', 'st_uid'))
            # update the st_size to be the length of the decrypted data
            props['st_size'] = len(decrypted_data)
            log.info("st_size after decryption: %s", props['st_size'])
        return props

    @logged
    def readdir(self, path, fh):
        """Read a directory.

        Return one or more directory entries (struct dirent) to the caller.
        This is one of the most complex FUSE functions. It is related to, but
        not identical to, the readdir(2) and getdents(2) system calls, and the
        readdir(3) library function. Because of its complexity, it is described
        separately below. Required for essentially any filesystem, since it's
        what makes ls and a whole bunch of other things work.

        """
        full_path = self._full_path(path)

        dirents = ['.', '..']
        if os.path.isdir(full_path):
            dirents.extend(os.listdir(full_path))
        for r in dirents:
            yield r

    @logged
    def readlink(self, path):
        """Read a symbolic link.

        If path is a symbolic link, fill buf with its target, up to size. See
        readlink(2) for how to handle a too-small buffer and for error codes.
        Not required if you don't support symbolic links. NOTE: Symbolic-link
        support requires only readlink and symlink. FUSE itself will take care
        of tracking symbolic links in paths, so your path-evaluation code
        doesn't need to worry about it.

        """
        pathname = os.readlink(self._full_path(path))
        if pathname.startswith("/"):
            # Path name is absolute, sanitize it.
            return os.path.relpath(pathname, self.root)
        else:
            return pathname

    @logged
    def rmdir(self, path):
        """Remove a directory.

        Remove the given directory. This should succeed only if the directory
        is empty (except for "." and ".."). See rmdir(2) for details.

        """
        full_path = self._full_path(path)
        return os.rmdir(full_path)

    @logged
    def mkdir(self, path, mode):
        """Make a directory.

        Create a directory with the given name. The directory permissions are
        encoded in mode. See mkdir(2) for details. This function is needed for
        any reasonable read/write filesystem.

        """
        return os.mkdir(self._full_path(path), mode)

    @logged
    def statfs(self, path):
        full_path = self._full_path(path)
        stv = os.statvfs(full_path)
        return dict((key, getattr(stv, key)) for key in ('f_bavail', 'f_bfree',
          'f_blocks', 'f_bsize', 'f_favail', 'f_ffree', 'f_files', 'f_flag',
          'f_frsize', 'f_namemax'))

    @logged
    def unlink(self, path):
        """Unlink a file.

        Remove (delete) the given file, symbolic link, hard link, or special
        node. Note that if you support hard links, unlink only deletes the data
        when the last hard link is removed. See unlink(2) for details.

        """
        return os.unlink(self._full_path(path))


    @logged
    def rename(self, old, new):
        """Rename a file.

        Rename the file, directory, or other object "from" to the target "to".
        Note that the source and target don't have to be in the same directory,
        so it may be necessary to move the source to an entirely new directory.
        See rename(2) for full details.

        """
        return os.rename(self._full_path(old), self._full_path(new))

    @logged
    def utimens(self, path, times=None):
        return os.utime(self._full_path(path), times)

    @logged
    def decrypt_file(self, file_path: str):
        with open(file_path, 'rb') as file:
            salt = file.read(self.saltSize)
            if not salt:
                # Return an empty byte array if file is empty or too small to contain salt
                return b'' 
            encrypted_data = file.read()
            if not encrypted_data:
                raise ValueError("File is empty or too small to contain encrypted data")
        
        f = self.get_fernet_object_with_salt(salt)
        decrypted_data = f.decrypt(encrypted_data)
        return decrypted_data


    @logged
    def open(self, path, flags):
        """Open a file.

        We're going to ignore the flags the user provides, basically opening everything in rw mode...

        If the file doesn't exist, or it's already open, return -1 (an error)

        Otherwise, read it, and store the decrypted version in your in-memory dictionary. 
    
        """
        path = self._full_path(path)
        log.info('open path: %s', path)

        #  If the file doesn't exist, or it's already open, return -1
        if (not os.path.exists(path)) or (path in self.openFiles):
            return -errno.EEXIST

        decrypted_data = self.decrypt_file(path)
        log.info('open decrypted_data: %s', decrypted_data)

        # Store the decrypted data in the in-memory dictionary
        self.openFiles[path] = decrypted_data
        
        # Increment the file descriptor and return it
        fd = self.fd
        self.fd += 1
        log.info('open current fd: %s', self.fd)
        return fd
        
    @logged
    def create(self, path, mode, fi=None):
        full_path = self._full_path(path)
        log.info('create path: %s', full_path)
        return os.open(full_path, os.O_WRONLY | os.O_CREAT, mode)

    @logged
    def read(self, path, length, offset, fh):
        """Read from a file.

        These should manipulate the entry in the in-memory dictionary. read/write take the offset and length, so they're easy to use with your in-memory array! Python's slice operations for array-like types should make this pretty easy to do! https://stackoverflow.com/questions/509211/understanding-pythons-slice-notation

        Read should return an array-like type with the appropriate data. Write should return the number of bytes written (which should be the number of bytes requested to be written)

        """
        full_path = self._full_path(path)
        # Retrieve the file content from the in-memory dictionary
        if (not full_path in self.openFiles):
            raise FileNotFoundError(
                f"No such file or directory: '{full_path}'")
        return self.openFiles[full_path]
    
    @logged
    def get_fernet_object_with_salt(self, salt: bytes):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.password))
        return Fernet(key)

    @logged
    def write(self, path, buf, offset, fh):
        full_path = self._full_path(path)

        if not os.path.exists(full_path):
            # create the file if it doesn't exist
            self.create(path, 0o666)

        if full_path not in self.openFiles:
            self.openFiles[full_path] = b''

        # append current buf to self.openFiles[full_path]
        self.openFiles[full_path] = self.openFiles[full_path][:offset] + buf

        # truncate / resize the current self.openFiles[full_path] with self.runcate(path, length)
        length = len(self.openFiles[full_path])
        self.truncate(path, length)

        # return the resized length of self.openFiles[full_path]
        return length

    @logged
    def truncate(self, path, length, fh=None):
        """Truncate a file to a specified length."""
        full_path = self._full_path(path)

        if full_path not in self.openFiles:
            log.error('truncate if full_path not in self.openFiles')
            # ftruncate(2) : On error, -1 is returned, and errno is set appropriately.
            return -1

        buf = self.openFiles.get(full_path, b'')
        buf = buf[:length] if len(buf) > length else buf.ljust(length, b'\0')

        self.openFiles[full_path] = buf

        # ftruncate(2) return 0: success
        return 0

        
    @logged
    def release(self, path, fh):
        """Release is called when FUSE is done with a file.

        This is the only FUSE function that doesn't have a directly
        corresponding system call, although close(2) is related. Release is
        called when FUSE is completely done with a file; at that point, you can
        free up any temporarily allocated data structures. The IBM document
        claims that there is exactly one release per open, but I don't know if
        that is true.

        """
        full_path = self._full_path(path)
        log.info('release full_path: %s', full_path)
        if(full_path in self.openFiles):
            # rewrite the encrypted file
            salt = os.urandom(self.saltSize)
            f = self.get_fernet_object_with_salt(salt)
            plain_text = self.openFiles[full_path]
            encrypted_data = f.encrypt(plain_text)
            with open(full_path, 'wb') as file:
                file.write(salt)
                file.write(encrypted_data)
                # delete the record whose key is full_path
                del self.openFiles[full_path]
        return os.close(fh)
    
if __name__ == '__main__':
    from sys import argv
    if len(argv) != 3:
        print('usage: %s <encrypted folder> <mountpoint>' % argv[0])
        exit(1)

    logging.basicConfig(level=logging.DEBUG)
    #create our virtual filesystem using argv[1] as the physical filesystem
    #and argv[2] as the virtual filesystem
    fuse = FUSE(EncFS(argv[1]), argv[2], foreground=True)
