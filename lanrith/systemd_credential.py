"""Read PID1 credential copies in its private-owner or exact named-user ACL form.

systemd prefers a root-owned read-only file with one named-user read ACL.
On filesystems without ACL support it assigns the file to the consumer instead.
Group/world readable files and grants to any other identity are rejected.
"""

import errno
import os
import stat
import struct


def acl(descriptor):
    try:
        return os.getxattr(descriptor, 'system.posix_acl_access')
    except OSError as error:
        if error.errno not in (errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP):
            raise
        return None


def read(path, maximum, consumer_uid):
    if (type(consumer_uid) is not int or not 0 <= consumer_uid < 2**32-1 or
            type(maximum) is not int or not 1 <= maximum <= 1024*1024):
        raise ValueError('Credential consumer identity differs.')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        access = acl(stream.fileno())
        private_owner = (before.st_uid in (0, consumer_uid) and access is None and
                         stat.S_IMODE(before.st_mode) in (0o400, 0o600))
        # Linux POSIX ACL xattr version 2, with only a read grant for this
        # consumer. The visible group-read bit is the ACL mask, not a group
        # permission: GROUP_OBJ and OTHER must both be empty.
        expected = struct.pack('<I', 2)+b''.join(struct.pack('<HHI', tag, permissions, identifier)
            for tag, permissions, identifier in ((1, 4, 0xffffffff), (2, 4, consumer_uid),
                (4, 0, 0xffffffff), (16, 4, 0xffffffff), (32, 0, 0xffffffff)))
        named_user = before.st_uid == 0 and stat.S_IMODE(before.st_mode) == 0o440 and access == expected
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                not 0 < before.st_size <= maximum or not (private_owner or named_user)):
            raise ValueError('Credential copy custody differs.')
        value = stream.read(maximum+1)
        after = os.fstat(stream.fileno())
        if (len(value) != before.st_size or len(value) > maximum or
                (before.st_dev, before.st_ino, before.st_size, before.st_uid, before.st_gid, before.st_mode,
                 before.st_mtime_ns, before.st_ctime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_uid, after.st_gid, after.st_mode,
                 after.st_mtime_ns, after.st_ctime_ns) or access != acl(stream.fileno())):
            raise ValueError('Credential copy changed during its read.')
    return value
