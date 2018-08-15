#!/usr/bin/env python

"""
Copyright (c) 2018 Serhey Popovych <serhe.popovych@gmail.com>
Distributed under MIT License.
See LICENSE file for full license text.
"""

import fcntl
import struct
import sys
import os
import hashlib
import logging
import argparse

RNDADDENTROPY = 0x40085203 # from linux/random.h

def sha512sum(digest, fileName, blockSize = 16 * 1024):
    """
    Take SHA512 digest from file given by it's name contents.

    File opened in os.O_NONBLOCK mode to support FIFOs and
    special files like /dev/kmsg. Read data from files in
    blockSize (default 16kB) chunks to keep memory usage at
    minimum when used with large files.

    Return True on success and False otherwise.
    """

    def read():
        try:
            return fp.read(blockSize)
        except IOError:
            return b''
    #end def

    if digest is None:
        return False

    try:
        fp = open(fileName, 'rb')
    except IOError:
        return False

    flags = fcntl.fcntl(fp, fcntl.F_GETFL) | os.O_NONBLOCK
    if fcntl.fcntl(fp, fcntl.F_SETFL, flags):
        fp.close()
        return False

    for block in iter(read, b''):
        digest.update(block)

    fp.close()
    return True

def sha512(digest, fileName):
    """
    Computes sha512sum() optionally logging status.

    For internal use only.

    Return 1 on success and 0 on failure.
    """

    rc = sha512sum(digest, fileName)
    logging.debug("SHA512 (%s) = %s", fileName, 'ok' if rc else 'fail')
    return int(rc)

def add_entropy(digest, fileName = "/dev/urandom"):
    """
    Adds digest.digest_size * 8 bits of entropy using ioctl(RNDADDENTROPY, ...)
    increasing entropy count if CAP_SYS_ADMIN is available and just writes to
    fileName (default "/dev/urandom") updating entropy pool without incrementing
    entropy count.
    """

    try:
        fp = open(fileName, 'wb')
    except IOError as e:
        return None, str(e)

    size = digest.digest_size
    digest = digest.digest()

    # struct rand_pool_info {
    #         int    entropy_count;
    #         int    buf_size;
    #         __u32  buf[0];
    # };
    fmt = "ii{:d}s".format(size)
    rand_pool_info = struct.pack(fmt, size * 8, size, digest)

    method = None
    err = None

    try:
        fcntl.ioctl(fp, RNDADDENTROPY, rand_pool_info)
    except IOError:
        try:
            fp.write(digest)
        except IOError as e:
            err = str(e)
        else:
            method = "write"
    else:
        method = "ioctl"

    return method, err

def init():
    prog_name = os.path.splitext(os.path.basename(__file__))[0]
    if not prog_name:
        prog_name = "initrng"

    parser = argparse.ArgumentParser(description = 'Linux RNG early init')

    # loglevel
    loglevels = {
        'crit' : 'CRITICAL',
        'err'  : 'ERROR',
        'warn' : 'WARNING',
        'info' : 'INFO',
        'debug': 'DEBUG',
    }
    parser.add_argument('-l', '--loglevel', default = 'info',
                        choices = list(loglevels.keys()),
                        help = 'set program loging severity (level)')

    # entropy_files
    dflt_entropy_files = [
        "/dev/kmsg",
        "/proc/buddyinfo",
        "/proc/interrupts",
        "/proc/loadavg",
    ]
    parser.add_argument('-e', '--entropy-file', default = [],
                        action = 'append', dest = 'entropy_files', type = str,
                        help = 'files to use as source of entropy (multiple)')

    args = parser.parse_args()

    logging.basicConfig(format = "{:s}: %(message)s".format(prog_name),
                        level = getattr(logging, loglevels[args.loglevel]))

    return args.entropy_files or dflt_entropy_files

if __name__ == '__main__':
    entropy_files = init()

    logging.info("Linux Random Number Generator (RNG) early init")

    digest_sha512 = hashlib.sha512()

    i = 0
    for f in entropy_files:
        i += sha512(digest_sha512, f)
    if not i:
        sys.exit(1)

    method, err = add_entropy(digest_sha512)
    if err:
        logging.error("error seeding Linux RNG: %s", err)
    else:
        logging.info("successfuly seeded Linux RNG using '%s' method", method)
