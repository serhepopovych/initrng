#!/usr/bin/env python

"""
Copyright (c) 2018 Serhey Popovych <serhe.popovych@gmail.com>
Distributed under MIT License.
See LICENSE file for full license text.
"""

import fcntl
import sys
import os
import time
import hashlib
import logging
import argparse

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

    fd = fp.fileno()
    flags = fcntl.fcntl(fd, fcntl.F_GETFL) | os.O_NONBLOCK
    if fcntl.fcntl(fd, fcntl.F_SETFL, flags):
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
        logging.debug("seeding with seconds since Epoch as last resort (very bad)")
        digest_sha512.update(time.time())

    try:
        with open("/dev/urandom", 'wb') as fp:
            fp.write(digest_sha512.digest())
    except IOError as e:
        logging.error("error seeding Linux RNG: %s", str(e))
    else:
        logging.info("successfuly seeded Linux RNG")
