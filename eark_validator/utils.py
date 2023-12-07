#!/usr/bin/env python
# coding=UTF-8
#
# E-ARK Validation
# Copyright (C) 2019
# All rights reserved.
#
# Licensed to the E-ARK project under one
# or more contributor license agreements. See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership. The E-ARK project licenses
# this file to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License. You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.
#
"""
E-ARK : Information package validation
        Utilities
"""
import hashlib
import os.path

BLOCKSIZE = 1024 * 64

def sha1(path, blocksize=BLOCKSIZE):
    """Fault tolerant sha_1(path) routine. Calaculates the SHA-1 digest of any
    file found at path arg. Returns None when the passed arg isn't a file path or
    arg can not be hashed."""
    if not os.path.isfile(path):
        return None
    hasher = hashlib.sha1()
    with open(path, 'rb') as afile:
        buf = afile.read(blocksize)
        while len(buf) > 0:
            hasher.update(buf)
            buf = afile.read(blocksize)
    return hasher.hexdigest()

def sha1_directory(directory_path, depth=3):
    sha1 = hashlib.sha1()
    # Initialize the current depth
    current_depth = directory_path.count(os.sep)
    for root, dirs, files in os.walk(directory_path):
        # Calculate the depth of the current root
        root_depth = root.count(os.sep)
        if root_depth - current_depth < depth:
            # Sort the file names to ensure consistent ordering
            for filename in sorted(files):
                filepath = os.path.join(root, filename)
                # Check if it is a regular file and not a directory
                if os.path.isfile(filepath):
                    with open(filepath, 'rb') as f:
                        while True:
                            # Read file in chunks of 4096 bytes
                            data = f.read(4096)
                            if not data:
                                break
                            # Update the hash with the file content
                            sha1.update(data)
        else:
            # Don't go beyond the specified depth
            del dirs[:]

    # Return the final sha1 hash of the directory
    return sha1.hexdigest()