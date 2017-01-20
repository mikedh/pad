import numpy as np

import collections
import base64
import zlib
import json
import os

# uses OS entropy rather than MT
from Crypto.Random import random

# the pad consists of 8 bit unsigned integers
# this is to correspond to ASCII charecters 
dtype_pad     = np.uint8

# messages consist of indexes in the pad, so they will
# always be positive
dtype_message = np.uint64

# default length of a pad
default_pad_length = 1000000

def encrypt(message, pad, unused):
    '''
    Encrypt a message using a one- time pad.

    Arguments
    -----------
    message: (m,) string, message to be encrypted
    pad:     (n,) dtype_pad, array of random numbers
    unused:  (n,) bool, which values in pad are unused

    Returns
    -----------
    encrypted: (m,) int, locations in pad which compose message
    unused:    (n,) bool, updated unused mask 
    '''
    
    # convert the message from a string to an array of 8 bit integers
    message_int = np.array([ord(i) for i in str(message)], 
                           dtype=dtype_pad)
        
    # create a list of options in the pad for charecters in the message
    lookup = {letter : pad == letter for letter in np.unique(message_int)}
    
    # the encrypted message is an array of pad indexes
    encrypted = collections.deque()
    # record how close to fully used the one- time pad is
    statistics = collections.deque()
    
    for charecter in message_int:        
        # all locations in the pad that are unused and that
        # represent the same value as the message charecter
        options = np.logical_and(unused, lookup[charecter])

        # record how many possible options there are in the pad for this char
        statistics.append(options.sum())
        
        # if the used/unused values are improperly carried forward
        # choosing randomly from the available options will preserve some strength
        # especially if the pad is very large relative to the messages
        # this will also raise an IndexError if all values are consumed
        pad_index = random.choice(np.nonzero(options)[0])
        
        # mark as consumed this index from the pad 
        unused[pad_index] = False
        
        # store the location in the encrypted message
        encrypted.append(pad_index)

    # print statistics about pad
    statistics = np.array(statistics)
    print('encryptor: pad chars remaining {:.2f} average, {} minimum'.format(statistics.mean(),
                                                                             statistics.min()))
        
    # convert the deque into a numpy array
    encrypted = np.array(encrypted, dtype=dtype_message)
    return encrypted, unused
    
def decrypt(encrypted, pad):
    '''
    Decrypt a message encoded with a one- time pad.

    Arguments
    -----------
    encrypted: (n,) int, locations in pad
    pad:       (m,) int, random data

    Returns
    ----------
    message: string, ascii message
    '''
    message = ''.join([chr(i) for i in pad[encrypted]])
    return message

def generate_pad(length):
    '''
    Generate a one- time pad using pycrypto.random

    Arguments
    -----------
    length: int, length of pad

    Returns
    ----------
    pad:    (length,) dtype_pad random data
    unused: (length,) bool, unused charecters in pad
    '''
    # get random bits and convert them into a numpy array
    pad = np.fromstring(random.long_to_bytes(random.getrandbits(int(length * 8))), 
                        dtype=dtype_pad)
    unused = np.ones(len(pad), dtype=np.bool)
    return pad, unused

def pack_pad(pad, unused):
    '''
    Pack a one- time pad and an unused array to a JSON string.

    Arguments
    ----------
    pad:    (n,) dtype_pad, random data
    unused: (n,) bool, which values in pad have not been used

    Returns
    ----------
    blob: string, JSON blob with keys:
                  'pad': base64 encoded string of array
                  'unused': base64 encoded zlib compressed unused array
    '''
    blob = {'pad'    : to_packed(pad,    compress=False),
            'unused' : to_packed(unused, compress=True)}
    return json.dumps(blob)

def unpack_pad(packed):
    '''
    Unpack a pad and unused array
    
    Arguments
    ----------
    packed: string, JSON dict containing 'pad' and 'unused'

    Returns
    ---------
    pad: (n,) dtype_pad
    unused: (n,) bool
    '''
    packed = json.loads(packed)

    pad = to_native(packed['pad'], dtype_pad, decompress=False)
    unused = to_native(packed['unused'], np.bool, decompress=True)

    return pad, unused

def to_native(blob, dtype, decompress=False):
    '''
    Convert a base64 and optionally zlib'd blob to a numpy array.

    Arguments
    ----------
    blob:       string, base64 encoded
    dtype:      numpy data type for result
    decompress: bool, if blob is also zlib- compressed, decompress

    Returns
    ---------
    native: numpy array
    '''
    blob = base64.b64decode(blob)
    if decompress:
        blob = zlib.decompress(blob)
    native = np.fromstring(blob, dtype=dtype)
    return native

def to_packed(array, compress=False):
    '''
    Convert a numpy array to a base64 string.
    
    Arguments
    -----------
    array:    numpy array
    compress: bool, zlib compress before encoding or not

    Returns
    -----------
    blob: string
    '''
    array = np.asanyarray(array)
    if compress:
        blob = base64.b64encode(zlib.compress(array.tostring()))
    else:
        blob = base64.b64encode(array.tostring())
    return blob.decode('utf-8')

class PadWriter:
    def __init__(self, file_name, length=None):
        '''
        A convinence object to handle pads as files on disc, 
        updating whenever an encrypt or decrypt transaction is done.
        '''
        self.file_name = file_name
        if os.path.exists(file_name):
            self._load_pad()
        else:
            print('PadWriter: file name was not existing file, creating new pad')
            self._new_pad(length)
            self._write_pad()

    def _new_pad(self, length):
        if length is None: 
            length = default_pad_length
        self.pad, self.unused = generate_pad(length)
        
    def _load_pad(self):
        with open(self.file_name, 'r') as in_file:
            self.pad, self.unused = unpack_pad(in_file.read())
        print('PadWriter: loaded pad from ' + self.file_name)
        
    def _write_pad(self):
        with open(self.file_name, 'w') as out_file:
            out_file.write(pack_pad(self.pad, self.unused))
        print('PadWriter: updated pad file on disk')
            
    def encrypt_message(self, message):
        '''
        Encrypt a message using the loaded one time pad

        Argumnets
        ----------
        messsage: string, message to encrypt

        Returns
        ----------
        encrypted_string: base64 and zlib compressed string
        '''
        encrypted, self.unused = encrypt(message=message,
                                        pad = self.pad,
                                        unused=self.unused)
        self._write_pad()
        encrypted_string = to_packed(encrypted, compress=True)
        
        return encrypted_string

    def decrypt_message(self, encrypted):
        '''
        Decrypt a message encrypted with the loaded one time pad.

        Arguments
        -----------
        encrypted: base64/zlib string of pad locations

        Returns
        ---------
        decrypted: string of decrypted message
        '''
        encrypted_array = to_native(encrypted, dtype_message, decompress=True)
        decrypted = decrypt(encrypted = encrypted_array,
                            pad = self.pad)
        # update the used flags for the one- time pad
        self.unused[encrypted_array] = False
        self._write_pad()
        return decrypted
    
if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--pad', default='pad_data.json')
    parser.add_argument('-e', '--encrypt')
    parser.add_argument('-d', '--decrypt')
    parser.add_argument('-l', '--pad_length')
    args = parser.parse_args()
    
    if args.encrypt:
        writer = PadWriter(file_name=args.pad,
                           length=args.pad_length)
        encrypted = writer.encrypt_message(args.encrypt)
        print('\n', encrypted, '\n')
    if args.decrypt:
        writer = PadWriter(file_name=args.pad,
                           length=args.pad_length)
        decrypted = writer.decrypt_message(args.decrypt)
        print('\n', decrypted, '\n')
