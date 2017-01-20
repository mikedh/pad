# pad

A toy implementation of one-time pads, with randomness from pycrypto. Stores and manages one-time pad data in a json blob.

## Example

```
mikedh@orbital:pad$ python pad.py --help
usage: pad.py [-h] [-p PAD] [-e ENCRYPT] [-d DECRYPT] [-l PAD_LENGTH]

optional arguments:
  -h, --help            show this help message and exit
  -p PAD, --pad PAD
  -e ENCRYPT, --encrypt ENCRYPT
  -d DECRYPT, --decrypt DECRYPT
  -l PAD_LENGTH, --pad_length PAD_LENGTH

mikedh@orbital:pad$ python pad.py -p pad_data.json -e 'hey wasup'
	  PadWriter: file name was not existing file, creating new pad
	  PadWriter: updated pad file on disk
	  encryptor: pad chars remaining 3869.56 average, 3780 minimum
	  PadWriter: updated pad file on disk

 eJz7f4aLAQRiOSF0vzMjmD4fA6YYrjDwgOnr0Xxgeu47NjCt940TTK+P4wbTAI38Cjo=

mikedh@orbital:pad$ python pad.py -p pad_data.json -d eJz7f4aLAQRiOSF0vzMjmD4fA6YYrjDwgOnr0Xxgeu47NjCt940TTK+P4wbTAI38Cjo=
PadWriter: loaded pad from pad_data.json
PadWriter: updated pad file on disk

 hey wasup
```