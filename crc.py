import binascii
import crc16

class CrcCalculator: 
   def __init__(self): 
      pass       
   
   def crc_ccitt(self, hex_string):
      crc = crc16.crc16xmodem(binascii.unhexlify(hex_string), 0xffff)
      crcval = '{:04X}'.format(crc & 0xffff)
      return crcval
