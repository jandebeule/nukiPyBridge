# nukiPyBridge

This python library let's you talk with Nuki lock (https://nuki.io/en/)

## Get started
1. install a BLE-compatible USB dongle (or use the built-in bluetooth stack if available)
2. sudo apt-get install libffi-dev
3. install bluez (https://learn.adafruit.com/install-bluez-on-the-raspberry-pi/installation)
4. install pygatt (pip install pygatt)
5. replace the /usr/local/lib/python2.7/dist-packages/pygatt/backends/gatttool/gatttool.py file with the file from this repository.
6. install nacl (pip install pynacl)
7. install crc16 (pip install crc16)
8. install pybluez (pip install pybluez)
9. install pexpect (pip install pexpect)
10. ready to start using the library in python!

## Example usage
### Authenticate
Before you will be able to send commands to the Nuki lock using the library, you must first authenticate (once!) yourself with a self-generated public/private keypair (using NaCl):
```python
import nuki_messages
import nuki
from nacl.public import PrivateKey

nukiMacAddress = "00:00:00:00:00:01"
# generate the private key which must be kept secret
keypair = PrivateKey.generate()
myPublicKeyHex = keypair.public_key.__bytes__().encode("hex")
myPrivateKeyHex = keypair.__bytes__().encode("hex")
myID = 50
# id-type = 00 (app), 01 (bridge) or 02 (fob)
# take 01 (bridge) if you want to make sure that the 'new state available'-flag is cleared on the Nuki if you read it out the state using this library
myIDType = '01'
myName = "PiBridge"

nuki = nuki.Nuki(nukiMacAddress)
nuki.authenticateUser(myPublicKeyHex, myPrivateKeyHex, myID, myIDType, myName)
```

**REMARK 1** The credentials are stored in the file (hard-coded for the moment in nuki.py) : /home/pi/nuki/nuki.cfg

**REMARK 2** Authenticating is only possible if the lock is in 'pairing mode'. You can set it to this mode by pressing the button on the lock for 5 seconds until the complete LED ring starts to shine.

### Commands for Nuki
Once you are authenticated (and the nuki.cfg file is created on your system), you can use the library to send command to your Nuki lock:
```python
import nuki_messages
import nuki

nukiMacAddress = "00:00:00:00:00:01"
Pin = "%04x" % 1234

nuki = nuki.Nuki(nukiMacAddress)
nuki.readLockState()
nuki.lockAction("UNLOCK")
logs = nuki.getLogEntries(10,Pin)
print "received %d log entries" % len(logs)

available = nuki.isNewNukiStateAvailable()
print "New state available: %d" % available

```
**REMARK** the method ```isNewNukiStateAvailable()``` only works if you run your python script as root (sudo). All the other methods do not require root privileges
