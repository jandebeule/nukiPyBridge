# nukiPyBridge

This python library let's you talk with Nuki lock (https://nuki.io/en/)

## Get started
1. install a BLE-compatible USB dongle (or use the built-in bluetooth stack if available)
2. install bluez (https://learn.adafruit.com/install-bluez-on-the-raspberry-pi/installation)
3. install pygatt (pip install https://github.com/stratosinc/pygatt)
4. replace the /usr/local/lib/python2.7/dist-packages/pygatt/backends/gatttool/gatttool.py file with the file from this repository.
5. install nacl (pip install pynacl)
6. ready to start using the library in python!

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

**REMARK** The credentials are stored in the file (hard-coded for the moment in nuki.py) : /home/pi/nuki/nuki.cfg

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
