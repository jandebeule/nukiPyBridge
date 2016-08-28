import nuki_messages
import nuki

nukiMacAddress = "00:00:00:00:00:01"
publicKeyPiHex = "3456789101235effd3d56b286386db07ba5e161af941e5c21b09c3ddfcbc923"
privateKeyPiHex = "3456789012345fe05f2a08ebdca17ee3d2ebf081e1a729cd5687ca56cb72da14"
ID = 50
IDType = '01'
Name = "PiBridge"
Pin = "%04x" % 1234

nuki = nuki.Nuki(nukiMacAddress)
nuki.authenticateUser(publicKeyPiHex, privateKeyPiHex, ID, IDType, Name)
nuki.readLockState()
nuki.lockAction("UNLOCK")
logs = nuki.getLogEntries(10,Pin)
print "received %d log entries" % len(logs)

available = nuki.isNewNukiStateAvailable()
print "New state available: %d" % available