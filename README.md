# nukiPyBridge

This python library let's you talk with Nuki lock (https://nuki.io/en/)

## Get started
1. install a BLE-compatible USB dongle (or use the built-in bluetooth stack if available)
2. install bluez (https://learn.adafruit.com/install-bluez-on-the-raspberry-pi/installation)
3. install pygatt (pip install https://github.com/stratosinc/pygatt)
4. replace the /usr/local/lib/python2.7/dist-packages/pygatt/backends/gatttool/gatttool.py file with the file from this repository.
5. ready to start using the library in python!

## Example usage
### Authenticate yourself for the first time
Before you will be able to send commands to the Nuki lock using the library, you must first authenticate yourself:
