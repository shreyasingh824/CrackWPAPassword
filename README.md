# CrackWPAPassword
# WPA Passphrase Cracking

## Overview

This repository contains a Python script for cracking a WPA passphrase using a captured handshake. The script uses a wordlist to attempt different passphrases and checks if the calculated MIC (Message Integrity Code) matches the captured MIC. This tool is intended for educational and security research purposes only.

## Features

- Crack WPA passphrases using a captured handshake.
- Utilize a wordlist to perform passphrase guessing.
- Verify passphrase correctness based on MIC comparison.

## Requirements

- Python 3.x
- [PyShark](https://github.com/cea-sec/pyxsw) for packet analysis.

## Usage

1. Capture a WPA handshake using a tool like Wireshark or aircrack-ng.
2. Save the capture as a `.cap` file.
3. Place the capture file in the same directory as the script.
4. Create a text file containing a list of potential passphrases (one per line) and name it `passphrases.txt`.
5. Run the script with Python: `python script.py`.
6. The script will iterate through the wordlist and attempt to crack the passphrase.

## Example

```shell
$ python script.py
Passphrase found: correct_passphrase
End of wordlist.
