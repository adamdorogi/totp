# Set exit when any command fails.
set -e

# Get last 30 second time block (used as our counter).
time=$(($(date +%s) / 30))
# Convert time to hexadecimal.
hexTime=`printf "%016X" $time`

# Input as hex string (usually input as base32, and then converted to hex).
# base32: JBSWY3DPEHPK3PXP -> hex: 48656c6c6f21deadbeef
secretKey=$1
# Generate HMAC hash from hexadecimal time and hexadecimal shared secret.
hmacHash=`echo -n $hexTime | xxd -r -p | openssl sha1 -mac HMAC -macopt "hexkey:$secretKey"`

# Get offset from last 4 bits of HMAC hash.
offset=$((0x$hmacHash & 0xf))
# Get 32 bit substring with offset (DBC1).
substring=${hmacHash:offset*2:8}
# Mask the most significant bit to get a 31 bit dynamic binary code (DBC2).
dbc2=$((0x$substring & 0x7fffffff))
# Modulo to get 6 digit code.
totp=`printf "%06d" $(($dbc2 % 10 ** 6))`

echo $hexTime
echo $hmacHash
echo $offset
echo $substring
echo $dc2
echo $totp
