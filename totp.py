#!/usr/bin/python
import base64
import hmac
import hashlib
import time
import argparse

# JBSWY3DPEHPK3PXP
def main():
    # Handle arguments.
    parser = argparse.ArgumentParser()
    parser.add_argument('secret', help='The shared secret in Base32 format.')
    parser.add_argument('-d', '--digits', help='The number of digits in the TOTP.', type=int, default=6)
    parser.add_argument('-p', '--period', help='The number of seconds for the token period.', type=int, default=30)
    args = parser.parse_args()

    if args.digits and args.digits < 1:
        parser.error('number of digits must not be less than 1')

    if args.period and args.period < 1:
        parser.error('token period must not be less than 1')

    try:
        # Decode secret from Base32.
        secret_string = base64.b32decode(args.secret)
    except TypeError:
        parser.error('Invalid secret format.')

    # Decode the current 30 second time block, which will be used as the counter.
    seconds = int(time.time()) / args.period
    seconds_string = '{:016X}'.format(seconds).decode('hex')

    # Encrypt the current 30 second time block (seconds_string) with secret_string.
    hmac_hash = hmac.new(secret_string, seconds_string, hashlib.sha1)
    hmac_hash_digest = hmac_hash.digest() # The 20-byte HMAC-SHA-1 digest.

    # Calculate the offset based on the last 4 bits of the digest.
    offset = ord(hmac_hash_digest[19]) & 0xF

    # Use the offset to extract a 4-byte dynamic binary code from the digest.
    dbc = hmac_hash_digest[offset:offset + 4]

    # Mask the most significant bit of the dbc to avoid confusion about signed vs. unsigned modulo computations.
    dbc2 = int(dbc.encode('hex'), 16) & 0x7FFFFFFF

    # Extract an n-digit TOTP.
    totp = dbc2 % 10 ** args.digits

    print '{:0{}d}'.format(totp, args.digits)

if __name__ == '__main__':
    main()
