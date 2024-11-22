#! /usr/bin/env python3

# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    ft_otp.py                                          :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: ssottori <ssottori@student.42london.com    +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2024/11/21 03:52:16 by ssottori          #+#    #+#              #
#    Updated: 2024/11/21 03:52:16 by ssottori         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

import os
import sys
import re
import pyotp
import argparse
import struct
import string
import hashlib
import hmac
import time

ERR_64 = "Error: The key must be at least 64 hexidecimal characters."

def ft_parse_arguments():
	parser = argparse.ArgumentParser(description="""*** ft_otp *** OTP Generator""")
	parser.add_argument("-g", help="Hashes and stores a 64-bit hexadecimal key securely in ft_otp.key")
	parser.add_argument("-k", help="Generates a one-time password using the stored key")
	args = parser.parse_args()

	if not args.g and not args.k:
		parser.error("Try -h for help.")
	if args.g:
		ft_basic_checks(args.g, ".hex", "hex")
	else:
		ft_basic_checks(args.k, ".key", "key")
	return args

def ft_save(file_name):
	with open(file_name, 'r') as file:
		hex_key = file.read()
		salt = os.urandom(16)
		comb = salt + bytes.fromhex(hex_key)
		# We create a hash using sha256 algorithm
		hash_obj = hashlib.sha256(comb)
		encrypted_str = hash_obj.hexdigest()
		with open('ft_otp.key', 'w') as key_key:
			key_key.write(encrypted_str)
	print('SUCCESSSSS! Your key was successfully saved in ft_otp.key.')

def ft_is_valid_hex(key):
	if len(key) < 64 or not re.match("^[0-9a-fA-F]{64}$", key) or len(key) % 2 == 1:
		print(ERR_64)
		return False
	try:
		int(key, 16) #check it can be converted to int
		return True
	except ValueError:
		print(ERR_64)
		return False

def ft_otp(arg):
	with open(arg, "r") as file:
		secret_key = file.read().strip()
		byte_key = bytes.fromhex(secret_key) # convert to bytes
		current_time_step = int(time.time() // 30)  # 30 sec intervals (TOTP)
		counter_bytes = struct.pack(">Q", current_time_step) #convert into a BIG endian (baso a longlong)
		hmac_key = hmac.new(byte_key, counter_bytes, hashlib.sha1).digest()
		offset = hmac_key[-1] & 15  # truncated hash
		truncated_hash = hmac_key[offset:offset + 4]
		otp_t = struct.unpack(">I", truncated_hash)[0] & 0x7FFFFFFF #convert to int and mask to ensure its + value
		otp = str(otp_t % 10**6).zfill(6)
	print(f"Generated OTP: {otp}")

def ft_basic_checks(arg, file_t, typ):
	if arg.endswith(file_t) == False:
		print(f"Error: {typ} file must be in {file_t} format")
		exit(1)
	try:
		with open(arg, "r") as file:
			secret_key = file.read().strip()
			if ft_is_valid_hex(secret_key):
				print(f"Key: {secret_key} is valid.")
			else:
				print("Error: Invalid Key format.")
				return None
	except Exception:
		print(f"Error: Could not open file {arg}")
		exit(1)

def main():
	args = ft_parse_arguments()
	if args.g:
		ft_save(args.g)
	elif args.k:
			ft_otp(args.k)  # Generate OTP using the stored key

if __name__ == "__main__":
	main()

#salt hashing ensures that there will always be some randomness to the hash
# eg if 2 people have the smae pasweord, salt ensures the hash value wil;l always be unique