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

from cryptography.fernet import Fernet
import os
import sys
import re
import pyotp
import argparse
import struct
import string
import hashlib
import hmac
import base64
import time

ERR_64 = "Error: The key must be at least 64 hexidecimal characters."
k_file = ".key"
k = "key"
fkey = Fernet.generate_key()
f = Fernet(fkey)

def ft_parse_arguments():
	parser = argparse.ArgumentParser(description="""*** ft_otp *** OTP Generator""")
	parser.add_argument("-g", help="Hashes and stores a 64-bit hexadecimal key securely in ft_otp.key")
	parser.add_argument("-k", help="Generates a one-time password using the stored key")
	args = parser.parse_args()

	if not args.g and not args.k:
		parser.error("Try -h for help.")
	if args.g:
		ft_basic_checks(args.g)
	else:
		k_file_check(args.k)
		ft_basic_checks(args.k)
	return args

def k_file_check(arg):
	if arg.endswith(k_file) == False:
		print(f"Error: {k} file must be in {k_file} format")
		exit(1)

# def ft_save(file_name):
# 	with open(file_name, 'r') as file:
# 		hex_key = file.read()
# 		salt = os.urandom(16)
# 		comb = salt + bytes.fromhex(hex_key)
# 		# We create a hash using sha256 algorithm
# 		hash_obj = hashlib.sha256(comb)
# 		encrypted_str = hash_obj.hexdigest()
# 		with open('ft_otp.key', 'w') as key_key:
# 			key_key.write(encrypted_str)
# 	print('SUCCESSSSS! Your key was successfully saved in ft_otp.key.')

# def ft_hash(file_name):
# 	with open(file_name, "r") as file:
# 		hex_key = file.read()
# 		hash_obj = hashlib.sha256(hex_key.encode("utf-8"))
# 		encrypted_str = hash_obj.hexdigest()
# 		base64_key = base64.b64encode(encrypted_str)
# 		return base64_key

def ft_save(file_name):
	with open(file_name, "r") as file:
		hex_key = file.read().strip()
		if not ft_is_valid_hex(hex_key):
			return
		hex_key_bytes = bytes.fromhex(hex_key)
		encrypted_key = f.encrypt(hex_key_bytes) #fernet encription
		with open("ft_otp.key", "wb") as key_file:
			key_file.write(encrypted_key)
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
	with open(arg, "rb") as file:
		encrypted_key = file.read() # open the encrypted file
		try:
			secret_key = f.decrypt(encrypted_key).decode() #decrypt the key
		except Exception as e:
			print(f"Error: Unable to decrypt the key: {e}")
			return
		byte_key = bytes.fromhex(secret_key) # convert to bytes
		current_time_step = int(time.time() // 30)  # 30 sec intervals (TOTP)
		counter_bytes = struct.pack(">Q", current_time_step) #convert into a BIG endian (baso a longlong)
		hmac_key = hmac.new(byte_key, counter_bytes, hashlib.sha1).digest()
		offset = hmac_key[-1] & 15  # truncated hash
		truncated_hash = hmac_key[offset:offset + 4]
		otp_t = struct.unpack(">I", truncated_hash)[0] & 0x7FFFFFFF #convert to int and mask to ensure its + value
		otp = str(otp_t % 10**6).zfill(6)
	print(f"Generated OTP: {otp}")

def ft_basic_checks(arg):
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