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
import argparse
from cryptography.fernet import Fernet
import string
import hashlib
import hmac
import time

ERR_64 = "Error: The key must be 64 hexidecimal characters."
secret_key = None

def parse_arguments():
	parser = argparse.ArgumentParser(description="""*** ft_otp *** This is a double factor of autentication tool based 
		in algorithm TOTP (Time based One-Time Password)""")
	parser.add_argument("-g", help="Store a 64-bit hexadecimal key securely in ft_otp.key")
	parser.add_argument("-k", help="Generate a one-time password using the stored key")
	args = parser.parse_args()

	if not args.g and not args.k:
		parser.error("Try -h for help.")
	# if args.g and args.k:
	# 	parser.error("You cannot use both '-g' and '-k' at the same time.")
	return args

def is_valid_hex(key):
	if len(key) != 64:
		print(ERR_64)
		return False
	try:
		int(key, 16)
		return True
	except ValueError:
		print(ERR_64)
		return False

def otp_gen(secret_key):
	# Convert the secret_key (hex) to bytes
	byte_key = bytes.fromhex(secret_key)

	current_time_step = int(time.time() // 30) # 30 sec intervals bc thats what most auth apps use
	counter_bytes = struct.pack(">Q", current_time_step)  # 8-byte counter (BIG-endiannnn - its baso a longlong)
	hmac_key = hmac.new(byte_key, counter_bytes, hashlib.sha1).digest()

	offset = hmac_result[-1] & 0x0F
	truncated_hash = hmac_result[offset:offset + 4]

	# Convert truncated hash to an integer and mask to ensure it's positive
	otp = struct.unpack(">I", truncated_hash)[0] & 0x7FFFFFFF
	otp = otp % 1000000  # 6-digit OTP

	return str(otp).zfill(6)

def main():
	args = parse_arguments()
	if args.g:
		with open(args.g, "r") as file:
			secret_key = file.read().strip()
		if is_valid_hex(secret_key):
			print(f"Key: {secret_key} is valid.")
		else:
			print("Error: Invalid Key format.")
			return
	if args.k:
		if 'secret_key':
			otp = otp_gen(secret_key)
			print(f"Generated OTP: {otp}")
		else:
			print("Error: Key is required to generate OTP. Use the -g option to provide the key.")
		# if all(c in string.hexdigits for c in secret_key):
		# 	byte_key = bytes.fromhex(secret_key)

if __name__ == "__main__":
	main()