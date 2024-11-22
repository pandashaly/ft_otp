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
import time

ERR_64 = "Error: The key must be 64 hexidecimal characters."

def check_args(args):
	for x in args:
		if "." in x:
			return 1
	return 2

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

#def check_key(args):
#	if is_valid_hex(args):
#		print("key looks sigma")

#	with = open("ft_otp.key", "w"):
#	sys.stdout = file
#	sys.stdout = original_stdout
#	print("Key was successfully saved in ft_otp.key.")

def en(args):

	key = Fernet.generate_key()
	fernet = Fernet(key)
	encKey = fernet.encrypt(args.encode())
	return encKey

def main():
	args = parse_arguments()  # Parse arguments and check them
	
	# Example of how you can use the arguments:
	if args.g:
		with open(args.g, "r") as file:
			secret_key = file.read().strip()  # Read the key from the file
		# check_key(secret_key)
		print(secret_key)
	if args.k:
		if all(c in string.hexdigits for c in secret_key):
			byte_key = bytes.fromhex(secret_key)
		print(f"Generating OTP with the stored key.")


if __name__ == "__main__":
	main()