#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Feb 25 18:57:02 2023

@author: richardm
"""

import hashlib, bcrypt, argon2
from argon2 import PasswordHasher, Type

while True:
    choice = input ("""
Hello, this is your hash encoder. We have four choices : 

    1. Encode string to hash
    2. Quit
    3. Hash files
    
To encode the string, please type 
"Encode string to hash".
                    
To quit, please type "Quit".

To hash files, please type "Hash file".


                    
""")
    
    if choice == "Encode string to hash":
        
        salt_question = str (input ("""
Do you want salt ?
If no, type "N".
If yes, type "Y".

"""))
        hash_to = str (input ("String to encode : "))
        hash_type = str (input ("""
Enter hash type : 
If MD5, type MD5.
If SHA-224, type SHA-224.
                                  
etc... """))
        if salt_question == 'N':
            hash_prepare = hash_to.encode ("utf-8")
            
            if hashtype == "MD5":
                encoded = hashlib.md5 (hash_prepare).hexdigest ()
                
            elif hashtype == "SHA-224":
                encoded = hashlib.sha224 (hash_prepare).hexdigest ()
                
            elif hashtype == 'SHA-1':
                encoded = hashlib.sha1 (hash_prepare).hexdigest ()
                
            elif hashtype == 'SHA-256':
                encoded = hashlib.sha256 (hash_prepare).hexdigest ()
                
            elif hashtype == 'SHA-384':
                encoded = hashlib.sha384 (hash_prepare).hexdigest ()
                
            elif hashtype == 'SHA-512':
                encoded = hashlib.sha512 (hash_prepare).hexdigest ()
                
            elif hashtype == 'Blake2b':
                encoded = hashlib.blake2b (hash_prepare).hexdigest ()
                
            elif hashtype == 'Blake2s':
                encoded = hashlib.blake2s (hash_prepare).hexdigest ()
                

            
        elif salt_question == "Y":
            salt = str (input ("Enter salt : "))
            encoded = hash_to.encode ('utf-8')
            if salt == "":
                new_salt = bcrypt.gensalt ()
                
                if hashtype == "MD5":
                    encoded = hashlib.pbkdf2_hmac ("MD5", encoded, new_salt, 1000000).hex ()
                    
                elif hashtype == "SHA-224":
                    encoded = hashlib.sha224 (encoded + new_salt).hexdigest ()
                    
                elif hashtype == 'SHA-1':
                    encoded = hashlib.sha1(encoded + new_salt).hexdigest ()
                    
                elif hashtype == 'SHA-256':
                    encoded = hashlib.sha256(encoded + new_salt).hexdigest ()
                    
                elif hashtype == 'SHA-384':
                    encoded = hashlib.sha384(encoded + new_salt).hexdigest ()
                
                elif hashtype == 'SHA-512':
                    encoded = hashlib.sha512(encoded + new_salt).hexdigest ()
                
                elif hashtype == 'BLAKE2b':
                    encoded = hashlib.blake2b(encoded + new_salt).hexdigest ()
                
                elif hashtype == 'BLAKE2s':
                    encoded = hashlib.blake2s(encoded + new_salt).hexdigest ()
                
                elif hashtype == 'Bcrypt algorithm':
                    encoded = bcrypt.hashpw (encoded, new_salt)
                    
                elif hashtype == 'Argon2 algorithm':
                    encoded = argon2.hash (encoded)
            
                print ()
                print ("The hash below : {0}.".format (encoded))
                
            else:
                renew_salt = salt.encode ('utf-8')
                if hashtype == "MD5":
                    encoded_salt = hashlib.pbkdf2_hmac ("MD5", encoded, renew_salt, 1000000).hex ()
                
                elif hashtype == "SHA-224":
                    encoded_salt = hashlib.sha224 (encoded + renew_salt).hexdigest ()
                    
                elif hashtype == 'SHA-1':
                    encoded_salt = hashlib.sha1 (encoded + renew_salt).hexdigest ()
                    
                elif hashtype == 'SHA-256':
                    encoded_salt = hashlib.sha256 (encoded + renew_salt).hexdigest ()
                    
                elif hashtype == 'SHA-384':
                    encoded_salt = hashlib.sha384 (encoded + renew_salt).hexdigest ()
                
                elif hashtype == 'SHA-512':
                    encoded_salt = hashlib.sha512 (encoded + renew_salt).hexdigest ()
                
                elif hashtype == 'BLAKE2b':
                    encoded_salt = hashlib.blake2b (encoded + renew_salt).hexdigest ()
                
                elif hashtype == 'BLAKE2s':
                    encoded_salt = hashlib.blake2s (encoded + renew_salt).hexdigest ()
                
                elif hashtype == 'Bcrypt algorithm':
                    encoded_salt = bcrypt.hashpw (encoded, renew_salt)
                    

                    
                
                print ()
                print ("The hash below : {0}.".format (encoded_salt))
    
    elif choice == "Hash file":
        salt_question = input ("""
Do you want salt ?
If no, type "N".
If yes, type "Y".

""")
        hashtype_file = str (input ("""Enter hash type : 
If MD5, type MD5.
If SHA-224, type SHA-224.
                                      
etc...
            
                                      
"""))
        file_to_hash = input ("Enter file name : ")
        with open (file_to_hash, 'rb') as hash_procedure:
            data_hash = hash_procedure.read ()
            
        if salt_question == "N":
            
            
            if hashtype_file == "MD5":
                encoded_file = hashlib.md5 (data_hash).hexdigest ()
                
            elif hashtype_file == "SHA-224":
                encoded_file = hashlib.sha224 (data_hash).hexdigest ()
                    
            elif hashtype_file == "SHA-256":
                encoded_file = hashlib.sha256 (data_hash).hexdigest ()
                    
            elif hashtype_file == "SHA-1":
                encoded_file = hashlib.sha1 (data_hash).hexdigest ()
                
            elif hashtype_file == "SHA-384":
                encoded_file = hashlib.sha384 (data_hash).hexdigest ()
                    
            elif hashtype == 'SHA-512':
                encoded_file = hashlib.sha512 (data_hash).hexdigest ()
                    
            elif hashtype == 'Blake2b':
                encoded_file = hashlib.blake2b (data_hash).hexdigest ()
                    
            elif hashtype == 'Blake2s':
                encoded_file = hashlib.blake2s (data_hash).hexdigest ()
                    
            elif hashtype == 'Argon2 algorithm':
                ph = PasswordHasher (
        memory_cost=65536,
        time_cost=4,
        parallelism=2,
        hash_len=256,
        type=Type.ID
    )
                encoded_file = ph.hash (data_hash)
                
            print ()
            print ("The hash below : {0}.".format (encoded_file)) 
        
        if salt_question == 'Y':
            salt_for_file = input ("Enter salt : ")
                
            if salt_for_file == "":
                new_salted = bcrypt.gensalt ()
                if hashtype_file == "MD5":
                    encoded_salt_file_random = hashlib.pbkdf2_hmac ("MD5", data_hash, new_salted, 100000000).hex () 
                
                elif hashtype_file == "SHA-1":
                    encoded_salt_file_random = hashlib.sha1 (data_hash + new_salted).hexdigest ()
                
                elif hashtype_file == "SHA-256":
                    encoded_salt_file_random = hashlib.sha256 (data_hash + new_salted).hexdigest ()
                    
                elif hashtype_file == "SHA-224":
                    encoded_salt_file_random = hashlib.sha224 (data_hash + new_salted).hexdigest ()
                    
                elif hashtype_file == "SHA-384":
                    encoded_salt_file_random = hashlib.sha384 (data_hash + new_salted).hexdigest ()
                    
                elif hashtype_file == "SHA-512":
                    encoded_salt_file_random = hashlib.sha512 (data_hash + new_salted).hexdigest ()
                    
                elif hashtype_file == "BLAKE2s":
                    encoded_salt_file_random = hashlib.blake2s (data_hash + new_salted).hexdigest ()
                
                elif hashtype_file == "BLAKE2b":
                    encoded_salt_file_random = hashlib.blake2b (data_hash + new_salted).hexdigest ()
                
                elif hashtype_file == "Bcrypt algorithm":
                    encoded_salt_file_random = bcrypt.hashpw (data_hash, new_salted)
                    
                elif hashtype_file == "Argon2 algorithm":
                    ph = PasswordHasher (
            memory_cost=65536,
            time_cost=4,
            parallelism=2,
            hash_len=256,
            type=Type.ID
        )
                    encoded_salt_file_random = ph.hash (data_hash)
                print ()
                print ("The hash below : {0}.".format (encoded_salt_file_random))
                
            else:
                if hashtype_file == "MD5":
                    salt_new = salt.encode ('utf-8')
                    encoded_salt_file = hashlib.pbkdf2_hmac ("MD5", data_hash, salt_new, 100000000).hex ()
                
                elif hashtype_file == "SHA-1":
                    encoded_salt_file = hashlib.sha1 (data_hash + salt_new).hexdigest ()
                    
                elif hashtype_file == "SHA-256":
                    encoded_salt_file = hashlib.sha256 (data_hash + salt_new).hexdigest ()
                    
                elif hashtype_file == "SHA-224":
                    encoded_salt_file = hashlib.sha224 (data_hash + salt_new).hexdigest()
                    
                elif hashtype_file == "SHA-384":
                    encoded_salt_file = hashlib.sha384(data_hash + salt_new).hexdigest()
                    
                elif hashtype_file == "SHA-512":
                    encoded_salt_file = hashlib.sha512 (data_hash + salt_new).hexdigest()
                    
                elif hashtype_file == "Blake2s":
                    encoded_salt_file = hashlib.blake2s(data_hash + salt_new).hexdigest()
                
                elif hashtype_file == "BLAKE2b":
                    encoded_salt_file = hashlib.blake2b(data_hash + salt_new).hexdigest()
                
                print ()
                print ("The hash below : {0}.".format (encoded_salt_file))
    
    
                
    elif choice == "Quit":
        print ("Goodbye !!!")
        break