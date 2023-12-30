#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Dec 21 20:48:51 2023

@author: richardm
"""

from os import *


def create_file ():
    filename = input ("Enter file name: ")
    try:
        with open (filename, 'w') as f:
            f.write('Type something...')
        print("Success !!!")
    except IOError:
        print("Error: could not create file: " + filename)
    
def write_file ():
    filename = input ("Enter file name: ")
    try:
        with open(filename, 'a') as f:
            f.write(text)
        print ("Successfully wrote text.")
    except IOError:
        print ("Error: could not write data to: " + filename)
    
def erase_data ():
    filename = input ("Enter file name: ")
    try:
        with open (filename, 'w') as f:
            f.write('')
        print ("Success !!!")
    except IOError:
        print ("Error: could not erase data in file: " + filename)
    
def delete_file ():
    filename = input ("Enter file name: ")
    try:
        remove (filename)
        print ("File " + filename + " deleted successfully.")
    except IOError:
        print ("Error: could not delete file: " + filename)
        
def read_file ():
    filename = input ("Enter file name: ")
    try:
        with open (filename, 'r') as f:
            for x in f:
                print (f.readline())
    except IOError:
        print ("Error: could not read file " + filename)
        
def rename_chosen_file ():
    filename = input ("Enter file name: ")
    new_filename = input ("Enter new file name: ")
    try:
        rename(filename, new_filename)
        print ("Successfully renamed file !!!")
        
    except OSError:
        print ("File not found.")
        
        
while True:
    option = input (
        
"""Welcome to your file manager !!!

Here you can write, delete text, create and extract text from the file.



Please choose your option: 
    
    1: Read
    2: Delete
    3: Write
    4: Erase
    5: Create
    6: Quit
    7: Rename
    
    
Type option: """)

    if option == "1":
        read_file()
        
    if option == "2":
        delete_file()
        
    if option == "3":
        write_file()
        
    if option == "4":
        erase_data()
        
    if option == "5":
        create_file()
        
    if option == "6":
        print ()
        print ("Program finished.")
        break
    
    if option == "7":
        rename_chosen_file ()
    

        
