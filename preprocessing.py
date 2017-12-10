#!/usr/bin/env python3

import collections
import os
import random
import re
import argparse
from pathlib import Path

header = '''
% 1. Title: Android Malware Samples
% 
% 2. Sources:
%      (a) Creator: Pietro Borrello
%      (b) From: DREBIN: Effective and Explainable Detection of Android Malware in Your Pocket
%      (c) Date: November, 2017
% 

@relation android_malwares

'''

drebin_dir_str = ""
drebin_dir = None
data = collections.OrderedDict()

def collect_attributes():
    print('collecting attributes...')
    attributes = set()

    attr_file = open('attributes.txt','w')

    for _dir in os.listdir(drebin_dir):

        filename = os.fsdecode(_dir)
        #print(filename)
        with open(drebin_dir_str + '/feature_vectors/' + filename, 'r') as f:
            for line in f.readlines():
                attributes.add(line)
                #print(line,end='')

    attr_file.write(''.join(attributes))
    attr_file.close()

def load_attributes_svm():

    print('SVM:')
    attributes = {}
    malwares = set()

    with open(drebin_dir_str + "/sha256_family.csv", 'r') as sha:
        for line in sha.readlines():
            malwares.add(line.strip().split(',')[0])

    print('reading attributes...')
    with open('attributes.txt', 'r') as attr_file:
        lines = attr_file.readlines()
        i = 1
        for attr in lines:
            if attr not in attributes:
                attributes[attr] = i
                i+=1

    #print(attributes)

    with open('android_malwares.libsvm', 'w') as svm_file:
        print('writing data attributes...')
        for _dir in os.listdir(drebin_dir):
            filename = os.fsdecode(_dir)
            with open(drebin_dir_str + '/feature_vectors/' + filename, 'r') as app_file:
                file_attrs = []
                for line in app_file.readlines():
                    file_attrs.append(attributes[line])

                if filename in malwares:
                    svm_file.write('1') #malware
                else:
                    svm_file.write('-1') #notmalware
                    
                for file_attr in sorted(file_attrs):
                    svm_file.write(' ' + str(file_attr) + ':1')
                svm_file.write('\n')

def load_attributes_bayes():

    print('BAYES:')
    attributes = {}
    malwares = set()

    with open(drebin_dir_str + "/sha256_family.csv", 'r') as sha:
        for line in sha.readlines():
            malwares.add(line.strip().split(',')[0])

    print('reading attributes...')
    with open('attributes.txt', 'r') as attr_file:
        lines = attr_file.readlines()
        for i, attr in enumerate(lines):
            attr = re.sub("\W+", "", attr)
            if attr not in attributes:
                attributes[attr] = i

    #print(attributes)

    with open('android_malwares.bayes', 'w') as svm_file:
        print('writing data attributes...')
        for _dir in os.listdir(drebin_dir):
            filename = os.fsdecode(_dir)
            with open(drebin_dir_str + '/feature_vectors/' + filename, 'r') as app_file:
                file_attrs = []
                for line in app_file.readlines():
                    file_attrs.append(attributes[re.sub("\W+", "", line)])

                if filename in malwares:
                    svm_file.write('1\t')  # malware
                else:
                    svm_file.write('-1\t')  # notmalware

                for file_attr in sorted(set(file_attrs)):
                    svm_file.write(' ' + str(file_attr + 1))
                svm_file.write('\n')

def load_attributes_arff():
    print('ARFF:')
    attributes = {}
    malwares = set()
    attributes_list = []

    with open(drebin_dir_str + "/sha256_family.csv", 'r') as sha:
        for line in sha.readlines():
            malwares.add(line.strip().split(',')[0])

    print('reading attributes...')
    with open('attributes.txt', 'r') as attr_file:
        lines = attr_file.readlines()
        for i,attr in enumerate(lines):
            if attr not in attributes:
                attributes[attr] = i
                attributes_list.append(attr)

    #print(attributes)

    with open('android_malwares.arff','w') as arff_file:
        arff_file.write(header)
        print('writing header attributes...')
        for attr in attributes_list:
            arff_file.write('@ATTRIBUTE "' + attr.strip().replace('\\','\\\\') + '" NUMERIC\n')
        arff_file.write("@ATTRIBUTE class {Malware,NotMalware}\n")
        arff_file.write("@DATA\n")

        print('writing data attributes...')
        for _dir in os.listdir(drebin_dir):
            filename=os.fsdecode(_dir)
            with open(drebin_dir_str + '/feature_vectors/' + filename, 'r') as app_file:
                file_attrs = []
                for line in app_file.readlines():
                    file_attrs.append(attributes[line])
                arff_file.write("{")
                for file_attr in sorted(file_attrs):
                    arff_file.write(str(file_attr) + ' 1, ')
                if filename in malwares:
                    arff_file.write(str(len(attributes)) + ' Malware}\n')
                else:
                    arff_file.write(str(len(attributes)) + ' NotMalware}\n')

'''
Deprecated in favour of subset.py script in libsvm/tools
'''
def generate_test_and_train():
    with open('android_malwares.libsvm', 'r') as svm_file:
        lines = svm_file.readlines()
        print('generating training set...')
        with open('train_android_malwares.libsvm', 'w') as train_file:
            train_file.write(''.join(random.sample(lines,100000)))

        print('generating test set...')
        with open('test_android_malwares.libsvm', 'w') as test_file:
            test_file.write(''.join(random.sample(lines, 10000)))

def main():
    parser = argparse.ArgumentParser(description='Preprocesses DREBIN dataset which is expected to be in ./drebin, otherwise select the right folder with the option --drebin')
    parser.add_argument("-c", '--collect', help="wheter to perform arguments collection from the DREBIN dataset or not",
                    action="store_true")
    parser.add_argument('-t', "--type", choices=['svm', 'bayes', 'arff'], default='svm', help='select the type of file to be produced (default = "svm")')
    parser.add_argument('-d', "--drebin",
                        default='./drebin/', help='select the root of the drebin dataset')
    args = parser.parse_args()
    
    global drebin_dir_str
    drebin_dir_str = args.drebin
    global drebin_dir
    drebin_dir = os.fsencode(drebin_dir_str+"/feature_vectors/")

    try:
        if args.collect:
            collect_attributes()
        elif not Path("./attributes").is_file:
            print("Attributes file doesn't exists, so")
            collect_attributes()

        if args.type == 'svm':
            load_attributes_svm()
        elif args.type == 'arff':
            load_attributes_arff()
        elif args.type == 'bayes':
            load_attributes_bayes()
    except FileNotFoundError as e:
        print(type(e))
        print(e)
        parser.print_help()
    

if __name__ == "__main__":
    main()
