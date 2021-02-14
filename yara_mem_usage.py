#!/usr/bin/env python3 


# yara memory measurement
# shows the increase in used memory if itself after loading and compiling a .yar file with yara-python
# by arnim rupp


import os, psutil
import argparse
import yara
import resource

baseline = 8460
baseline_res = 8448

process = psutil.Process(os.getpid())

parser = argparse.ArgumentParser(description='yara memory measurement')
parser.add_argument('RULES_FILE', help='Path to rules file')
args = parser.parse_args()

rulesfile = args.RULES_FILE

before =int (process.memory_info().rss/1024) 
before_res = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
rules = yara.compile(filepaths={
      'rules':rulesfile
                            }, 
                                externals={
                                    'filename': "",
                                    'filepath': "",
                                    'extension': "",
                                    'filetype': "",
                                    'md5': "",
                                })

after =int (process.memory_info().rss/1024) 
after_res = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

# actually scanning doesn't make a difference in memory use except of course the size of the read files
#print(rulesfile + ': psutil: {:,}'.format(after - before - baseline) + ' KB -- resource:  {:,}'.format(after_res - before_res - baseline_res) + ' KB')
#filePath = "/etc/timezone"
#with open(filePath, 'rb') as f:
    #fileData = f.read()
# Scan the data read from file
#try:
    #matches = rules.match(data=fileData)
#except Exception as e:
    #print("ERROR", "FileScan", "Cannot YARA scan file: %s" % filePath)


after =int (process.memory_info().rss/1024) 
after_res = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
print(rulesfile + ': psutil: {:,}'.format(after - before - baseline) + ' KB -- resource:  {:,}'.format(after_res - before_res - baseline_res) + ' KB')



