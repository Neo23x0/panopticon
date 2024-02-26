#!/usr/bin/env python3 


# yara memory measurement
# shows the increase in used memory if itself after loading and compiling a .yar file with yara-python
# by arnim rupp


import os, psutil
import argparse
import yara
import resource
import gc

def get_used_mem(process):
    proc_mem = int(process.memory_info().rss/1024) 
    res_get  = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if debug:
        print("process.memory_info(): " +str(proc_mem) + " - resource.getrusage: " + str(res_get) )
    return proc_mem, res_get


def load_and_unload_single_rule():
    # compile simple rule to activate yara
    rules = yara.compile(source='rule foo: bar {strings: $a = "lmn" condition: $a}')

    if debug: print("Compiled mini rule")
    before, before_res = get_used_mem(process)

    del rules

    if debug: print("Deleted rules")
    before, before_res = get_used_mem(process)

    gc.collect()

    if debug: print("Did garbage collection")
    before, before_res = get_used_mem(process)


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='yara memory measurement')
    parser.add_argument('RULES_FILE', help='Path to rules file')
    parser.add_argument('-d', help='Debug', action='store_true', default=False)
    parser.add_argument('-t','--thor', help='Use Thor/loki environment variables (needs more memory)', action='store_true', default=False)
    args = parser.parse_args()

    debug = args.d

    process = psutil.Process(os.getpid())

    rulesfile = args.RULES_FILE

    if debug: print("Just started python")
    before, before_res = get_used_mem(process)

    load_and_unload_single_rule()

    gc.collect()
    if debug: print("Did garbage collection")
    before, before_res = get_used_mem(process)

    if not args.thor:
        rules = yara.compile(filepaths={ 'rules':rulesfile })
    else:
        rules = yara.compile(filepaths={
              'rules':rulesfile
                                    }, 
                                        externals={
                                            'filename': "",
                                            'filepath': "",
                                            'extension': "",
                                            'filetype': "",
                                            'md5': "",
                                            'filemode': 0,
                                            'owner': "",
                                        })

    if debug: print("Compile rules to evaluate")
    after, after_res = get_used_mem(process)

    print(rulesfile + ':  -- resource:  {:,}'.format(after_res - before_res ) + ' KB')



