#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# Panopticon
# Florian Roth
#
# IMPORTANT: Requires plyara

__version__ = "0.2.0"

import os
import argparse
import logging
import platform
import sys
import plyara
import math
from plyara import utils as plutils
import yara
import traceback
import time

SAMPLE_SET = ['./samples']

CALIBRATION_RULE = """
rule Calibration_Rule {
    strings:
        $ = "Fubar, you lose again!" 
        $ = "A strange game. The only winning move is not to play."
        $ = "I'm sorry Dave, I'm afraid I can't do that."
    condition:
        1 of them
}
"""


def measure(rule, cycles, show_score=True, c_duration=0):
    """
    Measure rule performance
    :param rule: the YARA rule to test
    :param cycles: number of iterations over the sample set
    :param show_score: show the performance score
    :param c_duration: duration of the calibration run
    :return duration: duration in seconds
    :return count: count of samples in the given samples folders
    """
    yara_rule_string = plutils.rebuild_yara_rule(rule)
    y = yara.compile(source=yara_rule_string)
    Log.info("Scanning sample set with rule: %s" % rule['rule_name'])
    start = time.time()
    count = 0
    for s in SAMPLE_SET:
        if not os.path.exists(s):
            Log.error("[E] Error: sample directory '%s' doesn't exist" % s)
        else:
            for (dirpath, dirnames, filenames) in os.walk(s):
                for filename in filenames:
                    count += 1
                    for _ in range(cycles):
                        sample_file = os.path.join(dirpath, filename)
                        with open(sample_file, 'rb') as fh:
                            fdata = fh.read()
                            matches = y.match(data=fdata)
    end = time.time()
    duration = end - start
    if show_score:
        # If a calibration duration has been evaluated
        if c_duration > 0:
            print("Performance Score: %.2f (%0.2f)" % (duration, (duration-c_duration)))
        else:
            print("Performance Score: %.2f" % duration)
    return duration, count


if __name__ == '__main__':

    print("    ___                      __  _              ")
    print("   / _ \\___ ____  ___  ___  / /_(_)______  ___  ")
    print("  / ___/ _ `/ _ \\/ _ \\/ _ \\/ __/ / __/ _ \\/ _ \\ ")
    print(" /_/   \\_,_/_//_/\\___/ .__/\\__/_/\\__/\\___/_//_/ ")
    print(" by Florian Roth    /_/ v%s                 " % __version__)
    print(" ")
    print(" YARA Rule Performance Testing")

    # Parse Arguments
    parser = argparse.ArgumentParser(description='YARA RULE PERFORMANCE TESTER')
    parser.add_argument('-f', action='append', nargs='+', help='Path to input files (YARA rules, separated by space)',
                        metavar='yara files')
    parser.add_argument('-d', action='append', nargs='+',
                        help='Path to input directory (YARA rules folders, separated by space)', metavar='yara files')
    parser.add_argument('-l', help='Log file (default: panopticon.log)', metavar='logfile', default=r'panopticon.log')
    parser.add_argument('-i', help='Number of iterations (default: auto)', metavar='iterations')
    parser.add_argument('-s', help='Number of seconds to spend for each rule\'s measurement', metavar='seconds',
                        default=15)
    args = parser.parse_args()

    # Logging
    logFormatter = logging.Formatter("[%(levelname)-5.5s] %(message)s")
    logFormatterRemote = logging.Formatter("{0} [%(levelname)-5.5s] %(message)s".format(platform.uname()[1]))
    Log = logging.getLogger(__name__)
    Log.setLevel(logging.INFO)
    # File Handler
    fileHandler = logging.FileHandler(args.l)
    fileHandler.setFormatter(logFormatter)
    Log.addHandler(fileHandler)
    # Console Handler
    consoleHandler = logging.StreamHandler()
    consoleHandler.setFormatter(logFormatter)
    Log.addHandler(consoleHandler)

    # Check the input files and directories
    input_files = []
    if args.f or args.d:
        # File list
        if args.f:
            for f in args.f[0]:
                if not os.path.exists(f):
                    Log.error("[E] Error: input file '%s' doesn't exist" % f)
                else:
                    input_files.append(f)
        # Directory list
        if args.d:
            for d in args.d[0]:
                if not os.path.exists(d):
                    Log.error("[E] Error: input directory '%s' doesn't exist" % d)
                else:
                    for f in (os.listdir(d)):
                        if ".yar" in f:
                            input_files.append(os.path.join(d, f))

    # Calibration rule
    p = plyara.Plyara()
    calibration_rule = p.parse_string(CALIBRATION_RULE)

    # Loop over input files
    rules_list = []
    for f in input_files:
        # Parse YARA rules to Dictionary
        if not os.path.exists(f):
            Log.error("Cannot find input file '%s'" % f)
            sys.exit(1)
        try:
            Log.info("Processing %s ..." % f)
            p = plyara.Plyara()
            file_data = ""
            # Read file
            with open(f, 'r') as fh:
                file_data = fh.read()
            # Skip files without rule
            if 'rule' not in file_data:
                continue
            rules_list += p.parse_string(file_data)
            Log.info("Parsed %d rules from %s" % (len(rules_list), f))
            # input_file_names.append(os.path.basename(f))
        except Exception as e:
            Log.error("Error parsing YARA rule file '%s'" % f)
            traceback.print_exc()
            sys.exit(1)

    # Calibration
    if not args.i:
        # Evaluate an optimal amount of cycles if nothing has been set manually
        calib_duration, sample_count = measure(calibration_rule[0], 1, show_score=False)
        # One measurement should take 5 seconds
        auto_cycles = math.ceil(int(args.s) / calib_duration)
        cycles = auto_cycles
    else:
        cycles = int(args.i)

    # Startup
    Log.info("Auto-evaluation calculated that the defined %d seconds per rule could be accomplished by %d cycles per "
             "rule over the given sample set of %d samples" % (int(args.s), cycles, sample_count))
    Log.info("Running %d cycles over the sample set" % cycles)
    Log.info("Now the benchmarking begins ...")

    # Calibration Score
    crule_duration, count = measure(calibration_rule[0], cycles, show_score=True)

    # Scan files
    for r in rules_list:
        measure(r, cycles, show_score=True, c_duration=crule_duration)
