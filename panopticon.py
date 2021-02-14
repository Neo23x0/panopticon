#!/usr/bin/env python3

# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# Panopticon
# Florian Roth
# Arnim Rupp
#
# IMPORTANT: Requires plyara

__version__ = "0.3.0"

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
from rich.progress import track
from rich.progress import Progress
import gc

SAMPLE_SET = ['./samples']
CALIBRATION_RULE_HUGE = './baseline.yar'

CALIBRATION_RULE_ONE = """
rule Calibration_Rule {
    strings:
        $ = "Fubar, you lose again!" 
        $ = "A strange game. The only winning move is not to play."
        $ = "I'm sorry Dave, I'm afraid I can't do that."
    condition:
        1 of them
}
"""

with open(CALIBRATION_RULE_HUGE, 'r') as f:
    yr = f.read()

CALIBRATION_RULE = yr

samples=[]
rule_num=0

count = 0
for s in SAMPLE_SET:
    if not os.path.exists(s):
        Log.error("[E] Error: sample directory '%s' doesn't exist" % s)
    else:
        for (dirpath, dirnames, filenames) in os.walk(s):
            for filename in filenames:
                count += 1
                sample_file = os.path.join(dirpath, filename)
                with open(sample_file, 'rb') as fh:
                    fdata = fh.read()
                    samples.append(fdata)


def measure(rule, cycles, progress, show_score=True, c_duration=0, rule_name="", alert_diff=0):
    """
    Measure rule performance
    :param rule: the YARA rule to test
    :param cycles: number of iterations over the sample set
    :param show_score: show the performance score
    :param c_duration: duration of the calibration run
    :return duration: duration in seconds
    :return count: count of samples in the given samples folders
    """
    yara_rule_string = rule

    try:
        y = yara.compile(source=yara_rule_string, externals={
                                    'filename': "",
                                    'filepath': "",
                                    'extension': "",
                                    'filetype': "",
                                    'md5': "",
                                })
    except Exception as e:
        Log.error("Error compiling YARA rule '%s' : %s" % (rule_name, e))
        return 0,0,0
    #Log.info("Scanning sample set %d times with rule: %s" % (cycles, rule_name))
    min_duration=9999999999999999
    max_duration=0
    diff_perc = 0
    for _ in range(cycles):
        # do garbage collection to avoid that it happens during benchmarking
        gc.collect()

        start = time.time()
        for sample in samples:
            try:
                matches = y.match(data=sample, externals={
                                    'filename': "",
                                    'filepath': "",
                                    'extension': "",
                                    'filetype': "",
                                    'md5': "",
                                })
            except Exception as e:
                Log.error("Error matching YARA rule '%s' : %s" % (rule_name, e))
                traceback.print_exc()
                # TODO: sys.exit or not???
                #sys.exit(1)
        end = time.time()
        duration = end - start

        if duration < min_duration:
            min_duration = duration
            #print("New min: ", duration)
        if duration > max_duration:
            max_duration = duration
            #print("New max: ", duration)

        # If a calibration duration has been evaluated
        if c_duration > 0:
            diff_perc = ( (min_duration / c_duration -1)*100 )

        # skip test if this scan fast too fast
        if not slow_mode and diff_perc < alert_diff:
            progress.console.print("[INFO   ] Rule is fast enough, not measuring any further %s due to fast mode, diff %0.4f %% below alerting level: %0.4f %%" % (rule_name, diff_perc, alert_diff ))
            return 0,0,0

    if c_duration and not rule_name == "Baseline":
        if diff_perc > alert_diff:
            msg = ("Rule %s slows down a search with %d rules by %0.4f %% (Measured by best of %d runs)" % (rule_name, num_calib_rules, diff_perc , cycles ))
            Log.warning(msg)
            progress.console.print("[red]"+"[WARNING] "+"[/red]" + msg)
            progress.update(task2, advance=1)
        else:
            if show_score:
                progress.console.print("[INFO   ] Rule: %s - Best of %d - duration: %.4f s (%0.4f s, %0.4f %%)" % (rule_name, cycles, min_duration, (min_duration-c_duration), diff_perc ))
    else:
        progress.console.print("[INFO   ] Rule: %s - best of %d - duration: %.4f s" % (rule_name, cycles, min_duration))
    return min_duration, count, diff_perc


if __name__ == '__main__':

    print("    ___                      __  _              ")
    print("   / _ \\___ ____  ___  ___  / /_(_)______  ___  ")
    print("  / ___/ _ `/ _ \\/ _ \\/ _ \\/ __/ / __/ _ \\/ _ \\ ")
    print(" /_/   \\_,_/_//_/\\___/ .__/\\__/_/\\__/\\___/_//_/ ")
    print(" by Florian Roth    /_/ v%s                 " % __version__)
    print(" and Arnim Rupp")
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
    parser.add_argument('-s', help='Number of seconds to spend for each rule\'s measurement', metavar='seconds', default=30)
    parser.add_argument('-c', help='How often to run the iterations on the calibration rule', metavar='baseline_calib_times', default=5)
    parser.add_argument('-m', help='Number of normal runs to measure accuracy of calibration rule', metavar='baseline_test_times', default=5)
    parser.add_argument('-S', help='Slow mode, don\'t skip rule on first quick scan', action='store_true', default=False)
    parser.add_argument('-a', help='Alert bonus in percent: Only alert rules which slow down scans by this much percent (+ measured inaccuracy)', default=3)
    args = parser.parse_args()

    # don't to fast mode during calibration, it's set later by param
    slow_mode = True
    alert_bonus = int(args.a)

    # Logging
    logFormatter = logging.Formatter("[%(levelname)-7.7s] %(message)s")
    logFormatterRemote = logging.Formatter("{0} [%(levelname)-7.7s] %(message)s".format(platform.uname()[1]))
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

    Log.info("Starting measurement at: " + time.strftime("%Y-%m-%d %H:%M:%S") )

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
    else:
        # Provide at least an input file
        Log.error("You should at least provide a YARA file (-f) or a folder with YARA rules (-d)")
        sys.exit(1)

    # Calibration rule
    p = plyara.Plyara()
    calibration_rule = p.parse_string(CALIBRATION_RULE)
    num_calib_rules = len(calibration_rule)
    Log.info("Number of calibration rules: " + str(num_calib_rules))

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

    with Progress() as progress:
        # Calibration
        if not args.i:
            # Evaluate an optimal amount of cycles if nothing has been set manually
            calib_duration, sample_count, diff_perc = measure(CALIBRATION_RULE, 1, progress, show_score=False, rule_name='Baseline')
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
        baseline_calib_times = int(args.c)
        baseline_test_times = int(args.m)

        Log.info("Running baseline measure " + str(baseline_calib_times) + " times with " + str(cycles) + " cycles each to get a good average, droping the worst result")
        crule_duration_total=0
        crule_duration_max=0
        for x in range(baseline_calib_times):
            crule_duration_tmp, count, diff_perc = measure(CALIBRATION_RULE, cycles, progress, show_score=True, rule_name='Baseline')
            crule_duration_total += crule_duration_tmp
            if crule_duration_tmp >  crule_duration_max:
                crule_duration_max = crule_duration_tmp

        # drop worst result
        if baseline_calib_times > 1:
            crule_duration= ( crule_duration_total - crule_duration_max ) / ( baseline_calib_times -1 )
        else:
            crule_duration= crule_duration_total
        Log.info("Calibrate average baseline duration: " + str(crule_duration))

        if baseline_test_times:
            Log.info("Running baseline measure " + str(baseline_test_times) + " times with " + str(cycles) + " cycles (dropping the worst) to measure inaccuracy")
            min_diff_perc = 9999999999999999
            max_diff_perc = 0
            max_diff_perc_2nd = 0
            for x in range(baseline_test_times):
                crule_duration_tmp, count, diff_perc = measure(CALIBRATION_RULE, cycles, progress, c_duration=crule_duration, show_score=True, rule_name='Baseline')
                if crule_duration_tmp < crule_duration:
                    crule_duration_new = crule_duration_tmp
                if diff_perc < min_diff_perc:
                    min_diff_perc = diff_perc
                if diff_perc > max_diff_perc:
                    max_diff_perc_2nd = max_diff_perc
                    max_diff_perc = diff_perc
            Log.info("Min diff " + str(min_diff_perc) + " % -- max diff " + str(max_diff_perc_2nd) + " %")

            # we ignore results faster than baseline because that shouldn't happen anyway ;)
            # if it's slower, only alert it of it's at least 50% higher than the (imperfectly) measured inaccuracy + alert_bonus set by the user
            if max_diff_perc_2nd:
                alert_diff = max_diff_perc_2nd * 1.5 + alert_bonus
            else:
                alert_diff = max_diff_perc * 1.5 + alert_bonus
            Log.info("Setting warning diff to: " + str(alert_diff))

            # new value could be used to recalibrate crule_duration but that's not neccessarily clever because we want the average
            # crule_duration = crule_duration_new
            #Log.info("Recalibrated baseline duration: " + str(crule_duration))

        slow_mode = args.S

        # avoid mixing up output of rich and logging to console, only log to file from here on
        Log.removeHandler(consoleHandler)
        msg ="Calibrations done, now checking the rules"
        Log.info(msg)
        progress.console.print("[INFO   ][green] " + msg)
        
        rule_num=len(rules_list)
        task1 = progress.add_task("[green]Processing rules...", total=rule_num)
        if rule_num > 100:
            warning_bar_num = 100
        else:
            warning_bar_num = rule_num
        task2 = progress.add_task("[red]Warnings", total=warning_bar_num)

        # Scan files
        for r in rules_list:
            yara_rule_string = plutils.rebuild_yara_rule(r)
            rule_name = r['rule_name']
            if len(yara_rule_string) > 20000:
                msg =("Big rule: " + rule_name + " has " + str(len(yara_rule_string)) + " bytes")
                Log.warning(msg)
                progress.console.print("[red]" + msg + "[/red]")
                progress.update(task2, advance=1)

            measure_rule = CALIBRATION_RULE + yara_rule_string
            measure(measure_rule, cycles, progress, show_score=True, c_duration=crule_duration, rule_name=rule_name, alert_diff=alert_diff)
            progress.update(task1, advance=1)


    Log.info("Done scanning " + str(rule_num) + " rules. Check panoptiocon.log for \"WARN\" to get a list of rules slowing down your scans.")
    Log.info("Ending measurement at: " + time.strftime("%Y-%m-%d %H:%M:%S") )
