#!/usr/bin/env python3


# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# Panopticon
# Florian Roth
# Arnim Rupp
#
# IMPORTANT: Requires plyara

__version__ = "0.4.0"

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
from rich.console import Console
import gc
#import pprint

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

CALIBRATION_RULES = yr

samples_data=[]
rule_num=0

count = 0
for s in SAMPLE_SET:
    if not os.path.exists(s):
        print("[E] Error: sample directory '%s' doesn't exist" % s)
    else:
        for (dirpath, dirnames, filenames) in os.walk(s):
            for filename in filenames:
                count += 1
                sample_file = os.path.join(dirpath, filename)
                with open(sample_file, 'rb') as fh:
                    fdata = fh.read()
                    samples_data.append(fdata)

warnings_list =[]
warning_rules_file = 'warning_rules.yar'
warning_rules = open(warning_rules_file, 'w')
warning_rules.write("// New panopticon run at " + time.strftime("%Y-%m-%d %H:%M:%S") + '\n\n' )

def log_warning_rich(msg, rule):
    Log.warning(msg)
    progress.console.print("[red]"+"[WARNING] "+"[/red]" + msg)
    progress.update(task2, advance=1)
    warnings_list.append(msg)
    warning_rules.write("// " + msg + "\n")
    warning_rules.write(rule)
    warning_rules.write("\n")

def measure(yara_rule_string, cycles, progress, show_score=True, c_duration=0, rule_name="", alert_diff=0, single_rule=""):
    """
    Measure rule performance
    :param yara_rule_string: the YARA rule to test
    :param cycles: number of iterations over the sample set
    :param progress: progress indicator
    :param show_score: show the performance score
    :param c_duration: duration of the calibration run
    :param alert_diff: difference to alert on
    :param single_rule: the separate rule that is going to be tested as string
    :return min_duration: minimal duration in seconds
    :return count: count of samples in the given samples folders
    :return diff_perc: the difference in percent
    """
    try:
        y = yara.compile(source=yara_rule_string, externals={
                                    'filename': "",
                                    'filepath': "",
                                    'extension': "",
                                    'filetype': "",
                                    'md5': "",
                                })
    except Exception as e:
        Log.error("Error compiling YARA rule '%s' : %s" % ( rule_name, e ))
        return 0,0,0
    #Log.info("Scanning sample set %d times with rule: %s" % (cycles, rule_name ))
    min_duration=9999999999999999
    max_duration=0
    diff_perc = 0
    count_mega_slow = 0

    for _ in range(cycles):
        # do garbage collection to avoid that it happens during benchmarking
        gc.collect()

        start = time.time()
        for sample in samples_data:
            try:
                matches = y.match(data=sample, externals={
                                    'filename': "",
                                    'filepath': "",
                                    'extension': "",
                                    'filetype': "",
                                    'md5': "",
                                })
            except Exception as e:
                Log.error("Error matching YARA rule '%s' : %s" % ( rule_name, e))
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
            # print("%s - %s" % (c_duration, min_duration))
            diff_perc = ( (min_duration / c_duration -1)*100 )
            # print("Diff Percentage: %0.4f" % diff_perc)

        # skip test if this scan was too fast
        if not slow_mode and diff_perc < alert_diff:
            progress.console.print("[INFO   ] Rule \"%s\" is fast enough, not measuring any further due to fast mode, diff %0.4f %% below alerting level: %0.4f %%" % (rule_name, diff_perc, alert_diff ))
            return 0,0,0

        # stop test if this scan was mega slow for 10th time => warning because alert_diff is high enough
        if not slow_mode and diff_perc > 2 * alert_diff:
            count_mega_slow += 1
        if count_mega_slow > 10:
            break

    if c_duration and not rule_name == "Baseline":
        if diff_perc > alert_diff:
            log_warning_rich("Rule \"%s\" slows down a search with %d rules by %0.4f %% (Measured by best of %d runs)" % (rule_name, num_calib_rules, diff_perc , cycles ), single_rule)
        else:
            if show_score:
                progress.console.print("[INFO   ] Rule: \"%s\" - Best of %d - duration: %.4f s (%0.4f s, %0.4f %%)" % (rule_name, cycles, min_duration, (min_duration-c_duration), diff_perc ))
    else:
        progress.console.print("[INFO   ] Rule: \"%s\" - best of %d - duration: %.4f s" % (rule_name, cycles, min_duration))
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

    # Check the YARA rule input files and directories
    input_files = []
    if args.f or args.d:
        # File list
        if args.f:
            for f in args.f[0]:
                if not os.path.exists(f):
                    Log.error("[E] Error: input file '%s' doesn't exist" % f)
                    sys.exit(1)
                else:
                    input_files.append(f)
        # Directory list
        if args.d:
            for d in args.d[0]:
                if not os.path.exists(d):
                    Log.error("[E] Error: input directory '%s' doesn't exist" % d)
                    sys.exit(1)
                else:
                    for f in (os.listdir(d)):
                        if ".yar" in f:
                            input_files.append(os.path.join(d, f))

    # Loop over input files
    rules_list = []
    rules_all = ""
    for f in input_files:
        # Parse YARA rules to Dictionary
        if not os.path.exists(f):
            Log.error("Cannot find input file '%s'" % f)
            sys.exit(1)
        try:
            Log.info("Processing rules from %s ..." % f)
            p = plyara.Plyara()
            file_data = ""
            # Read file
            with open(f, 'r') as fh:
                file_data = fh.read()
            # Skip files without rule
            if 'rule' not in file_data:
                continue
            rules_all += file_data
        except Exception as e:
            Log.error("Can't process YARA rule file '%s'" % f)
            traceback.print_exc()

    # Now parse the YARA rules
    try:
        rules_list += p.parse_string(file_data)
        Log.info("Parsed %d rules from %s" % (len(rules_list), f))
        # input_file_names.append(os.path.basename(f))
    except Exception as e:
        Log.error("Error parsing YARA rule file '%s'" % f)
        traceback.print_exc()
        sys.exit(1)

    # Check the imports used by the rules to be tested
    used_imports = []
    for rule in rules_list:
        if "imports" in rule:
            for i in rule["imports"]:
                if i not in used_imports:
                    used_imports.append(i)
    Log.info("Imports used by the rules to test (will be prepended to the calibration set): %s" % ' '.join(used_imports))

    # Preparing the calibration rules
    p = plyara.Plyara()
    # Appending the imports used in the test rules
    prepend_imports = ""
    for i in used_imports:
        prepend_imports += 'import "%s"' % i
    calibration_rule_set = prepend_imports + CALIBRATION_RULES
    # Parse the calibration rule set    
    calibration_rules = p.parse_string(calibration_rule_set)
    num_calib_rules = len(calibration_rules)
    Log.info("Number of calibration rules: " + str(num_calib_rules))

    # Now start the measurements 
    with Progress(transient=True) as progress:
        # Calibration
        if not args.i:
            # Evaluate an optimal amount of cycles if nothing has been set manually
            calib_duration, sample_count, diff_perc = measure(calibration_rule_set, 1, progress, show_score=False, rule_name='Baseline')
            # One measurement should take 5 seconds
            auto_cycles = math.ceil(int(args.s) / calib_duration)
            cycles = auto_cycles
        else:
            # When cycle setting(option -i), occur error "sample_count not setting error"
            # set measure function same, error fix!
            # Evaluate an optimal amount of cycles if nothing has been set manually
            calib_duration, sample_count, diff_perc = measure(calibration_rule_set, 1, progress, show_score=False, rule_name='Baseline')
            cycles = int(args.i)

        # Startup
        Log.info("Auto-evaluation calculated that the defined %d seconds per rule can be accomplished by %d cycles per "
                 "rule over the given sample set of %d samples" % (int(args.s), cycles, sample_count))
        Log.info("Running %d cycles over the sample set" % cycles)
        Log.info("Now the benchmarking begins ... (try not cause any load on the system during benchmarking)")

        # Calibration Score
        baseline_calib_times = int(args.c)
        baseline_test_times = int(args.m)

        Log.info("Running baseline measure " + str(baseline_calib_times) + " times with " + str(cycles) + " cycles each to get a good average, dropping the worst result")
        crule_duration_total=0
        crule_duration_max=0
        for x in range(baseline_calib_times):
            crule_duration_tmp, count, diff_perc = measure(calibration_rule_set, cycles, progress, show_score=True, rule_name='Baseline')
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
            Log.info("Running baseline measure %s times with %s cycles (dropping the worst) to measure inaccuracy" % (baseline_test_times, cycles))
            min_diff_perc = 9999999999999999
            max_diff_perc = 0
            max_diff_perc_2nd = 0
            for x in range(baseline_test_times):
                crule_duration_tmp, count, diff_perc = measure(calibration_rule_set, cycles, progress, c_duration=crule_duration, show_score=True, rule_name='Baseline')
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

        slow_mode = args.S

        # avoid mixing up output of rich and logging to console, only log to file from here on
        # yep, this mix of logging and rich is ugly
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

        # first test all at once (this might easily fail on multiple files with duplicate rulenames)
        #measure_rule = CALIBRATION_RULES + rules_all
        #rule_name = "All " + str(len(rules_list)) + " rules from all input files"
        #measure(measure_rule, cycles, progress, show_score=True, c_duration=crule_duration, rule_name=rule_name, alert_diff=alert_diff)

        # Scan files
        for r in rules_list:
            yara_rule_string = plutils.rebuild_yara_rule(r)
            rule_name = r['rule_name']
            if len(yara_rule_string) > 20000:
                log_warning_rich("Big rule: " + rule_name + " has " + str(len(yara_rule_string)) + " bytes", yara_rule_string)

            measure_rule = calibration_rule_set + yara_rule_string

            measure(measure_rule, cycles, progress, show_score=True, c_duration=crule_duration, rule_name=rule_name, alert_diff=alert_diff, single_rule=yara_rule_string)
            progress.update(task1, advance=1)

    # rich console
    console = Console()
    console.print("")
    console.print("----------------------------------------------------------------------------------------------------------------")
    console.print("Done scanning " + str(rule_num) + " rules.")
    if warnings_list:
        console.print("Check the collected warnings below are look in " + args.l + " for \"WARNING\".")
        console.print("All offending rules written to \"" + warning_rules_file + "\" (hint: useful for rechecking)")
        for msg in warnings_list:
            console.print("[red]"+"[WARNING] "+"[/red]" + msg)
    else:
        console.print("Everything [green]ok[/green], log written to " + args.l)

    # reenable console logging because this should be on screen and in logfile
    Log.addHandler(consoleHandler)
    Log.info("Ending measurement at: " + time.strftime("%Y-%m-%d %H:%M:%S") )
    warning_rules.write("// End of panopticon run at " + time.strftime("%Y-%m-%d %H:%M:%S") + '\n\n' )
