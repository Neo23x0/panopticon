#!/usr/bin/env python3


# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# Panopticon
# Florian Roth
# Arnim Rupp
#
# IMPORTANT: Requires plyara

__version__ = "0.5.0"

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

# Global verbosity level
VERBOSITY_LEVEL = False

def log_warning_rich(msg, rule, progress, warning_rules_file):
    Log.warning(msg)
    progress.console.print("[red]"+"[WARNING] "+"[/red]" + msg)
    progress.update(task2, advance=1)

    with open(warning_rules_file, 'a') as f:        
        f.write("// " + msg + "\n")
        f.write(rule)
        f.write("\n")

    return msg

def measure(yara_rule_string, cycles, progress, samples_data, warning_rules_file, show_score=True, c_duration=0, rule_name="", alert_diff=0, single_rule=""):
    """
    Measure rule performance

    :param yara_rule_string: the YARA rule to test
    :param cycles: number of iterations over the sample set
    :param progress: progress indicator
    :param samples_data: list containing the samples to test against
    :param warning_rules_file: file to write offending rules to
    :param show_score: show the performance score
    :param c_duration: duration of the calibration run
    :param alert_diff: difference to alert on
    :param single_rule: the separate rule that is going to be tested as string

    :return min_duration: minimal duration in seconds
    :return samples_count: count of samples in the given samples folders
    :return diff_perc: the difference in percent
    :return warning_message: warning message for an offending rule
    """
    
    warning_message = ""
    
    try:
        y = yara.compile(source=yara_rule_string, externals={
                                    'filename': "",
                                    'filepath': "",
                                    'extension': "",
                                    'filetype': "",
                                    'md5': "",
                                })
    except Exception as e:
        Log.error(f"Error compiling YARA rule '{rule_name}' : {e}")
        sys.exit(1)
        #return 0,0,0
    
    min_duration=9999999999999999
    max_duration=0
    diff_perc = 0
    count_mega_slow = 0

    for _ in range(cycles):
        # do garbage collection to avoid that it happens during benchmarking
        gc.collect()

        # Get the time before the start of the YARA matches
        start = time.time()
        for sample in samples_data:
            try:
                y.match(data=sample, externals={
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

        # Get the time after the end of the YARA matches
        end = time.time()

        # The duration the matches operation took is the difference between the start and end
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
            msg = "Rule \"%s\" slows down a search with %d rules by %0.4f %% (Measured by best of %d runs)" % (rule_name, num_calib_rules, diff_perc , cycles )
            warning_message = log_warning_rich(msg, single_rule, progress, warning_rules_file)
        else:
            if show_score:
                progress.console.print("[INFO   ] Rule: \"%s\" - Best of %d - duration: %.4f s (%0.4f s, %0.4f %%)" % (rule_name, cycles, min_duration, (min_duration-c_duration), diff_perc ))
    else:
        progress.console.print("[INFO   ] Rule: \"%s\" - best of %d - duration: %.4f s" % (rule_name, cycles, min_duration))
    #return min_duration, count, diff_perc
    return min_duration, len(samples_data), diff_perc, warning_message

def create_sample_data_list(sample_set):
    samples_data = []
    for s in sample_set:
        if not os.path.exists(s):
            Log.error(f"Sample directory '{s}' doesn't exist")
        else:
            for (subdirs, dirs, files) in os.walk(s):
                for f in files:
                    sample_file = os.path.join(subdirs, f)
                    with open(sample_file, 'rb') as fh:
                        fdata = fh.read()
                        samples_data.append(fdata)
    if not samples_data:
        Log.error(f"No samples were provided to test against")
        sys.exit(1)
    Log.info(f"Creating sample data list...")
    return samples_data

def init_logging(log_file):
    logFormatter = logging.Formatter("[%(levelname)-7.7s] %(message)s")
    logFormatterRemote = logging.Formatter("{0} [%(levelname)-7.7s] %(message)s".format(platform.uname()[1]))
    Log = logging.getLogger(__name__)
    fileHandler = logging.FileHandler(log_file)
    consoleHandler = logging.StreamHandler()

    Log.setLevel(logging.INFO)
    
    fileHandler.setFormatter(logFormatter)
    Log.addHandler(fileHandler)    
    consoleHandler.setFormatter(logFormatter)
    Log.addHandler(consoleHandler)

    return logFormatter, logFormatterRemote, Log, fileHandler, consoleHandler

def get_input_files(paramType, path):
    input_files = []
    if paramType == "file":
        for f in path:
            if not os.path.exists(f):
                Log.error(f"Input file '{f}' doesn't exist")
            else:
                input_files.append(f)
    elif paramType == "directory":
        for d in path:
                if not os.path.exists(d):
                    Log.error(f"Input directory '{d}' doesn't exist")
                else:
                    for subdirs, dirs, files in os.walk(d):
                        for f in files:
                            if not os.path.exists(f):
                                Log.error(f"Input file '{f}' doesn't exist")
                            elif f.endswith(".yar"):
                                input_files.append(os.path.join(subdirs, f))

    if input_files:
        return input_files
    else:
        Log.error("No files selected. Incorrect input files or directory")
        sys.exit(1)

def parse_yara(rules_files_list):
    rules_list = []
    plyara_ = plyara.Plyara()

    for rule_file in rules_files_list:
        
        Log.info(f"Processing rules from {rule_file} ...")

        with open(rule_file, "r") as rule_content:
            content = rule_content.read()
            try:
                parsed_file = plyara_.parse_string(content)
                for i in parsed_file:
                    rules_list.append(i)
                Log.info(f"Parsed {len(rules_list)} rules from {rule_file}")
            except Exception as e:
                Log.error(f"Error parsing YARA rule file: '{rule_file}' - {e}")
                if VERBOSITY_LEVEL:
                    traceback.print_exc()
                sys.exit(1)
    return rules_list

def get_imports_to_prepend(rules_list):
    used_imports = []
    for rule in rules_list:
        if "imports" in rule:
            for i in rule["imports"]:
                if i not in used_imports:
                    used_imports.append(i)
    Log.info(f"The following Imports are used by the rules to test (will be prepended to the calibration set): {', '.join(used_imports)}")

    prepend_imports = ""
    for i in used_imports:
        prepend_imports += f"import \"{i}\"\n"
    
    return prepend_imports

def get_num_calibration_rules(rules):
    plyara_ = plyara.Plyara()
    return len(plyara_.parse_string(rules))
    
def read_calibration_set(calibration_set):
    if not os.path.exists(calibration_set):
        Log.error(f"Calibration ruleset '{calibration_set}' doesn't exist")
    else:
        try:
            with open(CALIBRATION_RULE_HUGE, 'r') as f:
                calibration_rules = f.read()
                Log.info(f"Getting content of the calibration ruleset '{calibration_set}'...")
        except IOError as e:
            Log.error(f"Cannot read contents of '{calibration_set}'")
            sys.exit(1)

    return calibration_rules

def print_rich_warning(warnings_list, rules_num, logfile, warning_rules_file):
    
    console = Console()
    
    console.print("")
    console.print("-"*112)
    console.print(f"Done scanning {rules_num} rules.")

    if warnings_list:
        console.print(f"Check the collected warnings below and look in {logfile} for \"WARNING\".")
        console.print(f"All offending rules are written to \"{warning_rules_file}\" (hint: useful for rechecking)")
        for msg in warnings_list:
            console.print(f"[red][WARNING] [/red] {msg}")
    else:
        console.print(f"Everything [green]ok[/green], log written to {logfile}")

    Log.info("Ending measurement at: " + time.strftime("%Y-%m-%d %H:%M:%S") )

    with open(warning_rules_file, "a") as f:
        f.write("// End of panopticon run at " + time.strftime("%Y-%m-%d %H:%M:%S") + '\n\n' )
    

if __name__ == '__main__':

    print("    ___                      __  _              ")
    print("   / _ \\___ ____  ___  ___  / /_(_)______  ___  ")
    print("  / ___/ _ `/ _ \\/ _ \\/ _ \\/ __/ / __/ _ \\/ _ \\ ")
    print(" /_/   \\_,_/_//_/\\___/ .__/\\__/_/\\__/\\___/_//_/ ")
    print(" by Florian Roth    /_/ v%s                 " % __version__)
    print(" and Arnim Rupp")
    print(" ")
    print(" YARA Rule Performance Testing\n")

    # Parse Arguments
    parser = argparse.ArgumentParser(description='YARA RULE PERFORMANCE TESTER')
    parser.add_argument('-f', action='append', nargs='+', help='Path to input files (YARA rules, separated by space)', metavar='yara files')
    parser.add_argument('-d', action='append', nargs='+', help='Path to input directory (YARA rules folders, separated by space)', metavar='yara files')
    parser.add_argument('-l', help='Log file (default: panopticon.log)', metavar='logfile', default=r'panopticon.log')
    parser.add_argument('-i', help='Number of iterations (default: auto)', metavar='iterations')
    parser.add_argument('-s', help='Number of seconds to spend on each rule\'s measurement', metavar='seconds', default=30)
    parser.add_argument('-c', help='How often to run the iterations on the calibration rule', metavar='baseline_calib_times', default=5)
    parser.add_argument('-m', help='Number of normal runs to measure accuracy of calibration rule', metavar='baseline_test_times', default=5)
    parser.add_argument('-S', help='Slow mode, don\'t skip rule on first quick scan', action='store_true', default=False)
    parser.add_argument('-a', help='Alert bonus in percent: Only alert rules which slow down scans by this much percent (+ measured inaccuracy)', default=3)
    parser.add_argument('-vv', help='Enable verbose mode for extra logging on the screen', action='store_true', default=False)
    args = parser.parse_args()

    # Init Logging
    logfile = args.l
    logFormatter, logFormatterRemote, Log, fileHandler, consoleHandler = init_logging(logfile)

    # Get verbosity level
    VERBOSITY_LEVEL = args.vv
    
    # Init Warning list and file - This list and file will contain offending the rules and warning messages
    warning_rules_file = 'warning_rules.yar'
    warnings_list =[]
    with open(warning_rules_file, 'w') as f:
        f.write("// New panopticon run at " + time.strftime("%Y-%m-%d %H:%M:%S") + '\n\n' )

    # don't to fast mode during calibration, it's set later by param
    slow_mode = True
    alert_bonus = int(args.a)

    # Read calibration ruleset
    CALIBRATION_RULE_HUGE = './baseline_50.yar'
    CALIBRATION_RULES = read_calibration_set(CALIBRATION_RULE_HUGE)

    # Set default samples folder and get the contents
    SAMPLE_SET = ['./samples']
    samples_data = create_sample_data_list(SAMPLE_SET)
    
    # Get the YARA rule input files and directories
    if args.f:
        input_files = get_input_files("file", args.f[0])
    elif args.d:
        input_files = get_input_files("directory", args.d[0])
    else:
        Log.error("No input files or directory provided")
        sys.exit(1)

    # Parse the YARA rules and get the number of YARA rules
    rules_list = parse_yara(input_files)
    rules_num=len(rules_list)

    # Check the imports used by the rules to be tested (if there are any) and prepend them to the "CALIBRATION_RULES" set
    imports_to_prepend = get_imports_to_prepend(rules_list)
    calibration_rule_set = imports_to_prepend + CALIBRATION_RULES

    # Get number Of Calibration Rules for stats purposes
    num_calib_rules = get_num_calibration_rules(calibration_rule_set)
    Log.info(f"Number of calibration rules: {num_calib_rules}")
    
    ######################################################
    ########## Now start the measurements ################
    ######################################################
    
    Log.info("Starting measurement at: " + time.strftime("%Y-%m-%d %H:%M:%S") )

    with Progress(transient=True) as progress:
        # Calibration
        calib_duration, samples_count, diff_perc, warning_message = measure(calibration_rule_set, 1, progress, samples_data, warning_rules_file, show_score=False, rule_name='Baseline')

        if not warning_message:
            warnings_list.append(warning_message)
        
        if not args.i:
            Log.info(f"Number of iterations is not set. Evaluating the optimal amount of cycles...")
            # One measurement should take 5 seconds
            auto_cycles = math.ceil(int(args.s) / calib_duration)
            cycles = auto_cycles
        else:
            # When cycle setting(option -i), occur error "sample_count not setting error"
            # set measure function same, error fix!
            # Evaluate an optimal amount of cycles if nothing has been set manually
            cycles = int(args.i)

        # Startup
        Log.info(f"Auto-evaluation calculated that the defined {args.s} seconds per rule can be accomplished by {cycles} cycles per rule over the given sample set of {samples_count} samples")
        Log.info(f"Running {cycles} cycles over the sample set")
        Log.info("Now the benchmarking begins ... (try not cause any load on the system during benchmarking)")

        ######################################################
        ############# First Calibration ######################
        ######################################################

        # Calibration Score
        baseline_calib_times = int(args.c)  # How often to run the iterations on the calibration rule (Default=5)
        baseline_test_times = int(args.m)   # Number of normal runs to measure accuracy of calibration rule (Default=5)

        Log.info(f"Running 1st baseline measurement {baseline_test_times} times with {cycles} cycles (dropping the worst run) to get an average duration")

        crule_duration_total=0
        crule_duration_max=0

        for x in range(baseline_calib_times):
            crule_duration_tmp, samples_count, diff_perc, warning_message = measure(calibration_rule_set, cycles, progress, samples_data, warning_rules_file, show_score=True, rule_name='Baseline')

            if not warning_message:
                warnings_list.append(warning_message)

            crule_duration_total += crule_duration_tmp
            if crule_duration_tmp >  crule_duration_max:
                crule_duration_max = crule_duration_tmp

        # drop worst result
        if baseline_calib_times > 1:
            crule_duration= ( crule_duration_total - crule_duration_max ) / ( baseline_calib_times -1 )
        else:
            crule_duration= crule_duration_total
        Log.info(f"Calibrate average baseline duration: {crule_duration}")


        ######################################################
        ############ Second Calibration ######################
        ######################################################

        if baseline_test_times:
            Log.info("Running 2nd baseline measurement %s times with %s cycles (dropping the worst run) to measure inaccuracy level" % (baseline_test_times, cycles))
            min_diff_perc = 9999999999999999
            max_diff_perc = 0
            max_diff_perc_2nd = 0
            for x in range(baseline_test_times):
                crule_duration_tmp, samples_count, diff_perc, warning_message = measure(calibration_rule_set, cycles, progress, samples_data, warning_rules_file, c_duration=crule_duration, show_score=True, rule_name='Baseline')

                if not warning_message:
                    warnings_list.append(warning_message)

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
        
        task1 = progress.add_task("[green]Processing rules...", total=rules_num)
        if rules_num > 100:
            warning_bar_num = 100
        else:
            warning_bar_num = rules_num
        task2 = progress.add_task("[red]Warnings", total=warning_bar_num)

        ######################################################
        ############# Scan Input Files #######################
        ######################################################

        for r in rules_list:
            yara_rule_string = plutils.rebuild_yara_rule(r)
            rule_name = r['rule_name']
            if len(yara_rule_string) > 20000:
                warning_message = log_warning_rich("Big rule: " + rule_name + " has " + str(len(yara_rule_string)) + " bytes", yara_rule_string)
                warnings_list.append(warning_message)

            measure_rule = calibration_rule_set + yara_rule_string

            measure(measure_rule, cycles, progress, samples_data, warning_rules_file, show_score=True, c_duration=crule_duration, rule_name=rule_name, alert_diff=alert_diff, single_rule=yara_rule_string)
            progress.update(task1, advance=1)

    print_rich_warning(warnings_list, rules_num, logfile, warning_rules_file)