# Panopticon

A YARA rule performance measurement tool

## What it does 

It runs a YARA rule set against a set of samples and measures the duration of a set of cycles over that sample set. 

The number of iterations over the sample set gets evaluated automatically by providing the number of seconds each rule should be tested against the sample set (default: 15). 

## Usage

```bash
usage: panopticon.py [-h] [-f yara files [yara files ...]]
                     [-d yara files [yara files ...]] [-l logfile]
                     [-i iterations] [-s seconds] [-c baseline_calib_times]
                     [-m baseline_test_times] [-S] [-a A]

YARA RULE PERFORMANCE TESTER

optional arguments:
  -h, --help            show this help message and exit
  -f yara files [yara files ...]
                        Path to input files (YARA rules, separated by space)
  -d yara files [yara files ...]
                        Path to input directory (YARA rules folders, separated
                        by space)
  -l logfile            Log file (default: panopticon.log)
  -i iterations         Number of iterations (default: auto)
  -s seconds            Number of seconds to spend for each rule's measurement
  -c baseline_calib_times
                        How often to run the iterations on the calibration
                        rule
  -m baseline_test_times
                        Number of normal runs to measure accuracy of
                        calibration rule
  -S                    Slow mode, don't skip rule on first quick scan
  -a A                  Alert bonus in percent: Only alert rules which slow
                        down scans by this much percent (+ measured
                        inaccuracy)

```

## Prerequisites

You need to find/build a good sample set that reflects best the use case in which you plan to use your YARA rules. Copy about 10-100 MB of the usual files into the samples directory, e.g. some exe, doc, txt, php, ...

## Considerations 

The measurements are influenced by the system load. If you run this on your Desktop system with many different running and active processes, the results can be distorted. 

The more seconds you give the measurements (parameter -s ), the better are the results. In fast mode (default) panopticon will stop measuring a rule, as soon as one scan was fast enough. So a high value here doesn't mean, that the whole test will take long, but it will give better results.

Give the panopticon process maximum priority in the OS, e.g. "chrt -r 99 ./panopticon.py" (if your kernel has realtime extension) or "nice -n -20 ./panopticon.py" on Linux.

### On Linux: Reserving a physical CPU core
Follow instructions on https://unix.stackexchange.com/questions/326579/how-to-ensure-exclusive-cpu-availability-for-a-running-process to exclude all virtual cores of a physical core from the normal scheduler. See "core id" in the output of "cat /proc/cpuinfo", e.g. on a core i7 processors 3 and 7 share core id 3. After report start with:
'''
chrt -r 99 taskset -c 7 ./panopticon.py
'''

This command should show several kernel processes (square bracket) but only one in userland (no square brackets):
'''
ps -eo psr,command | tr -s " " | grep "^ [3|7]"
'''

## Getting Started 

1. Clone this repo and cd to it `git clone https://github.com/Neo23x0/panopticon.git && cd panopticon`
2. Install the requirements `pip3 install -r requirements.txt`
3. Place your samples into the `./samples` sub folder (see section "Prerequisites" for help on that matter) 
4. Start a measurement with `python3 panopticon.py -f your-yara-rules.yar`

## Expected Output


```bash
    ___                      __  _              
   / _ \___ ____  ___  ___  / /_(_)______  ___  
  / ___/ _ `/ _ \/ _ \/ _ \/ __/ / __/ _ \/ _ \ 
 /_/   \_,_/_//_/\___/ .__/\__/_/\__/\___/_//_/ 
 by Florian Roth    /_/ v0.3.0                 
 and Arnim Rupp
 
 YARA Rule Performance Testing
[INFO   ] Starting measurement at: 2021-02-14 12:09:35
[INFO   ] Number of calibration rules: 100
[INFO   ] Processing test-rules.yar ...
[INFO   ] Parsed 6 rules from test-rules.yar
[INFO   ] Rule:  - best of 1 - duration: 0.0969 s
[INFO   ] Auto-evaluation calculated that the defined 3 seconds per rule could be accomplished by 31 cycles per rule over the given sample set of 45 samples
[INFO   ] Running 31 cycles over the sample set
[INFO   ] Now the benchmarking begins ...
[INFO   ] Running baseline measure 3 times with 31 cycles each to get a good average, droping the worst result
[INFO   ] Rule: Baseline - best of 31 - duration: 0.0940 s
[INFO   ] Rule: Baseline - best of 31 - duration: 0.0935 s
[INFO   ] Rule: Baseline - best of 31 - duration: 0.0935 s
[INFO   ] Calibrate average baseline duration: 0.09349751472473145
[INFO   ] Running baseline measure 3 times with 31 cycles (dropping the worst) to measure inaccuracy
[INFO   ] Rule: Baseline - best of 31 - duration: 0.0939 s
[INFO   ] Rule: Baseline - best of 31 - duration: 0.0936 s
[INFO   ] Rule: Baseline - best of 31 - duration: 0.0936 s
[INFO   ] Min diff 0.089249968762517 % -- max diff 0 %
[INFO   ] Setting warning diff to: 2.6441297745545915
[INFO   ] Calibrations done, now checking the rules
[INFO   ] Rule is fast enough, not measuring any further Embedded_EXE_Cloaking due to fast mode, diff 2.0181 % below alerting level: 2.6441 %
[WARNING] Rule Methodology_Suspicious_Shortcut_LOLcommand slows down a search with 100 rules by 16.0362 % (Measured by best of 31 runs)
[WARNING] Rule password_dump_TESTING slows down a search with 100 rules by 3.0184 % (Measured by best of 31 runs)
[WARNING] Rule APT_Trojan_Win_REDFLARE_5 slows down a search with 100 rules by 9.8361 % (Measured by best of 31 runs)
[INFO   ] Rule is fast enough, not measuring any further APT_CN_Taskmasters_TimeStompingTool_Nov19_1 due to fast mode, diff 0.7347 % below alerting level: 2.6441 %
[INFO   ] Rule is fast enough, not measuring any further Hunting_Rule_ShikataGaNai due to fast mode, diff 2.4929 % below alerting level: 2.6441 %
Processing rules... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
Warnings            ━━━━━━━━━━━━━━━━━━━━╺━━━━━━━━━━━━━━━━━━━  50% 0:00:10
```

## yara_mem_usage.py

yara_mem_usage.py is a small script which measures the difference in used memory before and after loading and compiling a .yar file using 2 different methods.

Example:
```bash
$ ./yara_mem_usage.py all.yar
all.yar: psutil: 17,464 KB -- resource:  17,476 KB
```

## Contact 

Follow me on [twitter](https://twitter.com/cyb3rops).
