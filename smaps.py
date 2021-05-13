#!/bin/env python3

# wrapper script for smap_analyzer.py allowing one to analyze smaps for
# one or multiple processes based on a regex.

import io
import subprocess
import os
from argparse import ArgumentParser

parser = ArgumentParser()
parser.add_argument(
    "-p", "--process-string",
    help="pattern to match processes to analyze",
    required=False,
    type=str,
    default="com.android",
)
parser.add_argument(
    "-s", "--serial",
    help="ADB device serial number",
    required=False,
    type=str,
    default="",
)
parser.add_argument(
    "-o", "--output",
    help="output directory",
    required=False,
    type=str,
    default="/tmp",
)
parser.add_argument(
    "-S", "--smap-analyzer",
    help="Location of smap_analyzer.py",
    required=False,
    type=str,
    default="smap_analyzer.py",
)
parser.add_argument(
    "-t", "--type",
    help="Analyze by pss, rss, or size (vss)",
    required=False,
    type=str,
    default="pss",
)


if __name__ == '__main__':
    args = parser.parse_args()
    serial = ""
    if args.serial:
        serial = " -s" + args.serial

    fd = subprocess.Popen(["adb"+serial+" shell ps -fe"], shell=True, stdout=subprocess.PIPE)
    ptable = {}
    for l in io.TextIOWrapper(fd.stdout, encoding="utf-8"):
        if args.process_string in l:
            line = l.split()
            ptable[line[1]] = line[7]
            
    for p in ptable:
        smap_filename = args.output + "/" + ptable[p] + "-" + str(p) + ".smap"
        adb = "adb" + serial
        cmd = adb + " pull /proc/" + str(p) + "/smaps " + smap_filename
        fd2 = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        fd2.communicate()[0]

        analyze_filename = smap_filename + ".analyzed"
        analyzefd = open(analyze_filename, "w")
        smap_analyzer_cmd = args.smap_analyzer + " -f " + smap_filename + " -t " + args.type
        print("Analyzing smaps " + analyze_filename)
        fd3 = subprocess.Popen(smap_analyzer_cmd, shell=True, stdin=subprocess.PIPE, stdout=analyzefd)
        fd3.communicate()[0]
        analyzefd.close()
        
