#!/bin/env python3

# Based on linux_smap_analyzer.py by https://gist.github.com/LanderlYoung
# https://gist.github.com/LanderlYoung/aedd0e1fe09214545a7f20c40c01776c

from argparse import ArgumentParser
import re
import sys

head_regex = re.compile(r"^[\da-f]{8,}-[\da-f]{8,}")
# This ignores VmFlags: and Name: lines but we don't want those
item_regex = re.compile(r"^(\w+):\s*(\d+) kB")

parser = ArgumentParser(
    description='A utility to analyze smaps on Linux. It requires either an '
    'smaps file or a pid to analyze. Per default only objects which have a '
    'value will be shown. You can list zero objects by specifying the '
    '--full argument.'
)

arggroup = parser.add_mutually_exclusive_group()
arggroup.add_argument(
    "-f", "--file",
    help="input smaps file to parse",
    required=False,
    type=str,
)
arggroup.add_argument(
    "-p", "--pid",
    help="pid to analyze (requires root). This is equivalent to --file="
    "/proc/<pid>/smaps",
    required=False,
    type=str,
)
parser.add_argument(
    "-t", "--type",
    help="column to sort output based on, valid arguments are: pss, rss, size, anon",
    required=False,
    type=str,
    default="pss",
)
parser.add_argument(
    "-F", "--full-map",
    help="list full smap list, even for objects that have a zero count",
    required=False,
    default=False,
    action="store_true"
)
parser.add_argument(
    "-S", "--stack",
    help="list all stack maps",
    required=False,
    default=False,
    action="store_true"
)
parser.add_argument(
    "-T", "--thread-stack",
    help="list all thread stack maps",
    required=False,
    default=False,
    action="store_true"
)
parser.add_argument(
    "-s", "--shared-object",
    help="list all shared object maps (.so maps)",
    required=False,
    default=False,
    action="store_true"
)
parser.add_argument(
    "-d", "--dex",
    help="list all DEX maps",
    required=False,
    default=False,
    action="store_true"
)
parser.add_argument(
    "-P", "--process-name",
    help="process name to specify in the output",
    required=False,
    default="",
    type=str
)

def is_head_line(line):
    return head_regex.search(line) != None


def get_object_name(line):
    m = re.search(' {3,}', line)
    if m != None:
        return line[m.end():].rstrip()
    return "unknown"

stack_regex = re.compile('\[.*stack.*\]')
so_regex = re.compile('\.so$')
dex_regex = re.compile('\.(dex)|(odex)|(art)$')
thread_stack_regex = re.compile('(\[anon:stack_and_tls:\d+)|(anon:thread signal stack)|(anon:dalvik-thread local mark stack)')

def parse_smap(lines):
    smaps = {}
    i = 0
    while i < len(lines):
        name = get_object_name(lines[i])

        if not name in smaps:
            values = {}
            smaps[name] = values
        else:
            values = smaps[name]

        i += 1

        while i < len(lines) and not is_head_line(lines[i]):
            seg_line = lines[i]
            i += 1
            if seg_line.startswith('Name:') or seg_line.startswith('VmFlags:'):
                continue;
            m = item_regex.search(seg_line)
            if m != None:
                type = m.group(1).lower()
                size = int(m.group(2))
                if not type in values:
                    values[type] = size
                else:
                    values[type] = values[type] + size
    return smaps

def sort_smaps(smaps, args):
    return sorted(smaps.items(), key = lambda x: x[1][args.type.lower()], reverse=True)

NAME = "name"
PSS = "pss"
RSS = "rss"
SIZE = "size"
ANON = "anonymous"
OTHER = "other"

def print_cond(smaps, args, if_cond=lambda name, map: True):
    fmt = "{:<11}{:<11}{:<11}{:<11}{:<11}"
    print(fmt.format("PSS", "RSS", "Size", "Anon", "Name"))

    for (name, map) in smaps:
        if if_cond(name, map) and (map[args.type.lower()] > 0 or args.full_map):
            print(fmt.format(str(map[PSS]) + " kB", str(map[RSS]) + " kB", str(map[SIZE]) + " kB", str(map[ANON]) + " kB", name))


def count_cond(smaps, type, if_cond=lambda name, map: True):
    count = 0
    for (name, map) in smaps:
        if if_cond(name, map):
            count += map[type]
    return count

def count_thread_stack(smaps):
    count = 0
    for (name, map) in smaps:
        if thread_stack_regex.search(name):
            count += map[ANON]
    return count

def print_data(smaps, args):
    # order by pss
    smaps = sort_smaps(smaps, args)

    is_stack = lambda name, map: stack_regex.search(name) != None
    all_so_maps_if = lambda name, map: so_regex.search(name) != None
    all_dex_maps_if = lambda name, map: dex_regex.search(name) != None

    print("Per object data: " + args.process_name)
    print("===============================================================================")
    print_cond(smaps, args)

    if args.stack:
        print("\nStack maps:")
        print("===============================================================================")
        print_cond(smaps, args, is_stack)

    if args.shared_object:
        print("\nAll SO maps:")
        print("===============================================================================")
        print_cond(smaps, args, all_so_maps_if)

    if args.dex:
        print("\nAll DEX maps:")
        print("===============================================================================")
        print_cond(smaps, args, all_dex_maps_if)

    print("")
    print("Summary: " + args.process_name)
    print("===============================================================================")

    fmt = "{:<20} = {:>8} kB"
    print(fmt.format("PSS", count_cond(smaps, 'pss')))
    print(fmt.format("RSS", count_cond(smaps, 'rss')))
    print(fmt.format("Size (VSS)", count_cond(smaps, 'size')))

    print(fmt.format("Shared_Clean", count_cond(smaps, 'shared_clean')))
    print(fmt.format("Shared_Dirty", count_cond(smaps, 'shared_dirty')))

    print(fmt.format("Private_Clean", count_cond(smaps, 'private_clean')))
    print(fmt.format("Private_Dirty", count_cond(smaps, 'private_dirty')))

    print(fmt.format("Anonymous", count_cond(smaps, 'anonymous')))

    print(fmt.format("Swap", count_cond(smaps, 'swap')))
    print(fmt.format("Swap PSS", count_cond(smaps, 'swappss')))

    print(fmt.format("Stacks PSS", count_cond(smaps, 'pss', is_stack)))
    print(fmt.format("Stacks VSS", count_cond(smaps, 'size', is_stack)))

    print(fmt.format("Thread Stacks (anon)", count_thread_stack(smaps)))

    if args.shared_object:
        print(fmt.format("All SO map PSS", count_cond(smaps, 'pss', all_so_maps_if)))
        print(fmt.format("All SO map VSS", count_cond(smaps, 'size', all_so_maps_if)))

    if args.dex:
        print(fmt.format("All DEX map PSS", count_cond(smaps, 'pss', all_dex_maps_if)))
        print(fmt.format("All DEX map VSS", count_cond(smaps, 'size', all_dex_maps_if)))

if __name__ == '__main__':
    args = parser.parse_args()
    if args.type == 'anon':
        args.type = 'anonymous'

    fd = -1
    if args.file:
        file = args.file
        if args.file == '-':
            fd = sys.stdin
    elif args.pid:
        file = "/proc/"+args.pid+"/smaps"
    else:
        parser.print_help()
        exit(0)

    if fd == -1:
        try:
            fd = open(file)
        except OSError as err:
            print("{0}".format(err))
            exit(0)

    lines = [l.strip('\n') for l in fd.readlines()]

    smaps = parse_smap(lines)

    print_data(smaps, args)
