#!/usr/bin/python3

import os
import sys
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as blt
import numpy as np


getpid_CPMON = -1
getpid_IPMON = -1
toggle_MVX_CPMON = -1
toggle_MVX_IPMON = -1
fork_native = -1
fork_CPMON_estimate = -1
fork_IPMON_estimate = -1
clone_native = -1
clone_CPMON_estimate = -1
clone_IPMON_estimate = -1
nginx_C1_latency_native = -1
nginx_C1_latency_ReMon = -1
nginx_C1_latency_FORTDIVIDE = -1
nginx_C1_latency_ReMon_IPMON = -1
nginx_C1_latency_FORTDIVIDE_IPMON = -1
nginx_C2_latency_native = -1
nginx_C2_latency_ReMon = -1
nginx_C2_latency_FORTDIVIDE = -1
nginx_C2_latency_ReMon_IPMON = -1
nginx_C2_latency_FORTDIVIDE_IPMON = -1
lighttpd_C1_latency_native = -1
lighttpd_C1_latency_ReMon = -1
lighttpd_C1_latency_FORTDIVIDE = -1
lighttpd_C1_latency_ReMon_IPMON = -1
lighttpd_C1_latency_FORTDIVIDE_IPMON = -1
lighttpd_C2_latency_native = -1
lighttpd_C2_latency_ReMon = -1
lighttpd_C2_latency_FORTDIVIDE = -1
lighttpd_C2_latency_ReMon_IPMON = -1
lighttpd_C2_latency_FORTDIVIDE_IPMON = -1
nginx_C1_overhead_native = -1
nginx_C1_overhead_ReMon = -1
nginx_C1_overhead_FORTDIVIDE = -1
nginx_C1_overhead_ReMon_IPMON = -1
nginx_C1_overhead_FORTDIVIDE_IPMON = -1
nginx_C2_overhead_native = -1
nginx_C2_overhead_ReMon = -1
nginx_C2_overhead_FORTDIVIDE = -1
nginx_C2_overhead_ReMon_IPMON = -1
nginx_C2_overhead_FORTDIVIDE_IPMON = -1
lighttpd_C1_overhead_native = -1
lighttpd_C1_overhead_ReMon = -1
lighttpd_C1_overhead_FORTDIVIDE = -1
lighttpd_C1_overhead_ReMon_IPMON = -1
lighttpd_C1_overhead_FORTDIVIDE_IPMON = -1
lighttpd_C2_overhead_native = -1
lighttpd_C2_overhead_ReMon = -1
lighttpd_C2_overhead_FORTDIVIDE = -1
lighttpd_C2_overhead_ReMon_IPMON = -1
lighttpd_C2_overhead_FORTDIVIDE_IPMON = -1
nginx_C2_manual_migration_handlers = -1
nginx_C2_known_globals = -1
nginx_C2_pointer_scanning = -1
nginx_C2_libc_allocator = -1
nginx_C2_FORTDIVIDE_allocator = -1
lighttpd_C2_libc_allocator = -1
lighttpd_C2_FORTDIVIDE_allocator = -1

mapping_lower_path = ""
mapping_lower_table = ""
mapping_upper_path = ""
mapping_upper_table = ""
migration_path = ""
migration_table = ""
latency_path = ""
overhead_path = ""


if len(sys.argv) != 2:
    exit(1)

base_dir = sys.argv[1]


results = {}


def ask_to_stop():
    response = input("continur? (Y/n) > ")
    print(" > %s" % response)
    if response != "y" and response != '\n' and response != '':
        exit(1)


class mapping_count_data_data:
    def __init__(self):
        self.svx_measure = []
        self.svx_getpid = []
        self.mvx_measure = []
        self.mvx_getpid = []
        self.toggle_mappings = {}
        self.migrations = {}
        self.pointers = {}
        self.toggle_hardened = []
        self.toggle_libc = []
        self.toggle_pmvee = []


class mapping_count_data:
    def __init__(self):
        self.native = None
        self.pmvee = None
        self.pmvee_ipmon = None
        self.forkkill_child = None
        self.forkkill_self = None
        self.clonekill_self = None


class switcheroo_data:
    def __init__(self):
        self.measure = []
        self.getpid = []
        self.enter_exit = []


class switcheroo_data_data:
    def __init__(self):
        self.native = []
        self.native_sync = []
        self.svx_pmvee_micro = []
        self.svx_pmvee_ipmon_micro = []
        self.svx_pmvee = []
        self.svx_pmvee_ipmon = []
        self.pmvee_micro = []
        self.pmvee_ipmon_micro = []
        self.pmvee = []
        self.pmvee_ipmon = []


class server_results:
    def __init__(self):
        self.avg_latency = -1
        self.stdev_latency = -1
        self.max_latency = -1
        self.plusminus_stdev_latency = -1
        self.avg_reqsec = -1
        self.stdev_reqsec = -1
        self.max_reqsec = -1
        self.plusminus_stdev_reqsec = -1
        self.reqsec = -1
        self.transfersec = -1


def to_us(string):
    string = string.replace('s', '')
    if string[-1] == 'u':
        return float(string[:-1])
    if string[-1] == 'm':
        return float(string[:-1]) * 1000
    return float(string[:-1]) * 1000 * 1000


def to_total(string):
    if string[-1] == 'k':
        return float(string[:-1]) * 1000
    return float(string[:-1])


def to_bytes(string):
    if string[-2:] == 'MB':
        return float(string[:-2]) * 1000 * 1000
    if string[-2:] == 'KB':
        return float(string[:-2]) * 1000
    if string[-1:] == 'B':
        return float(string[:-1])
    else:
        print("do me - %s" % string)
        exit(1)
    return float(string[:-1])


def load_file_results(file_path):
    result = []
    with open(file_path, 'r') as file_reading:
        while True:
            line = file_reading.readline()
            if not line:
                break
            if "Running" in line:
                result.append(server_results())
            elif "Latency" in line:
                line = [ element for element in line.replace('\n', '').split(' ') if element ][1:]
                result[-1].avg_latency = to_us(line[0])
                result[-1].stdev_latency = to_us(line[1])
                result[-1].max_latency = to_us(line[2])
                result[-1].plusminus_stdev_latency = float(line[3][:-1])
            elif "Req/Sec" in line:
                line = [ element for element in line.replace('\n', '').split(' ') if element ][1:]
                result[-1].avg_reqsec = to_total(line[0])
                result[-1].stdev_reqsec = to_total(line[1])
                result[-1].max_reqsec = to_total(line[2])
                result[-1].plusminus_stdev_reqsec = float(line[3][:-1])
            elif "Requests/sec" in line:
                line = [ element for element in line.replace('\n', '').split(' ') if element ][1:]
                result[-1].reqsec = float(line[-1])
            elif "Transfer/sec" in line:
                line = [ element for element in line.replace('\n', '').split(' ') if element ][1:]
                result[-1].transfersec = to_bytes(line[-1])
    return result


def load_mapping_count_files(file_path):
    result = mapping_count_data()
    for result_file in [ entry.path for entry in os.scandir(file_path) ]:
        with open(result_file, 'r') as file_reading:
            result_data = mapping_count_data_data()
            while True:
                line = file_reading.readline()
                if not line:
                    break
                if "[single-variant measuring] > time elapsed: " in line:
                    iterations = int(line.split(" us for ")[1].replace(" iterations", ''))
                    result_data.svx_measure.append(int(line.split("[single-variant measuring] > time elapsed: ")[1].split("us")[0]))
                elif "[single-variant get pid] > time elapsed: " in line:
                    iterations = int(line.split(" us for ")[1].replace(" iterations", ''))
                    result_data.svx_getpid.append(int(line.split("[single-variant get pid] > time elapsed: ")[1].split("us")[0])/iterations)
                elif "[multi-variant measuring] > time elapsed: " in line:
                    iterations = int(line.split(" us for ")[1].replace(" iterations", ''))
                    result_data.mvx_measure.append(int(line.split("[multi-variant measuring] > time elapsed: ")[1].split("us")[0])/iterations)
                elif "[multi-variant get pid] > time elapsed: " in line:
                    iterations = int(line.split(" us for ")[1].replace(" iterations", ''))
                    result_data.mvx_getpid.append(int(line.split("[multi-variant get pid] > time elapsed: ")[1].split("us")[0])/iterations)
                elif "[nginx mappings hardened heap] > time elapsed: " in line:
                    iterations = int(line.split(" us for ")[1].replace(" iterations", ''))
                    result_data.toggle_hardened.append(int(line.split("[nginx mappings hardened heap] > time elapsed: ")[1].split("us")[0])/iterations)
                elif "[libc mappings libc heap] > time elapsed: " in line:
                    iterations = int(line.split(" us for ")[1].replace(" iterations", ''))
                    result_data.toggle_libc.append(int(line.split("[libc mappings libc heap] > time elapsed: ")[1].split("us")[0])/iterations)
                elif "[nginx mappings pmvee heap] > time elapsed: " in line:
                    iterations = int(line.split(" us for ")[1].replace(" iterations", ''))
                    result_data.toggle_pmvee.append(int(line.split("[nginx mappings pmvee heap] > time elapsed: ")[1].split("us")[0])/iterations)
                elif " mapping count " in line:
                    iterations = int(line.split(" us for ")[1].replace(" iterations", ''))
                    line = line.replace(">[", '').split("] > time elapsed: ")
                    time = int(line[1].split("us")[0])
                    line = line[0].split(" mapping count ")
                    size = int(line[0], 16)
                    count = int(line[1])
                    if size not in result_data.toggle_mappings:
                        result_data.toggle_mappings[size] = {}
                    if count not in result_data.toggle_mappings[size]:
                        result_data.toggle_mappings[size][count] = []
                    result_data.toggle_mappings[size][count].append(time/iterations)
                elif ">[migration " in line:
                    iterations = int(line.split(" us for ")[1].replace(" iterations", ''))
                    line = line.replace(">[migration ", '').split("] > time elapsed: ")
                    time = int(line[1].split("us")[0])
                    count = int(line[0])
                    if count not in result_data.migrations:
                        result_data.migrations[count] = []
                    result_data.migrations[count].append(time/iterations)
                elif ">[pointer migration " in line:
                    iterations = int(line.split(" us for ")[1].replace(" iterations", ''))
                    line = line.replace(">[pointer migration ", '').split("] > time elapsed: ")
                    time = int(line[1].split("us")[0])
                    count = int(line[0])
                    if count not in result_data.pointers:
                        result_data.pointers[count] = []
                    result_data.pointers[count].append(time/iterations)
            run = result_file.split('/')[-1]
            if run == "native":
                result.native = result_data
            elif run == "pmvee":
                result.pmvee = result_data
            elif run == "pmvee-ipmon":
                result.pmvee_ipmon = result_data
    return result


def load_switcheroo_files(file_path):
    result = mapping_count_data()
    result.measure = switcheroo_data_data()
    result.getpid = switcheroo_data_data()
    result.enter_exit = switcheroo_data_data()
    result.forkkill_child = []
    result.forkkill_self = []
    result.clonekill_self = []

    for result_file in [ entry.path for entry in os.scandir(file_path) ]:
        with open(result_file, 'r') as file_reading:
            run = result_file.split('/')[-1]

            while True:
                line = file_reading.readline()
                if not line:
                    break
                if ">[" not in line:
                    continue

                iterations = int(line.split(" us for ")[1].replace(" iterations", ''))

                if "[native measuring] > time elapsed: " in line:
                    time = int(line.split("[native measuring] > time elapsed: ")[1].split("us")[0])
                    result.measure.native.append(time)
                elif "[native getpid] > time elapsed: " in line:
                    time = int(line.split("[native getpid] > time elapsed: ")[1].split("us")[0])/iterations
                    result.getpid.native.append(time)
                elif "getpid sanity check] > time elapsed: " in line:
                    time = int(line.split("getpid sanity check] > time elapsed: ")[1].split("us")[0])/iterations
                elif "[getpid sync] > time elapsed: " in line:
                    time = int(line.split("[getpid sync] > time elapsed: ")[1].split("us")[0])/iterations
                    result.getpid.native_sync.append(time)
                elif "[native enter exit] > time elapsed: " in line:
                    time = int(line.split("[native enter exit] > time elapsed: ")[1].split("us")[0])/iterations
                    result.enter_exit.native.append(time)
                elif "[native enter exit sync] > time elapsed: " in line:
                    time = int(line.split("[native enter exit sync] > time elapsed: ")[1].split("us")[0])/iterations
                    result.enter_exit.native_sync.append(time)
                elif "[fork and kill child] > time elapsed: " in line:
                    time = int(line.split("[fork and kill child] > time elapsed: ")[1].split("us")[0])/iterations
                    result.forkkill_child.append(time)
                elif "[fork and kill self] > time elapsed: " in line:
                    time = int(line.split("[fork and kill self] > time elapsed: ")[1].split("us")[0])/iterations
                    result.forkkill_self.append(time)
                elif "[clone and kill self] > time elapsed: " in line:
                    time = int(line.split("[clone and kill self] > time elapsed: ")[1].split("us")[0])/iterations
                    result.clonekill_self.append(time)
                elif "[SVX measuring] > time elapsed: " in line:
                    time = int(line.split("[SVX measuring] > time elapsed: ")[1].split("us")[0])/iterations
                    if "micro" not in run:
                        if "ipmon" in run:
                            result.measure.svx_pmvee_ipmon.append(time)
                        else:
                            result.measure.svx_pmvee.append(time)
                    else:
                        if "ipmon" in run:
                            result.measure.svx_pmvee_ipmon_micro.append(time)
                        else:
                            result.measure.svx_pmvee_micro.append(time)
                elif "[SVX getpid] > time elapsed: " in line:
                    time = int(line.split("[SVX getpid] > time elapsed: ")[1].split("us")[0])/iterations
                    if "micro" not in run:
                        if "ipmon" in run:
                            result.getpid.svx_pmvee_ipmon.append(time)
                        else:
                            result.getpid.svx_pmvee.append(time)
                    else:
                        if "ipmon" in run:
                            result.getpid.svx_pmvee_ipmon_micro.append(time)
                        else:
                            result.getpid.svx_pmvee_micro.append(time)
                elif "[MVX measuring] > time elapsed: " in line:
                    time = int(line.split("[MVX measuring] > time elapsed: ")[1].split("us")[0])/iterations
                    if "micro" not in run:
                        if "ipmon" in run:
                            result.measure.pmvee_ipmon.append(time)
                        else:
                            result.measure.pmvee.append(time)
                    else:
                        if "ipmon" in run:
                            result.measure.pmvee_ipmon_micro.append(time)
                        else:
                            result.measure.pmvee_micro.append(time)
                elif "[MVX getpid] > time elapsed: " in line:
                    time = int(line.split("[MVX getpid] > time elapsed: ")[1].split("us")[0])/iterations
                    if "micro" not in run:
                        if "ipmon" in run:
                            result.getpid.pmvee_ipmon.append(time)
                        else:
                            result.getpid.pmvee.append(time)
                    else:
                        if "ipmon" in run:
                            result.getpid.pmvee_ipmon_micro.append(time)
                        else:
                            result.getpid.pmvee_micro.append(time)
                elif "[MVX enter exit] > time elapsed: " in line:
                    time = int(line.split("[MVX enter exit] > time elapsed: ")[1].split("us")[0])/iterations
                    if "micro" not in run:
                        if "ipmon" in run:
                            result.enter_exit.pmvee_ipmon.append(time)
                        else:
                            result.enter_exit.pmvee.append(time)
                    else:
                        if "ipmon" in run:
                            result.enter_exit.pmvee_ipmon_micro.append(time)
                        else:
                            result.enter_exit.pmvee_micro.append(time)

    return result


for sub_dir_path in [ entry.path for entry in os.scandir(base_dir) if entry.is_dir()]:
    sub_dir = sub_dir_path.split('/')[-1]
    results[sub_dir] = {}
    for sub_sub_dir_path in [ entry.path for entry in os.scandir(sub_dir_path) if entry.is_dir()]:
        sub_sub_dir = sub_sub_dir_path.split('/')[-1]
        results[sub_dir][sub_sub_dir] = {}
        for file_path in [ entry.path for entry in os.scandir("%s/%s/%s/" % (base_dir, sub_dir, sub_sub_dir)) ]:
            file = file_path.split('/')[-1]
            if file == "mapping_count":
                results[sub_dir][sub_sub_dir][file] = load_mapping_count_files(file_path)
            elif file == "switcheroo":
                results[sub_dir][sub_sub_dir][file] = load_switcheroo_files(file_path)
            elif file == "server_micro":
                pass
            elif "connections" in file:
                connections = int(file.split('-')[0])
                results[sub_dir][sub_sub_dir][connections] = {}
                for server_path in [ entry.path for entry in os.scandir("%s/%s/%s/%s/" % (base_dir, sub_dir, sub_sub_dir, file)) ]:
                    file = server_path.split('/')[-1]
                    results[sub_dir][sub_sub_dir][connections][file] = load_file_results(server_path)



matplotlib.rcParams['axes.spines.right'] = False
matplotlib.rcParams['axes.spines.top'] = False


if "merge-pmd-shorter-skip" in results and "none" in results["merge-pmd-shorter-skip"] and "switcheroo" in results["merge-pmd-shorter-skip"]["none"]:
    switcheroo = results["merge-pmd-shorter-skip"]["none"]["switcheroo"]

    getpid_CPMON = sum(switcheroo.getpid.pmvee)/len(switcheroo.getpid.pmvee)
    getpid_IPMON = sum(switcheroo.getpid.pmvee_ipmon)/len(switcheroo.getpid.pmvee_ipmon)
    toggle_MVX_CPMON = sum(switcheroo.enter_exit.pmvee)/len(switcheroo.enter_exit.pmvee)
    toggle_MVX_IPMON = sum(switcheroo.enter_exit.pmvee_ipmon)/len(switcheroo.enter_exit.pmvee_ipmon)
    fork_native = sum(switcheroo.forkkill_self)/len(switcheroo.forkkill_self)
    fork_CPMON_estimate = fork_native + getpid_CPMON
    fork_IPMON_estimate = fork_native + getpid_IPMON
    clone_native = sum(switcheroo.clonekill_self)/len(switcheroo.clonekill_self)
    clone_CPMON_estimate = clone_native + getpid_CPMON
    clone_IPMON_estimate = clone_native + getpid_IPMON

    # print(sum(switcheroo.getpid.native))
    # print(" > native getpid:           %.4f us" % (sum(switcheroo.getpid.native)/len(switcheroo.getpid.native)))
    # print(" > sync getpid:             %.4f us" % (sum(switcheroo.getpid.native_sync)/len(switcheroo.getpid.native_sync)))
    # print(" > svx pmvee getpid:        %.4f us" % (sum(switcheroo.getpid.svx_pmvee)/len(switcheroo.getpid.svx_pmvee)))
    # print(" > svx pmvee ipmon getpid:  %.4f us" % (sum(switcheroo.getpid.svx_pmvee_ipmon)/len(switcheroo.getpid.svx_pmvee_ipmon)))
    # # print(" > pmvee unsynced getpid:   %.4f us" % (sum(switcheroo.getpid.pmvee_micro)/len(switcheroo.getpid.pmvee_micro)))
    # # print(" > pmvee ipmon getpid:      %.4f us" % (sum(switcheroo.getpid.pmvee_ipmon_micro)/len(switcheroo.getpid.pmvee_ipmon_micro)))
    # print(" > pmvee getpid:            %.4f us" % (sum(switcheroo.getpid.pmvee)/len(switcheroo.getpid.pmvee)))
    # print(" > pmvee ipmon getpid:      %.4f us" % (sum(switcheroo.getpid.pmvee_ipmon)/len(switcheroo.getpid.pmvee_ipmon)))
# 
    # print(" > native enter_exit:                %.4f us" % (sum(switcheroo.enter_exit.native)/len(switcheroo.enter_exit.native)))
    # print(" > sync enter_exit:                  %.4f us" % (sum(switcheroo.enter_exit.native_sync)/len(switcheroo.enter_exit.native_sync)))
    # # print(" > pmvee enter_exit w/o args:        %.4f us" % (sum(switcheroo.enter_exit.pmvee_micro)/len(switcheroo.enter_exit.pmvee_micro)))
    # # print(" > pmvee ipmon enter_exit w/o args:  %.4f us" % (sum(switcheroo.enter_exit.pmvee_ipmon_micro)/len(switcheroo.enter_exit.pmvee_ipmon_micro)))
    # print(" > pmvee enter_exit:                 %.4f us" % (sum(switcheroo.enter_exit.pmvee)/len(switcheroo.enter_exit.pmvee)))
    # print(" > pmvee ipmon enter_exit:           %.4f us" % (sum(switcheroo.enter_exit.pmvee_ipmon)/len(switcheroo.enter_exit.pmvee_ipmon)))
# 
    # print(" > fork and kill:  %.4us" % (sum(switcheroo.forkkill_self)/len(switcheroo.forkkill_self)))
    # print(" > clone and kill: %.4us" % (sum(switcheroo.clonekill_self)/len(switcheroo.clonekill_self)))


class server_data:
    def __init__(self, requests, latency):
        self.requests = requests
        self.latency = latency

class server_results:
    def __init__(self):
        self.baseline = None
        self.ghumvee = None
        self.pmvee = None
        self.remon = None
        self.pmvee_ipmon = None

# server results: pmvee allocator, skip kernel
def pmvee_skip_server_results(nginx_connections=10, nginx_single_connections=10, lighttpd_connections=10, nginx_workers=4, suffix=""):
    print(" > generating graphs for server benchmarks...")
    if "merge-pmd-shorter-skip" not in results:
        print(" > skipping server results due to missing skip data")
        return
    if "pmvee" not in results["merge-pmd-shorter-skip"]:
        print(" > skipping server results due to missing pmvee allocator data")
        return
    if 10 not in results["merge-pmd-shorter-skip"]["pmvee"]:
        print(" > skipping server results due to missing data for 10 connections")
        return

    lighttpd_faster_results = server_results()
    nginx_split_results = { 1: server_results(), 4: server_results() }
    lighttpd_full_results = server_results()
    nginx_full_results = { 1: server_results(), 4: server_results() }

    if "nginx-4-baseline" not in results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]:
        print(" > skipping server results due to missing nginx baseline")
        ask_to_stop()
    expected_len = len(results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]["nginx-4-baseline"])
    nginx_split_results[4].baseline = server_data(
            sum([ element.reqsec for element in results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]["nginx-4-baseline"] ]) / expected_len,
            sum([ element.avg_latency for element in results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]["nginx-4-baseline"] ]) / expected_len)

    if "nginx-4-remon-noipmon" not in results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]:
        print(" > skipping server results due to missing GHUMVEE data")
        ask_to_stop()
    length = len(results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]["nginx-4-remon-noipmon"])
    nginx_split_results[4].ghumvee = server_data(
            sum([ element.reqsec for element in results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]["nginx-4-remon-noipmon"] ]) / length,
            sum([ element.avg_latency for element in results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]["nginx-4-remon-noipmon"] ]) / length)
    if len(results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]["nginx-4-remon-noipmon"]) != expected_len:
        print(" > mismatching result length for nginx_ghumvee")
        ask_to_stop()

    if "nginx-4-pmvee-noipmon" not in results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]:
        print(" > skipping server results due to missing PMVEE data")
        ask_to_stop()
    length = len(results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]["nginx-4-pmvee-noipmon"])
    nginx_split_results[4].pmvee = server_data(
            sum([ element.reqsec for element in results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]["nginx-4-pmvee-noipmon"] ]) / length,
            sum([ element.avg_latency for element in results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]["nginx-4-pmvee-noipmon"] ]) / length)
    if len(results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]["nginx-4-pmvee-noipmon"]) != expected_len:
        print(" > mismatching result length for nginx_pmvee")
        ask_to_stop()

    if "nginx-4-remon-withipmon" not in results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]:
        print(" > skipping server results due to missing ReMon data")
        ask_to_stop()
    length = len(results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]["nginx-4-remon-withipmon"])
    nginx_split_results[4].remon = server_data(
            sum([ element.reqsec for element in results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]["nginx-4-remon-withipmon"] ]) / length,
            sum([ element.avg_latency for element in results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]["nginx-4-remon-withipmon"] ]) / length)
    if len(results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]["nginx-4-remon-withipmon"]) != expected_len:
        print(" > mismatching result length for nginx_remon")
        ask_to_stop()

    if "nginx-4-pmvee-withipmon" not in results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]:
        print(" > skipping server results due to missing PMVEE IP-MON data")
        ask_to_stop()
    length = len(results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]["nginx-4-pmvee-withipmon"])
    nginx_split_results[4].pmvee_ipmon = server_data(
            sum([ element.reqsec for element in results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]["nginx-4-pmvee-withipmon"] ]) / length,
            sum([ element.avg_latency for element in results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]["nginx-4-pmvee-withipmon"] ]) / length)
    if len(results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]["nginx-4-pmvee-withipmon"]) != expected_len:
        print(" > mismatching result length for nginx_pmvee_ipmon")
        ask_to_stop()



    if "nginx-full-4-baseline" not in results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]:
        print(" > skipping server results due to missing nginx baseline")
        ask_to_stop()
    expected_len = len(results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]["nginx-full-4-baseline"])
    nginx_full_results[4].baseline = server_data(
            sum([ element.reqsec for element in results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]["nginx-full-4-baseline"] ]) / expected_len,
            sum([ element.avg_latency for element in results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]["nginx-full-4-baseline"] ]) / expected_len)

    if "nginx-full-4-remon-noipmon" not in results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]:
        print(" > skipping server results due to missing GHUMVEE data")
        ask_to_stop()
    length = len(results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]["nginx-full-4-remon-noipmon"])
    nginx_full_results[4].ghumvee = server_data(
            sum([ element.reqsec for element in results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]["nginx-full-4-remon-noipmon"] ]) / length,
            sum([ element.avg_latency for element in results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]["nginx-full-4-remon-noipmon"] ]) / length)
    if len(results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]["nginx-full-4-remon-noipmon"]) != expected_len:
        print(" > mismatching result length for nginx_ghumvee")
        ask_to_stop()

    if "nginx-full-4-pmvee-noipmon" not in results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]:
        print(" > skipping server results due to missing PMVEE data")
        ask_to_stop()
    length = len(results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]["nginx-full-4-pmvee-noipmon"])
    nginx_full_results[4].pmvee = server_data(
            sum([ element.reqsec for element in results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]["nginx-full-4-pmvee-noipmon"] ]) / length,
            sum([ element.avg_latency for element in results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]["nginx-full-4-pmvee-noipmon"] ]) / length)
    if len(results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]["nginx-full-4-pmvee-noipmon"]) != expected_len:
        print(" > mismatching result length for nginx_pmvee")
        ask_to_stop()

    if "nginx-full-4-remon-withipmon" not in results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]:
        print(" > skipping server results due to missing ReMon data")
        ask_to_stop()
    length = len(results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]["nginx-full-4-remon-withipmon"])
    nginx_full_results[4].remon = server_data(
            sum([ element.reqsec for element in results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]["nginx-full-4-remon-withipmon"] ]) / length,
            sum([ element.avg_latency for element in results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]["nginx-full-4-remon-withipmon"] ]) / length)
    if len(results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]["nginx-full-4-remon-withipmon"]) != expected_len:
        print(" > mismatching result length for nginx_remon")
        ask_to_stop()

    if "nginx-full-4-pmvee-withipmon" not in results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]:
        print(" > skipping server results due to missing PMVEE IP-MON data")
        ask_to_stop()
    length = len(results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]["nginx-full-4-pmvee-withipmon"])
    nginx_full_results[4].pmvee_ipmon = server_data(
            sum([ element.reqsec for element in results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]["nginx-full-4-pmvee-withipmon"] ]) / length,
            sum([ element.avg_latency for element in results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]["nginx-full-4-pmvee-withipmon"] ]) / length)
    if len(results["merge-pmd-shorter-skip"]["pmvee"][nginx_connections]["nginx-full-4-pmvee-withipmon"]) != expected_len:
        print(" > mismatching result length for nginx_pmvee_ipmon")
        ask_to_stop()


    if "nginx-1-baseline" not in results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]:
        print(" > skipping server results due to missing nginx baseline")
        ask_to_stop()
    expected_len = len(results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]["nginx-1-baseline"])
    nginx_split_results[1].baseline = server_data(
            sum([ element.reqsec for element in results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]["nginx-1-baseline"] ]) / expected_len,
            sum([ element.avg_latency for element in results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]["nginx-1-baseline"] ]) / expected_len)

    if "nginx-1-remon-noipmon" not in results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]:
        print(" > skipping server results due to missing GHUMVEE data")
        ask_to_stop()
    length = len(results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]["nginx-1-remon-noipmon"])
    nginx_split_results[1].ghumvee = server_data(
            sum([ element.reqsec for element in results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]["nginx-1-remon-noipmon"] ]) / length,
            sum([ element.avg_latency for element in results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]["nginx-1-remon-noipmon"] ]) / length)
    if len(results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]["nginx-1-remon-noipmon"]) != expected_len:
        print(" > mismatching result length for nginx_ghumvee")
        ask_to_stop()

    if "nginx-1-pmvee-noipmon" not in results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]:
        print(" > skipping server results due to missing PMVEE data")
        ask_to_stop()
    length = len(results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]["nginx-1-pmvee-noipmon"])
    nginx_split_results[1].pmvee = server_data(
            sum([ element.reqsec for element in results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]["nginx-1-pmvee-noipmon"] ]) / length,
            sum([ element.avg_latency for element in results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]["nginx-1-pmvee-noipmon"] ]) / length)
    if len(results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]["nginx-1-pmvee-noipmon"]) != expected_len:
        print(" > mismatching result length for nginx_pmvee")
        ask_to_stop()

    if "nginx-1-remon-withipmon" not in results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]:
        print(" > skipping server results due to missing ReMon data")
        ask_to_stop()
    length = len(results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]["nginx-1-remon-withipmon"])
    nginx_split_results[1].remon = server_data(
            sum([ element.reqsec for element in results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]["nginx-1-remon-withipmon"] ]) / length,
            sum([ element.avg_latency for element in results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]["nginx-1-remon-withipmon"] ]) / length)
    if len(results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]["nginx-1-remon-withipmon"]) != expected_len:
        print(" > mismatching result length for nginx_remon")
        ask_to_stop()

    if "nginx-1-pmvee-withipmon" not in results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]:
        print(" > skipping server results due to missing PMVEE IP-MON data")
        ask_to_stop()
    length = len(results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]["nginx-1-pmvee-withipmon"])
    nginx_split_results[1].pmvee_ipmon = server_data(
            sum([ element.reqsec for element in results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]["nginx-1-pmvee-withipmon"] ]) / length,
            sum([ element.avg_latency for element in results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]["nginx-1-pmvee-withipmon"] ]) / length)
    if len(results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]["nginx-1-pmvee-withipmon"]) != expected_len:
        print(" > mismatching result length for nginx_pmvee_ipmon")
        ask_to_stop()



    if "nginx-full-1-baseline" not in results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]:
        print(" > skipping server results due to missing nginx baseline")
        ask_to_stop()
    expected_len = len(results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]["nginx-full-1-baseline"])
    nginx_full_results[1].baseline = server_data(
            sum([ element.reqsec for element in results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]["nginx-full-1-baseline"] ]) / expected_len,
            sum([ element.avg_latency for element in results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]["nginx-full-1-baseline"] ]) / expected_len)

    if "nginx-full-1-remon-noipmon" not in results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]:
        print(" > skipping server results due to missing GHUMVEE data")
        ask_to_stop()
    length = len(results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]["nginx-full-1-remon-noipmon"])
    nginx_full_results[1].ghumvee = server_data(
            sum([ element.reqsec for element in results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]["nginx-full-1-remon-noipmon"] ]) / length,
            sum([ element.avg_latency for element in results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]["nginx-full-1-remon-noipmon"] ]) / length)
    if len(results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]["nginx-full-1-remon-noipmon"]) != expected_len:
        print(" > mismatching result length for nginx_ghumvee")
        ask_to_stop()

    if "nginx-full-1-pmvee-noipmon" not in results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]:
        print(" > skipping server results due to missing PMVEE data")
        ask_to_stop()
    length = len(results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]["nginx-full-1-pmvee-noipmon"])
    nginx_full_results[1].pmvee = server_data(
            sum([ element.reqsec for element in results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]["nginx-full-1-pmvee-noipmon"] ]) / length,
            sum([ element.avg_latency for element in results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]["nginx-full-1-pmvee-noipmon"] ]) / length)
    if len(results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]["nginx-full-1-pmvee-noipmon"]) != expected_len:
        print(" > mismatching result length for nginx_pmvee")
        ask_to_stop()

    if "nginx-full-1-remon-withipmon" not in results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]:
        print(" > skipping server results due to missing ReMon data")
        ask_to_stop()
    length = len(results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]["nginx-full-1-remon-withipmon"])
    nginx_full_results[1].remon = server_data(
            sum([ element.reqsec for element in results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]["nginx-full-1-remon-withipmon"] ]) / length,
            sum([ element.avg_latency for element in results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]["nginx-full-1-remon-withipmon"] ]) / length)
    if len(results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]["nginx-full-1-remon-withipmon"]) != expected_len:
        print(" > mismatching result length for nginx_remon")
        ask_to_stop()

    if "nginx-full-1-pmvee-withipmon" not in results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]:
        print(" > skipping server results due to missing PMVEE IP-MON data")
        ask_to_stop()
    length = len(results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]["nginx-full-1-pmvee-withipmon"])
    nginx_full_results[1].pmvee_ipmon = server_data(
            sum([ element.reqsec for element in results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]["nginx-full-1-pmvee-withipmon"] ]) / length,
            sum([ element.avg_latency for element in results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]["nginx-full-1-pmvee-withipmon"] ]) / length)
    if len(results["merge-pmd-shorter-skip"]["pmvee"][nginx_single_connections]["nginx-full-1-pmvee-withipmon"]) != expected_len:
        print(" > mismatching result length for nginx_pmvee_ipmon")


    if "lighttpd-faster-baseline" not in results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]:
        print(" > skipping server results due to missing lighttpd baseline")
        ask_to_stop()
    length = len(results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]["lighttpd-faster-baseline"])
    lighttpd_faster_results.baseline = server_data(
            sum([ element.reqsec for element in results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]["lighttpd-faster-baseline"] ]) / expected_len,
            sum([ element.avg_latency for element in results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]["lighttpd-faster-baseline"] ]) / expected_len)
    if len(results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]["lighttpd-faster-baseline"]) != expected_len:
        print(" > mismatching result length for lighttpd_base")
        ask_to_stop()

    if "lighttpd-faster-remon-noipmon" not in results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]:
        print(" > skipping server results due to missing GHUMVEE data")
        ask_to_stop()
    length = len(results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]["lighttpd-faster-remon-noipmon"])
    lighttpd_faster_results.ghumvee = server_data(
            sum([ element.reqsec for element in results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]["lighttpd-faster-remon-noipmon"] ]) / length,
            sum([ element.avg_latency for element in results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]["lighttpd-faster-remon-noipmon"] ]) / length)
    if len(results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]["lighttpd-faster-remon-noipmon"]) != expected_len:
        print(" > mismatching result length for lighttpd_ghumvee")
        ask_to_stop()

    if "lighttpd-faster-pmvee-noipmon" not in results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]:
        print(" > skipping server results due to missing PMVEE data")
        ask_to_stop()
    length = len(results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]["lighttpd-faster-pmvee-noipmon"])
    lighttpd_faster_results.pmvee = server_data(
            sum([ element.reqsec for element in results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]["lighttpd-faster-pmvee-noipmon"] ]) / length,
            sum([ element.avg_latency for element in results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]["lighttpd-faster-pmvee-noipmon"] ]) / length)
    if len(results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]["lighttpd-faster-pmvee-noipmon"]) != expected_len:
        print(" > mismatching result length for lighttpd_pmvee")
        ask_to_stop()

    if "lighttpd-faster-remon-withipmon" not in results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]:
        print(" > skipping server results due to missing ReMon data")
        ask_to_stop()
    length = len(results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]["lighttpd-faster-remon-withipmon"])
    lighttpd_faster_results.remon = server_data(
            sum([ element.reqsec for element in results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]["lighttpd-faster-remon-withipmon"] ]) / length,
            sum([ element.avg_latency for element in results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]["lighttpd-faster-remon-withipmon"] ]) / length)
    if len(results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]["lighttpd-faster-remon-withipmon"]) != expected_len:
        print(" > mismatching result length for lighttpd_remon")
        ask_to_stop()

    if "lighttpd-faster-pmvee-withipmon" not in results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]:
        print(" > skipping server results due to missing PMVEE IP-MON data")
        ask_to_stop()
    length = len(results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]["lighttpd-faster-pmvee-withipmon"])
    lighttpd_faster_results.pmvee_ipmon = server_data(
            sum([ element.reqsec for element in results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]["lighttpd-faster-pmvee-withipmon"] ]) / length,
            sum([ element.avg_latency for element in results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]["lighttpd-faster-pmvee-withipmon"] ]) / length)
    if len(results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]["lighttpd-faster-pmvee-withipmon"]) != expected_len:
        print(" > mismatching result length for lighttpd_pmvee_ipmon")
        ask_to_stop()


    if "lighttpd-default-baseline" not in results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]:
        print(" > skipping server results due to missing lighttpd baseline")
        ask_to_stop()
    length = len(results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]["lighttpd-default-baseline"])
    lighttpd_full_results.baseline = server_data(
            sum([ element.reqsec for element in results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]["lighttpd-default-baseline"] ]) / expected_len,
            sum([ element.avg_latency for element in results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]["lighttpd-default-baseline"] ]) / expected_len)
    if len(results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]["lighttpd-default-baseline"]) != expected_len:
        print(" > mismatching result length for lighttpd_base")
        ask_to_stop()

    if "lighttpd-default-remon-noipmon" not in results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]:
        print(" > skipping server results due to missing GHUMVEE data")
        ask_to_stop()
    length = len(results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]["lighttpd-default-remon-noipmon"])
    lighttpd_full_results.ghumvee = server_data(
            sum([ element.reqsec for element in results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]["lighttpd-default-remon-noipmon"] ]) / length,
            sum([ element.avg_latency for element in results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]["lighttpd-default-remon-noipmon"] ]) / length)
    if len(results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]["lighttpd-default-remon-noipmon"]) != expected_len:
        print(" > mismatching result length for lighttpd_ghumvee")
        ask_to_stop()

    if "lighttpd-default-pmvee-noipmon" not in results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]:
        print(" > skipping server results due to missing PMVEE data")
        ask_to_stop()
    length = len(results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]["lighttpd-default-pmvee-noipmon"])
    lighttpd_full_results.pmvee = server_data(
            sum([ element.reqsec for element in results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]["lighttpd-default-pmvee-noipmon"] ]) / length,
            sum([ element.avg_latency for element in results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]["lighttpd-default-pmvee-noipmon"] ]) / length)
    if len(results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]["lighttpd-default-pmvee-noipmon"]) != expected_len:
        print(" > mismatching result length for lighttpd_pmvee")
        ask_to_stop()

    if "lighttpd-default-remon-withipmon" not in results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]:
        print(" > skipping server results due to missing ReMon data")
        ask_to_stop()
    length = len(results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]["lighttpd-default-remon-withipmon"])
    lighttpd_full_results.remon = server_data(
            sum([ element.reqsec for element in results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]["lighttpd-default-remon-withipmon"] ]) / length,
            sum([ element.avg_latency for element in results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]["lighttpd-default-remon-withipmon"] ]) / length)
    if len(results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]["lighttpd-default-remon-withipmon"]) != expected_len:
        print(" > mismatching result length for lighttpd_remon")
        ask_to_stop()

    if "lighttpd-default-pmvee-withipmon" not in results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]:
        print(" > skipping server results due to missing PMVEE IP-MON data")
        ask_to_stop()
    length = len(results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]["lighttpd-default-pmvee-withipmon"])
    lighttpd_full_results.pmvee_ipmon = server_data(
            sum([ element.reqsec for element in results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]["lighttpd-default-pmvee-withipmon"] ]) / length,
            sum([ element.avg_latency for element in results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]["lighttpd-default-pmvee-withipmon"] ]) / length)
    if len(results["merge-pmd-shorter-skip"]["pmvee"][lighttpd_connections]["lighttpd-default-pmvee-withipmon"]) != expected_len:
        print(" > mismatching result length for lighttpd_pmvee_ipmon")
        ask_to_stop()

    global nginx_C1_latency_native
    nginx_C1_latency_native = nginx_full_results[nginx_workers].baseline.latency
    global nginx_C1_latency_ReMon
    nginx_C1_latency_ReMon = nginx_full_results[nginx_workers].ghumvee.latency
    global nginx_C1_latency_FORTDIVIDE
    nginx_C1_latency_FORTDIVIDE = nginx_full_results[nginx_workers].pmvee.latency
    global nginx_C1_latency_ReMon_IPMON
    nginx_C1_latency_ReMon_IPMON = nginx_full_results[nginx_workers].remon.latency
    global nginx_C1_latency_FORTDIVIDE_IPMON
    nginx_C1_latency_FORTDIVIDE_IPMON = nginx_full_results[nginx_workers].pmvee_ipmon.latency
    global nginx_C2_latency_native
    nginx_C2_latency_native = nginx_split_results[nginx_workers].baseline.latency
    global nginx_C2_latency_ReMon
    nginx_C2_latency_ReMon = nginx_split_results[nginx_workers].ghumvee.latency
    global nginx_C2_latency_FORTDIVIDE
    nginx_C2_latency_FORTDIVIDE = nginx_split_results[nginx_workers].pmvee.latency
    global nginx_C2_latency_ReMon_IPMON
    nginx_C2_latency_ReMon_IPMON = nginx_split_results[nginx_workers].remon.latency
    global nginx_C2_latency_FORTDIVIDE_IPMON
    nginx_C2_latency_FORTDIVIDE_IPMON = nginx_split_results[nginx_workers].pmvee_ipmon.latency
    global lighttpd_C1_latency_native
    lighttpd_C1_latency_native = lighttpd_full_results.baseline.latency
    global lighttpd_C1_latency_ReMon
    lighttpd_C1_latency_ReMon = lighttpd_full_results.ghumvee.latency
    global lighttpd_C1_latency_FORTDIVIDE
    lighttpd_C1_latency_FORTDIVIDE = lighttpd_full_results.pmvee.latency
    global lighttpd_C1_latency_ReMon_IPMON
    lighttpd_C1_latency_ReMon_IPMON = lighttpd_full_results.remon.latency
    global lighttpd_C1_latency_FORTDIVIDE_IPMON
    lighttpd_C1_latency_FORTDIVIDE_IPMON = lighttpd_full_results.pmvee_ipmon.latency
    global lighttpd_C2_latency_native
    lighttpd_C2_latency_native = lighttpd_faster_results.baseline.latency
    global lighttpd_C2_latency_ReMon
    lighttpd_C2_latency_ReMon = lighttpd_faster_results.ghumvee.latency
    global lighttpd_C2_latency_FORTDIVIDE
    lighttpd_C2_latency_FORTDIVIDE = lighttpd_faster_results.pmvee.latency
    global lighttpd_C2_latency_ReMon_IPMON
    lighttpd_C2_latency_ReMon_IPMON = lighttpd_faster_results.remon.latency
    global lighttpd_C2_latency_FORTDIVIDE_IPMON
    lighttpd_C2_latency_FORTDIVIDE_IPMON = lighttpd_faster_results.pmvee_ipmon.latency
    global nginx_C1_overhead_native
    nginx_C1_overhead_native = nginx_full_results[nginx_workers].baseline.requests
    global nginx_C1_overhead_ReMon
    nginx_C1_overhead_ReMon = nginx_full_results[nginx_workers].ghumvee.requests
    global nginx_C1_overhead_FORTDIVIDE
    nginx_C1_overhead_FORTDIVIDE = nginx_full_results[nginx_workers].pmvee.requests
    global nginx_C1_overhead_ReMon_IPMON
    nginx_C1_overhead_ReMon_IPMON = nginx_full_results[nginx_workers].remon.requests
    global nginx_C1_overhead_FORTDIVIDE_IPMON
    nginx_C1_overhead_FORTDIVIDE_IPMON = nginx_full_results[nginx_workers].pmvee_ipmon.requests
    global nginx_C2_overhead_native
    nginx_C2_overhead_native = nginx_split_results[nginx_workers].baseline.requests
    global nginx_C2_overhead_ReMon
    nginx_C2_overhead_ReMon = nginx_split_results[nginx_workers].ghumvee.requests
    global nginx_C2_overhead_FORTDIVIDE
    nginx_C2_overhead_FORTDIVIDE = nginx_split_results[nginx_workers].pmvee.requests
    global nginx_C2_overhead_ReMon_IPMON
    nginx_C2_overhead_ReMon_IPMON = nginx_split_results[nginx_workers].remon.requests
    global nginx_C2_overhead_FORTDIVIDE_IPMON
    nginx_C2_overhead_FORTDIVIDE_IPMON = nginx_split_results[nginx_workers].pmvee_ipmon.requests
    global lighttpd_C1_overhead_native
    lighttpd_C1_overhead_native = lighttpd_full_results.baseline.requests
    global lighttpd_C1_overhead_ReMon
    lighttpd_C1_overhead_ReMon = lighttpd_full_results.ghumvee.requests
    global lighttpd_C1_overhead_FORTDIVIDE
    lighttpd_C1_overhead_FORTDIVIDE = lighttpd_full_results.pmvee.requests
    global lighttpd_C1_overhead_ReMon_IPMON
    lighttpd_C1_overhead_ReMon_IPMON = lighttpd_full_results.remon.requests
    global lighttpd_C1_overhead_FORTDIVIDE_IPMON
    lighttpd_C1_overhead_FORTDIVIDE_IPMON = lighttpd_full_results.pmvee_ipmon.requests
    global lighttpd_C2_overhead_native
    lighttpd_C2_overhead_native = lighttpd_faster_results.baseline.requests
    global lighttpd_C2_overhead_ReMon
    lighttpd_C2_overhead_ReMon = lighttpd_faster_results.ghumvee.requests
    global lighttpd_C2_overhead_FORTDIVIDE
    lighttpd_C2_overhead_FORTDIVIDE = lighttpd_faster_results.pmvee.requests
    global lighttpd_C2_overhead_ReMon_IPMON
    lighttpd_C2_overhead_ReMon_IPMON = lighttpd_faster_results.remon.requests
    global lighttpd_C2_overhead_FORTDIVIDE_IPMON
    lighttpd_C2_overhead_FORTDIVIDE_IPMON = lighttpd_faster_results.pmvee_ipmon.requests

    legend_labels = [ "baseline", "ReMon", "PMVEE", "ReMon + IP-MON", "PMVEE + IP-MON" ]
    legend = [ "+++", "\\\\\\\\", "...", "////", "OOO"]
    legend_colors = [ "white", "silver", "grey", "silver", "grey"]
    labels = [ "nginx", "lighttpd" ]
    
    blt.rc('font', size=15)
    fig, axes = blt.subplots(1, 2)
    fig.set_figwidth(8)
    fig.set_figheight(3)

    nginx_absolute_ax = axes[0]
    # nginx_absolute_ax.title.set_text("a) Request Latency (µs)")

    offsets_five = [ 0.7, 0.85, 1, 1.15, 1.3]

    baseline_ticks = [ offsets_five[0] + index for index in range(0, 2) ]
    remon_ticks = [ offsets_five[1] + index for index in range(0, 2) ]
    pmvee_ticks = [ offsets_five[2] + index for index in range(0, 2) ]
    remon_ipmon_ticks = [ offsets_five[3] + index for index in range(0, 2) ]
    pmvee_ipmon_ticks = [ offsets_five[4] + index for index in range(0, 2) ]
    width=0.15

    nginx_absolute_ax.bar(baseline_ticks, [nginx_full_results[nginx_workers].baseline.latency, nginx_split_results[nginx_workers].baseline.latency], width, align="center", label="baseline", edgecolor="black", hatch=legend[0], color=legend_colors[0], zorder=3)
    nginx_absolute_ax.bar(remon_ticks, [nginx_full_results[nginx_workers].ghumvee.latency, nginx_split_results[nginx_workers].ghumvee.latency], width, align="center", label="remon", edgecolor="black", hatch=legend[1], color=legend_colors[1], zorder=3)
    nginx_absolute_ax.bar(pmvee_ticks, [nginx_full_results[nginx_workers].pmvee.latency, nginx_split_results[nginx_workers].pmvee.latency], width, align="center", label="pmvee", edgecolor="black", hatch=legend[2], color=legend_colors[2], zorder=3)
    nginx_absolute_ax.bar(remon_ipmon_ticks, [nginx_full_results[nginx_workers].remon.latency, nginx_split_results[nginx_workers].remon.latency], width, align="center", label="remon+ipmon", edgecolor="black", hatch=legend[3], color=legend_colors[3], zorder=3)
    nginx_absolute_ax.bar(pmvee_ipmon_ticks, [nginx_full_results[nginx_workers].pmvee_ipmon.latency, nginx_split_results[nginx_workers].pmvee_ipmon.latency], width, align="center", label="pmvee+ipmon", edgecolor="black", hatch=legend[4], color=legend_colors[4], zorder=3)

    nginx_absolute_ax.set_xticks(range(1, 3))
    nginx_absolute_ax.set_xticklabels(["nginx C1", "nginx C2"])
    nginx_absolute_ax.spines['right'].set_visible(False)
    nginx_absolute_ax.spines['top'].set_visible(False)
    nginx_absolute_ax.grid(which="major", axis="y", dashes=(5, 5), zorder=-1)

    lighttpd_absolute_ax = axes[1]
    # lighttpd_absolute_ax.title.set_text("a) Request Latency (µs)")

    lighttpd_absolute_ax.bar(baseline_ticks, [lighttpd_full_results.baseline.latency, lighttpd_faster_results.baseline.latency], width, align="center", label="baseline", edgecolor="black", hatch=legend[0], color=legend_colors[0], zorder=3)
    lighttpd_absolute_ax.bar(remon_ticks, [lighttpd_full_results.ghumvee.latency, lighttpd_faster_results.ghumvee.latency], width, align="center", label="remon", edgecolor="black", hatch=legend[1], color=legend_colors[1], zorder=3)
    lighttpd_absolute_ax.bar(pmvee_ticks, [lighttpd_full_results.pmvee.latency, lighttpd_faster_results.pmvee.latency], width, align="center", label="pmvee", edgecolor="black", hatch=legend[2], color=legend_colors[2], zorder=3)
    lighttpd_absolute_ax.bar(remon_ipmon_ticks, [lighttpd_full_results.remon.latency, lighttpd_faster_results.remon.latency], width, align="center", label="remon+ipmon", edgecolor="black", hatch=legend[3], color=legend_colors[3], zorder=3)
    lighttpd_absolute_ax.bar(pmvee_ipmon_ticks, [lighttpd_full_results.pmvee_ipmon.latency, lighttpd_faster_results.pmvee_ipmon.latency], width, align="center", label="pmvee+ipmon", edgecolor="black", hatch=legend[4], color=legend_colors[4], zorder=3)

    lighttpd_absolute_ax.set_xticks(range(1, 3))
    lighttpd_absolute_ax.set_xticklabels(["lighttpd C1", "lighttpd C2"])
    nginx_absolute_ax.spines['right'].set_visible(False)
    nginx_absolute_ax.spines['top'].set_visible(False)
    lighttpd_absolute_ax.grid(which="major", axis="y", dashes=(5, 5), zorder=-1)

    blt.tight_layout(pad=0.5)
    # fig.legend(labels=legend_labels, loc="lower center", ncol=3, prop={'size': 15}, bbox_to_anchor=(0, 1))
    blt.figlegend(loc="lower center", ncol=3, prop={'size': 15}, labels=legend_labels, bbox_to_anchor=(0.5, 1))
    global latency_path
    latency_path = ("./servers_latency%s.pdf" % (suffix)) # os.path.abspath("./servers_latency%s.pdf" % (suffix))
    blt.savefig("servers_latency%s.pdf" % (suffix), format="pdf", bbox_inches="tight")
    
    blt.rc('font', size=15)
    fig, axes = blt.subplots(1, 2)
    fig.set_figwidth(8)
    fig.set_figheight(3)

    nginx_absolute_ax = axes[0]
    # nginx_absolute_ax.title.set_text("a) Request Latency (µs)")

    offsets_five = [ 0.7, 0.85, 1, 1.15, 1.3]

    baseline_ticks = [ offsets_five[0] + index for index in range(0, 2) ]
    remon_ticks = [ offsets_five[1] + index for index in range(0, 2) ]
    pmvee_ticks = [ offsets_five[2] + index for index in range(0, 2) ]
    remon_ipmon_ticks = [ offsets_five[3] + index for index in range(0, 2) ]
    pmvee_ipmon_ticks = [ offsets_five[4] + index for index in range(0, 2) ]
    width=0.15

    nginx_absolute_ax.bar(baseline_ticks, [nginx_full_results[nginx_workers].baseline.requests, nginx_split_results[nginx_workers].baseline.requests], width, align="center", label="baseline", edgecolor="black", hatch=legend[0], color=legend_colors[0], zorder=3)
    nginx_absolute_ax.bar(remon_ticks, [nginx_full_results[nginx_workers].ghumvee.requests, nginx_split_results[nginx_workers].ghumvee.requests], width, align="center", label="remon", edgecolor="black", hatch=legend[1], color=legend_colors[1], zorder=3)
    nginx_absolute_ax.bar(pmvee_ticks, [nginx_full_results[nginx_workers].pmvee.requests, nginx_split_results[nginx_workers].pmvee.requests], width, align="center", label="pmvee", edgecolor="black", hatch=legend[2], color=legend_colors[2], zorder=3)
    nginx_absolute_ax.bar(remon_ipmon_ticks, [nginx_full_results[nginx_workers].remon.requests, nginx_split_results[nginx_workers].remon.requests], width, align="center", label="remon+ipmon", edgecolor="black", hatch=legend[3], color=legend_colors[3], zorder=3)
    nginx_absolute_ax.bar(pmvee_ipmon_ticks, [nginx_full_results[nginx_workers].pmvee_ipmon.requests, nginx_split_results[nginx_workers].pmvee_ipmon.requests], width, align="center", label="pmvee+ipmon", edgecolor="black", hatch=legend[4], color=legend_colors[4], zorder=3)

    nginx_absolute_ax.set_xticks(range(1, 3))
    nginx_absolute_ax.set_xticklabels(["nginx C1", "nginx C2"])
    nginx_absolute_ax.spines['right'].set_visible(False)
    nginx_absolute_ax.spines['top'].set_visible(False)
    nginx_absolute_ax.grid(which="major", axis="y", dashes=(5, 5), zorder=-1)

    lighttpd_absolute_ax = axes[1]
    # lighttpd_absolute_ax.title.set_text("a) Request Latency (µs)")

    lighttpd_absolute_ax.bar(baseline_ticks, [lighttpd_full_results.baseline.requests, lighttpd_faster_results.baseline.requests], width, align="center", label="baseline", edgecolor="black", hatch=legend[0], color=legend_colors[0], zorder=3)
    lighttpd_absolute_ax.bar(remon_ticks, [lighttpd_full_results.ghumvee.requests, lighttpd_faster_results.ghumvee.requests], width, align="center", label="remon", edgecolor="black", hatch=legend[1], color=legend_colors[1], zorder=3)
    lighttpd_absolute_ax.bar(pmvee_ticks, [lighttpd_full_results.pmvee.requests, lighttpd_faster_results.pmvee.requests], width, align="center", label="pmvee", edgecolor="black", hatch=legend[2], color=legend_colors[2], zorder=3)
    lighttpd_absolute_ax.bar(remon_ipmon_ticks, [lighttpd_full_results.remon.requests, lighttpd_faster_results.remon.requests], width, align="center", label="remon+ipmon", edgecolor="black", hatch=legend[3], color=legend_colors[3], zorder=3)
    lighttpd_absolute_ax.bar(pmvee_ipmon_ticks, [lighttpd_full_results.pmvee_ipmon.requests, lighttpd_faster_results.pmvee_ipmon.requests], width, align="center", label="pmvee+ipmon", edgecolor="black", hatch=legend[4], color=legend_colors[4], zorder=3)

    lighttpd_absolute_ax.set_xticks(range(1, 3))
    lighttpd_absolute_ax.set_xticklabels(["lighttpd C1", "lighttpd C2"])
    nginx_absolute_ax.spines['right'].set_visible(False)
    nginx_absolute_ax.spines['top'].set_visible(False)
    lighttpd_absolute_ax.grid(which="major", axis="y", dashes=(5, 5), zorder=-1)

    blt.tight_layout(pad=0.5)
    # fig.legend(labels=legend_labels, loc="lower center", ncol=3, prop={'size': 15}, bbox_to_anchor=(0, 1))
    blt.figlegend(loc="lower center", ncol=3, prop={'size': 15}, labels=legend_labels, bbox_to_anchor=(0.5, 1))
    blt.savefig("servers_requests%s.pdf" % (suffix), format="pdf", bbox_inches="tight")


    fig, axes = blt.subplots(1, 1)
    fig.set_figwidth(8)
    fig.set_figheight(3)
    relative_ax = axes
    # relative_ax.title.set_text("b) Relative Throughput (% of native)")

    offsets_four = [ 0.7, 0.9, 1.1, 1.3 ]
    remon_ticks = [ offsets_four[0] + index for index in range(0, 4) ] # [0.7, 1.7, 1.7+1, 1.7+2 ] # [0.85, 1.85, 2.85]
    pmvee_ticks = [ offsets_four[1] + index for index in range(0, 4) ] # [0.9, 1.9, 1.9+1, 1.9+2 ] # [1, 2, 3]
    remon_ipmon_ticks = [ offsets_four[2] + index for index in range(0, 4) ] # [1.1, 2.1, 2.1+1, 2.1+2 ] # [1.15, 2.15, 3.15]
    pmvee_ipmon_ticks = [ offsets_four[3] + index for index in range(0, 4) ] # [1.3, 2.3, 2.3+1, 2.3+2 ] # [1.3, 2.3, 3.3]
    width=0.2

    remon_requests = [
        (nginx_full_results[nginx_workers].ghumvee.requests/nginx_full_results[nginx_workers].baseline.requests) * 100,
        (nginx_split_results[nginx_workers].ghumvee.requests/nginx_split_results[nginx_workers].baseline.requests) * 100,
        (lighttpd_full_results.ghumvee.requests/lighttpd_full_results.baseline.requests) * 100,
        (lighttpd_faster_results.ghumvee.requests/lighttpd_faster_results.baseline.requests) * 100
    ]
    pmvee_requests = [
        (nginx_full_results[nginx_workers].pmvee.requests/nginx_full_results[nginx_workers].baseline.requests) * 100,
        (nginx_split_results[nginx_workers].pmvee.requests/nginx_split_results[nginx_workers].baseline.requests) * 100,
        (lighttpd_full_results.pmvee.requests/lighttpd_full_results.baseline.requests) * 100,
        (lighttpd_faster_results.pmvee.requests/lighttpd_faster_results.baseline.requests) * 100
    ]
    remon_ipmon_requests =  [
        (nginx_full_results[nginx_workers].remon.requests/nginx_full_results[nginx_workers].baseline.requests) * 100,
        (nginx_split_results[nginx_workers].remon.requests/nginx_split_results[nginx_workers].baseline.requests) * 100,
        (lighttpd_full_results.remon.requests/lighttpd_full_results.baseline.requests) * 100,
        (lighttpd_faster_results.remon.requests/lighttpd_faster_results.baseline.requests) * 100
    ]
    pmvee_ipmon_requests = [
        (nginx_full_results[nginx_workers].pmvee_ipmon.requests/nginx_full_results[nginx_workers].baseline.requests) * 100,
        (nginx_split_results[nginx_workers].pmvee_ipmon.requests/nginx_split_results[nginx_workers].baseline.requests) * 100,
        (lighttpd_full_results.pmvee_ipmon.requests/lighttpd_full_results.baseline.requests) * 100,
        (lighttpd_faster_results.pmvee_ipmon.requests/lighttpd_faster_results.baseline.requests) * 100
    ]

    print(" > 1 worker baseline vs pmvee ipmon: %.2f - %.2f = %.2f (%.2f)" % (
        nginx_split_results[1].baseline.latency,
        nginx_split_results[1].pmvee_ipmon.latency,
        nginx_split_results[1].baseline.latency - nginx_split_results[1].pmvee_ipmon.latency,
        (nginx_split_results[1].baseline.latency - nginx_split_results[1].pmvee_ipmon.latency) / nginx_split_results[1].baseline.latency
    ))

    print(" > 4 worker baseline vs pmvee ipmon: %.2f - %.2f = %.2f (%.2f)" % (
        nginx_split_results[nginx_workers].baseline.latency,
        nginx_split_results[nginx_workers].pmvee_ipmon.latency,
        nginx_split_results[nginx_workers].baseline.latency - nginx_split_results[nginx_workers].pmvee_ipmon.latency,
        (nginx_split_results[nginx_workers].baseline.latency - nginx_split_results[nginx_workers].pmvee_ipmon.latency) / nginx_split_results[nginx_workers].baseline.latency
    ))

    print(" > 1 worker remon vs pmvee ipmon: %.2f - %.2f = %.2f (%.2f)" % (
        nginx_split_results[1].remon.latency,
        nginx_split_results[1].pmvee_ipmon.latency,
        nginx_split_results[1].remon.latency - nginx_split_results[1].pmvee_ipmon.latency,
        (nginx_split_results[1].remon.latency - nginx_split_results[1].pmvee_ipmon.latency) / nginx_split_results[1].remon.latency
    ))

    print(" > 4 worker remon vs pmvee ipmon: %.2f - %.2f = %.2f (%.2f)" % (
        nginx_split_results[nginx_workers].remon.latency,
        nginx_split_results[nginx_workers].pmvee_ipmon.latency,
        nginx_split_results[nginx_workers].remon.latency - nginx_split_results[nginx_workers].pmvee_ipmon.latency,
        (nginx_split_results[nginx_workers].remon.latency - nginx_split_results[nginx_workers].pmvee_ipmon.latency) / nginx_split_results[nginx_workers].remon.latency
    ))

    print(" > 1 vs 4 workers baseline, remon, and pmvee ipmon: %.2f -> %.2f -> %.2f" % (
        nginx_split_results[nginx_workers].baseline.latency / nginx_split_results[1].baseline.latency,
        nginx_split_results[nginx_workers].remon.latency / nginx_split_results[1].remon.latency,
        nginx_split_results[nginx_workers].pmvee_ipmon.latency / nginx_split_results[1].pmvee_ipmon.latency
    ))

    relative_ax.bar(remon_ticks, remon_requests, width, align="center", label="remon", edgecolor="black", hatch=legend[1], color=legend_colors[1], zorder=3)
    relative_ax.bar(pmvee_ticks, pmvee_requests, width, align="center", label="pmvee", edgecolor="black", hatch=legend[2], color=legend_colors[2], zorder=3)
    relative_ax.bar(remon_ipmon_ticks, remon_ipmon_requests, width, align="center", label="remon+ipmon", edgecolor="black", hatch=legend[3], color=legend_colors[3], zorder=3)
    relative_ax.bar(pmvee_ipmon_ticks, pmvee_ipmon_requests, width, align="center", label="pmvee+ipmon", edgecolor="black", hatch=legend[4], color=legend_colors[4], zorder=3)

    relative_ax.set_xticks([1, 2, 3, 4])
    relative_ax.set_xticklabels([ "nginx C1", "nginx C2", "lighttpd C1", "lighttpd C2" ])
    nginx_absolute_ax.spines['right'].set_visible(False)
    nginx_absolute_ax.spines['top'].set_visible(False)
    relative_ax.set_ylim((0, 105))
    
    blt.tight_layout(pad=0.5)
    # fig.legend(labels=legend_labels, loc="lower center", ncol=3, prop={'size': 15}, bbox_to_anchor=(0, 1))
    blt.grid(which="major", axis="y", dashes=(5, 5), zorder=-1)
    global overhead_path
    overhead_path = ("./servers_throughput%s.pdf" % (suffix)) # os.path.abspath("./servers_throughput%s.pdf" % (suffix))
    blt.savefig("servers_throughput%s.pdf" % (suffix), format="pdf", bbox_inches="tight")

pmvee_skip_server_results()
# pmvee_skip_server_results(4, 1, 1, 4, "_matched")
# pmvee_skip_server_results(nginx_workers=1, suffix="_single")
# pmvee_skip_server_results(4, 1, 1, 1, "_single_matched")

# server results: pmvee allocator, skip kernel


# Micro mapping count results

def micro_mapping_count_results_lower():
    if "merge-pmd-shorter-skip" not in results:
        print(" > skipping mapping count results due to missing data")
        return
    if "none" not in results["merge-pmd-shorter-skip"]:
        print(" > skipping server results due to missing pmvee allocator data")
        return
    mapping_count = results["merge-pmd-shorter-skip"]["none"]["mapping_count"]


    print(" > lower bound mapping count results ======================================")
    max_width = 0
    cpmon_delta_total = [ float("inf"), 0 ]
    nativ_delta_total = [ float("inf"), 0 ]
    cpmon_delta_avg = 0
    cpmon_delta_avg_count = 0
    table = {}
    counts = []
    for size in mapping_count.pmvee_ipmon.toggle_mappings:
        table[size] = {}
        max_width = max(max_width, len(str(size/0x1000)))
        cpmon_delta = [ float("inf"), 0 ]
        nativ_delta = [ float("inf"), 0 ]
        for count in mapping_count.pmvee_ipmon.toggle_mappings[size]:
            if count not in counts:
                counts.append(count)
            if count not in table[size]:
                table[size][count] = []
                max_width = max(max_width, len(str(count)))
            ipmon_time = (sum(mapping_count.pmvee_ipmon.toggle_mappings[size][count])/len(mapping_count.pmvee_ipmon.toggle_mappings[size][count]))
            table[size][count] = (ipmon_time)
            max_width = max(max_width, len("%.2f" % (ipmon_time)))
            cpmon_time = (sum(mapping_count.pmvee.toggle_mappings[size][count])/len(mapping_count.pmvee.toggle_mappings[size][count])) - ipmon_time
            nativ_time = ipmon_time - (sum(mapping_count.native.toggle_mappings[size][count])/len(mapping_count.native.toggle_mappings[size][count]))

            cpmon_delta_avg += cpmon_time
            cpmon_delta_avg_count += 1
            cpmon_delta[0] = min(cpmon_delta[0], cpmon_time)
            cpmon_delta[1] = max(cpmon_delta[1], cpmon_time)

            nativ_delta[0] = min(nativ_delta[0], nativ_time)
            nativ_delta[1] = max(nativ_delta[1], nativ_time)

            # print("   > %d * %d pages: %.2f || %.2f" % (count, size/0x1000, cpmon_time, nativ_time))
        # print(" > [ %.2f ; %.2f ] || [ %.2f ; %.2f ]" % (cpmon_delta[0], cpmon_delta[1], nativ_delta[0], nativ_delta[1]))

        cpmon_delta_total[0] = min(cpmon_delta_total[0], cpmon_delta[0])
        cpmon_delta_total[1] = max(cpmon_delta_total[1], cpmon_delta[1])

        nativ_delta_total[0] = min(nativ_delta_total[0], nativ_delta[0])
        nativ_delta_total[1] = max(nativ_delta_total[1], nativ_delta[1])

    print(" > [ %.2f ; %.2f ] || [ %.2f ; %.2f ]" % (cpmon_delta_total[0], cpmon_delta_total[1], nativ_delta_total[0], nativ_delta_total[1]))
    print(" > average: %.2f" % (cpmon_delta_avg / cpmon_delta_avg_count))
    global mapping_lower_table
    mapping_lower_table = " %s " % (max_width*' ')
    for size in table:
        mapping_lower_table += "| %s%s " % ((max_width-len(str(size/0x1000)))*' ', size/0x1000)
    mapping_lower_table += '\n'
    for count in counts:
        mapping_lower_table += " %s%s " % ((max_width-len(str(count)))*' ', count)
        for size in table:
            mapping_lower_table += "| %s%.2f " % ((max_width-len("%.2f"%(table[size][count])))*' ', table[size][count])
        mapping_lower_table += '\n'
    print()
    print(" > lower bound mapping count results ======================================")


    decorations = [ "o", "D", "^", "v", "*", "p" ]

    blt.rc('font', size=15)
    fig = blt.figure(figsize=(8, 4))
    decoration_i = 0
    allow = [ 1, 4, 16, 32, 64 ]
    for size in mapping_count.pmvee_ipmon.toggle_mappings:
        if size/0x1000 not in allow:
            continue
        # print(size/0x1000)
        size_plot_count = []
        size_plot_time = []
        for count in mapping_count.pmvee_ipmon.toggle_mappings[size]:
            size_plot_count.append(count)
            size_plot_time.append(sum(mapping_count.pmvee_ipmon.toggle_mappings[size][count]) / len(mapping_count.pmvee_ipmon.toggle_mappings[size][count]))
        blt.plot(size_plot_count, size_plot_time, label="%s pages"%int(size/0x1000), color="black", marker=decorations[decoration_i])
        decoration_i+=1
        # print(" > %d pages: %.2f -> %.2f" % (size/0x1000, size_plot_time[0], size_plot_time[-1]))
        # for i in range(len(size_plot_count)):
            # print("   > %d: %.2f" % (size_plot_count[i], size_plot_time[i]))
    blt.xlabel("# mappings to be migrated")
    blt.ylabel("migration duration (µs)")
    # ax = (fig.get_axes()[0])
    # box = ax.get_position()
    # ax.set_position([box.x0, box.y0 + box.height * 0.25, box.width, box.height * 0.75])
    fig.legend(loc="upper center", prop={'size': 15}, ncol=2, bbox_to_anchor=(0.36, 0.95))
    blt.grid(which="major", axis="y", dashes=(5, 5), zorder=-1)

    global mapping_lower_path
    mapping_lower_path = ("./micro_mapping_count_lower.pdf") # os.path.abspath("./micro_mapping_count_lowe.pdf")
    blt.savefig("micro_mapping_count_lower.pdf", format="pdf", bbox_inches="tight")


def micro_mapping_count_results_upper():
    if "merge-pmd-skip" not in results:
        print(" > skipping mapping count results due to missing data")
        return
    if "none" not in results["merge-pmd-skip"]:
        print(" > skipping server results due to missing pmvee allocator data")
        return

    mapping_count = results["merge-pmd-skip"]["none"]["mapping_count"]
    
    print(" > upper bound mapping count results ======================================")
    max_width = 0
    cpmon_delta_total = [ float("inf"), 0 ]
    nativ_delta_total = [ float("inf"), 0 ]
    cpmon_delta_avg = 0
    cpmon_delta_avg_count = 0
    table = {}
    counts = []
    for size in mapping_count.pmvee_ipmon.toggle_mappings:
        table[size] = {}
        max_width = max(max_width, len(str(size/0x1000)))
        cpmon_delta = [ float("inf"), 0 ]
        nativ_delta = [ float("inf"), 0 ]
        for count in mapping_count.pmvee_ipmon.toggle_mappings[size]:
            if count not in counts:
                counts.append(count)
            if count not in table[size]:
                table[size][count] = []
                max_width = max(max_width, len(str(count)))
            ipmon_time = (sum(mapping_count.pmvee_ipmon.toggle_mappings[size][count])/len(mapping_count.pmvee_ipmon.toggle_mappings[size][count]))
            table[size][count] = (ipmon_time)
            max_width = max(max_width, len("%.2f" % (ipmon_time)))
            cpmon_time = (sum(mapping_count.pmvee.toggle_mappings[size][count])/len(mapping_count.pmvee.toggle_mappings[size][count])) - ipmon_time
            nativ_time = ipmon_time - (sum(mapping_count.native.toggle_mappings[size][count])/len(mapping_count.native.toggle_mappings[size][count]))

            cpmon_delta_avg += cpmon_time
            cpmon_delta_avg_count += 1
            cpmon_delta[0] = min(cpmon_delta[0], cpmon_time)
            cpmon_delta[1] = max(cpmon_delta[1], cpmon_time)

            nativ_delta[0] = min(nativ_delta[0], nativ_time)
            nativ_delta[1] = max(nativ_delta[1], nativ_time)

            # print("   > %d * %d pages: %.2f || %.2f" % (count, size/0x1000, cpmon_time, nativ_time))
        # print(" > [ %.2f ; %.2f ] || [ %.2f ; %.2f ]" % (cpmon_delta[0], cpmon_delta[1], nativ_delta[0], nativ_delta[1]))

        cpmon_delta_total[0] = min(cpmon_delta_total[0], cpmon_delta[0])
        cpmon_delta_total[1] = max(cpmon_delta_total[1], cpmon_delta[1])

        nativ_delta_total[0] = min(nativ_delta_total[0], nativ_delta[0])
        nativ_delta_total[1] = max(nativ_delta_total[1], nativ_delta[1])

    print(" > [ %.2f ; %.2f ] || [ %.2f ; %.2f ]" % (cpmon_delta_total[0], cpmon_delta_total[1], nativ_delta_total[0], nativ_delta_total[1]))
    print(" > average: %.2f" % (cpmon_delta_avg / cpmon_delta_avg_count))
    global mapping_upper_table
    mapping_upper_table = " %s " % (max_width*' ')
    for size in table:
        mapping_upper_table += "| %s%s " % ((max_width-len(str(size/0x1000)))*' ', size/0x1000)
    mapping_upper_table += '\n'
    for count in counts:
        mapping_upper_table += " %s%s " % ((max_width-len(str(count)))*' ', count)
        for size in table:
            mapping_upper_table += "| %s%.2f " % ((max_width-len("%.2f"%(table[size][count])))*' ', table[size][count])
        mapping_upper_table += '\n'
    mapping_upper_table += '\n'
    print(" > upper bound mapping count results ======================================")

    decorations = [ "o", "D", "^", "v", "*", "p" ]

    blt.rc('font', size=15)
    fig = blt.figure(figsize=(8, 4))
    decoration_i = 0
    allow = [ 1, 4, 16, 32, 64 ]
    for size in mapping_count.pmvee_ipmon.toggle_mappings:
        if size/0x1000 not in allow:
            continue
        size_plot_count = []
        size_plot_time = []
        for count in mapping_count.pmvee_ipmon.toggle_mappings[size]:
            size_plot_count.append(count)
            size_plot_time.append(sum(mapping_count.pmvee_ipmon.toggle_mappings[size][count]) / len(mapping_count.pmvee_ipmon.toggle_mappings[size][count]))
        blt.plot(size_plot_count, size_plot_time, label="%s pages"%int(size/0x1000), color="black", marker=decorations[decoration_i])
        decoration_i+=1
    blt.xlabel("# mappings to be migrated")
    blt.ylabel("migration duration (µs)")
    # ax = (fig.get_axes()[0])
    # box = ax.get_position()
    # ax.set_position([box.x0, box.y0 + box.height * 0.25, box.width, box.height * 0.75])
    fig.legend(loc="upper center", prop={'size': 15}, ncol=2, bbox_to_anchor=(0.36, 0.95))
    blt.grid(which="major", axis="y", dashes=(5, 5), zorder=-1)

    global mapping_upper_path
    mapping_upper_path = ("./micro_mapping_count_upper.pdf") # os.path.abspath("./micro_mapping_count_upper.pdf")
    blt.savefig("micro_mapping_count_upper.pdf", format="pdf", bbox_inches="tight")


def micro_migration_results_upper():
    if "merge-pmd-shorter-skip" not in results:
        print(" > skipping mapping count results due to missing data")
        return
    if "none" not in results["merge-pmd-shorter-skip"]:
        print(" > skipping server results due to missing pmvee allocator data")
        return

    mapping_count = results["merge-pmd-shorter-skip"]["none"]["mapping_count"]

    decorations = [ "v", "^" ]

    blt.rc('font', size=15)
    fig = blt.figure(figsize=(8, 4))
    decoration_i = 0
    size_plot_count = []
    size_plot_time = []
    pointer = [float('inf'), 0]
    asis = [float('inf'), 0]
    for count in mapping_count.pmvee_ipmon.migrations:
        size_plot_count.append(count)
        asis = [min(asis[0], sum(mapping_count.pmvee_ipmon.migrations[count]) / len(mapping_count.pmvee_ipmon.migrations[count])), max(asis[1], sum(mapping_count.pmvee_ipmon.migrations[count]) / len(mapping_count.pmvee_ipmon.migrations[count]))]
        size_plot_time.append(sum(mapping_count.pmvee_ipmon.migrations[count]) / len(mapping_count.pmvee_ipmon.migrations[count]))
    blt.plot(size_plot_count, size_plot_time, label="migration", color="black", marker=decorations[decoration_i])
    decoration_i+=1
    size_plot_count = []
    size_plot_time = []
    for count in mapping_count.pmvee_ipmon.pointers:
        size_plot_count.append(count)
        pointer = [min(asis[0], sum(mapping_count.pmvee_ipmon.pointers[count]) / len(mapping_count.pmvee_ipmon.pointers[count])), max(asis[1], sum(mapping_count.pmvee_ipmon.pointers[count]) / len(mapping_count.pmvee_ipmon.pointers[count]))]
        size_plot_time.append(sum(mapping_count.pmvee_ipmon.pointers[count]) / len(mapping_count.pmvee_ipmon.pointers[count]))
    blt.plot(size_plot_count, size_plot_time, label="pointer migration", color="black", marker=decorations[decoration_i])
    decoration_i+=1
    blt.xlabel("# values to be migrated")
    blt.ylabel("migration duration (µs)")
    # ax = (fig.get_axes()[0])
    # box = ax.get_position()
    # ax.set_position([box.x0, box.y0 + box.height * 0.25, box.width, box.height * 0.75])
    fig.legend(loc="upper center", prop={'size': 15}, ncol=1, bbox_to_anchor=(0.29, 0.95))
    blt.grid(which="major", axis="y", dashes=(5, 5), zorder=-1)

    global migration_path
    migration_path = ("./migrations.pdf") # os.path.abspath("./migrations.pdf")
    blt.savefig("migrations.pdf", format="pdf", bbox_inches="tight")

    global migration_table
    migration_table = ""
    for count in mapping_count.pmvee_ipmon.pointers:
        migration_table += "%d\t| %.2f\t | %.2f\n" % (count, sum(mapping_count.pmvee_ipmon.migrations[count])/len(mapping_count.pmvee_ipmon.migrations[count]), sum(mapping_count.pmvee_ipmon.pointers[count])/len(mapping_count.pmvee_ipmon.migrations[count]))

micro_mapping_count_results_lower()
micro_mapping_count_results_upper()
micro_migration_results_upper()
# Micro mapping count results


# Micro mapping count results

def micro_mapping_count_results():
    if "shortest-skip" not in results:
        print(" > skipping server results due to missing skip data")
        return
    if "none" not in results["shortest-skip"]:
        print(" > skipping server results due to missing pmvee allocator data")
        return
    mapping_count = results["shortest-skip"]["none"]["mapping_count"]

    decorations = [ "o", "D", "^", "v", "*", "p" ]

    blt.rc('font', size=15)
    fig, pmvee_ax = blt.subplots(1, 1)
    fig.set_figwidth(8)
    fig.set_figheight(4)

    labels = []

    allow = [ 1, 4, 16, 64 ]

    # pmvee_ax = axes[0]
    # pmvee_ax.title.set_text("a) CP-MON call gate")

    decoration_i = 0
    for size in mapping_count.pmvee.toggle_mappings:
        if size/0x1000 not in allow:
            continue
        size_plot_count = []
        size_plot_time = []
        for count in mapping_count.pmvee.toggle_mappings[size]:
            size_plot_count.append(count)
            size_plot_time.append(sum(mapping_count.pmvee.toggle_mappings[size][count]) / len(mapping_count.pmvee.toggle_mappings[size][count]))
        pmvee_ax.plot(size_plot_count, size_plot_time, label="%s pages"%int(size/0x1000), color="black", marker=decorations[decoration_i])
        labels.append("%s pages"%int(size/0x1000))
        decoration_i+=1
    pmvee_ax.set_xlabel("# mappings to be migrated")

    # pmvee_ipmon_ax = axes[1]
    # pmvee_ipmon_ax.title.set_text("b) IP-MON call gate")
# 
    # decoration_i = 0
    # for size in mapping_count.pmvee.toggle_mappings:
    #     if size/0x1000 not in allow:
    #         continue
    #     size_plot_count = []
    #     size_plot_time = []
    #     for count in mapping_count.pmvee.toggle_mappings[size]:
    #         size_plot_count.append(count)
    #         size_plot_time.append(sum(mapping_count.pmvee_ipmon.toggle_mappings[size][count]) / len(mapping_count.pmvee.toggle_mappings[size][count]))
    #     pmvee_ipmon_ax.plot(size_plot_count, size_plot_time, label="%s pages"%int(size/0x1000), color="black", marker=decorations[decoration_i])
    #     decoration_i+=1
    # pmvee_ipmon_ax.set_xlabel("# mappings to be migrated")
# 
# 
    # maxy = max(pmvee_ax.get_ylim()[1], pmvee_ipmon_ax.get_ylim()[1])
    # pmvee_ax.set_ylim([0, maxy])
    # pmvee_ipmon_ax.set_ylim([0, maxy])
    pmvee_ax.set_ylabel("migration duration (µs)")
    # ax = (fig.get_axes()[0])
    # box = ax.get_position()
    # ax.set_position([box.x0, box.y0 + box.height * 0.25, box.width, box.height * 0.75])
    # fig.legend(loc="lower center", labels=labels, prop={'size': 15}, ncol=4, bbox_to_anchor=(0.5, -0.14))
    fig.legend(loc="upper center", labels=labels, prop={'size': 15}, ncol=2, bbox_to_anchor=(0.35, 0.95))
    blt.tight_layout(pad=0.5)
    blt.savefig("micro_mapping_count.pdf", format="pdf", bbox_inches="tight")

# micro_mapping_count_results()
# Micro mapping count results



# Micro mapping count results compare native

def micro_mapping_count_stacked():
    if "shortest-skip" not in results:
        print(" > skipping server results due to missing skip data")
        return
    if "none" not in results["shortest-skip"]:
        print(" > skipping server results due to missing pmvee allocator data")
        return
    mapping_count = results["shortest-skip"]["none"]["mapping_count"]

    blt.rc('font', size=15)
    fig = blt.figure(figsize=(8, 4))
    decoration_i = 0
    size_plot_count = []
    size_plot_time = [[], [], []]
    size = 64*0x1000
    for count in mapping_count.pmvee.toggle_mappings[size]:
        size_plot_count.append(count)
        size_plot_time[2].append(sum(mapping_count.pmvee.toggle_mappings[size][count]) / len(mapping_count.pmvee.toggle_mappings[size][count]))
    for count in mapping_count.native.toggle_mappings[size]:
        size_plot_time[1].append(sum(mapping_count.pmvee_ipmon.toggle_mappings[size][count]) / len(mapping_count.pmvee_ipmon.toggle_mappings[size][count]))
    for count in mapping_count.native.toggle_mappings[size]:
        size_plot_time[0].append(sum(mapping_count.native.toggle_mappings[size][count]) / len(mapping_count.native.toggle_mappings[size][count]))
    # for i in range(len(size_plot_time[0])):
    #     size_plot_time[2][i] -= size_plot_time[1][i]
    # for i in range(len(size_plot_time[0])):
    #     size_plot_time[1][i] -= size_plot_time[0][i]

    blt.stackplot(size_plot_count, np.vstack([size_plot_time[2]]), colors=[ "gray" ], hatch="..", edgecolors=[ "black" ])
    blt.stackplot(size_plot_count, np.vstack([size_plot_time[1]]), colors=[ "gray" ], hatch="OO", edgecolors=[ "black" ])
    blt.stackplot(size_plot_count, np.vstack([size_plot_time[0]]), colors=[ "white" ], hatch="++", edgecolors=[ "black" ])
    decoration_i+=1
    blt.xlabel("# mappings to be migrated")
    blt.ylabel("migration duration (µs)")
    # ax = (fig.get_axes()[0])
    # box = ax.get_position()
    # ax.set_position([box.x0, box.y0 + box.height * 0.25, box.width, box.height * 0.75])
    fig.legend(loc="upper center", prop={'size': 15}, ncol=1, bbox_to_anchor=(0.3, 0.88), labels=["PMVEE", "PMVEE + IP-MON", "native"])

    print(" > native getpid: %.2f us" % (sum(mapping_count.native.mvx_getpid) / len(mapping_count.native.mvx_getpid)))
    print(" > ipmon getpid: %.2f us" % (sum(mapping_count.pmvee_ipmon.mvx_getpid) / len(mapping_count.pmvee_ipmon.mvx_getpid)))
    print(" > CP-MON getpid: %.2f us" % (sum(mapping_count.pmvee.mvx_getpid) / len(mapping_count.pmvee.mvx_getpid)))
    print(" > native enter_exit: %.2f us" % size_plot_time[0][0])
    print(" > ipmon enter_exit: %.2f us" % size_plot_time[1][0])
    print(" > CP-MON enter_exit: %.2f us" % size_plot_time[2][0])

    blt.savefig("micro_mapping_count_stack_pmveevnative.pdf", format="pdf", bbox_inches="tight")

micro_mapping_count_stacked()
# Micro mapping count results compare native


# Kernel module impact

def pmvee_skip_server_results():
    if "shortest-skip" not in results or "none" not in results["shortest-skip"] or "mapping_count" not in results["shortest-skip"]["none"]:
        print(" > skipping kernel impact results due to missing shortest-skip data")
        return
    if "skip" not in results or "none" not in results["skip"] or "mapping_count" not in results["skip"]["none"]:
        print(" > skipping kernel impact results due to missing skip data")
        return
    if "no-unmap" not in results or "none" not in results["no-unmap"] or "mapping_count" not in results["no-unmap"]["none"]:
        print(" > skipping kernel impact results due to missing naive data")
        return
    if "naive" not in results or "none" not in results["naive"] or "mapping_count" not in results["naive"]["none"]:
        print(" > skipping kernel impact results due to missing naive data")
        return

    legend =        [ "",      "..",     "//",   "xx" ]
    decorations =   [ "o",     "D",      "^",    "v", "*", "p" ]
    legend_colors = [ "white", "silver", "grey", "grey" ]
    labels =        []
    
    blt.rc('font', size=15)
    fig = blt.figure(figsize=(8, 4))

    blt.ylabel("partial fork duration (µs)")

    naive_ticks = [ 0.7, 1.7, 2.7, 3.7 ]
    avoid_unmap_ticks = [ 0.9, 1.9, 2.9, 3.9 ]
    skip_ticks = [ 1.1, 2.1, 3.1, 4.1 ]
    shortest_skip_ticks = [ 1.3, 2.3, 3.3, 4.3 ]
    width=0.2

    allow = [ 1, 4, 16, 64 ]
    count = 100
    shortest_skip = []
    skip = []
    avoid_unmap = []
    naive = []
    for allowed in allow:
        labels.append("%d pages" % allowed)
        naive_average = results["naive"]["none"]["mapping_count"].native.toggle_mappings[allowed*0x1000][count]
        avoid_unmap_average = results["no-unmap"]["none"]["mapping_count"].native.toggle_mappings[allowed*0x1000][count]
        skip_average = results["skip"]["none"]["mapping_count"].native.toggle_mappings[allowed*0x1000][count]
        shortest_skip_average = results["shortest-skip"]["none"]["mapping_count"].native.toggle_mappings[allowed*0x1000][count]

        naive.append(sum(naive_average)/len(naive_average))
        avoid_unmap.append(sum(avoid_unmap_average)/len(avoid_unmap_average))
        skip.append(sum(skip_average)/len(skip_average))
        shortest_skip.append(sum(shortest_skip_average)/len(shortest_skip_average))
    # allow = [ 0, 1, 5, 10, 20, 50, 100, 200 ]
    # for count in allow:
    #     naive_average = results["naive"]["none"]["mapping_count"].native.toggle_mappings[16*0x1000][count]
    #     avoid_unmap_average = results["no-unmap"]["none"]["mapping_count"].native.toggle_mappings[16*0x1000][count]
    #     skip_average = results["skip"]["none"]["mapping_count"].native.toggle_mappings[16*0x1000][count]
    #     shortest_skip_average = results["shortest-skip"]["none"]["mapping_count"].native.toggle_mappings[16*0x1000][count]
# 
    #     naive.append(sum(naive_average)/len(naive_average))
    #     avoid_unmap.append(sum(avoid_unmap_average)/len(avoid_unmap_average))
    #     skip.append(sum(skip_average)/len(skip_average))
    #     shortest_skip.append(sum(shortest_skip_average)/len(shortest_skip_average))

    # blt.bar(naive_ticks, naive, width, align="center", label="munmap and mmap", edgecolor="black", hatch=legend[0], color=legend_colors[0])
    # blt.bar(avoid_unmap_ticks, avoid_unmap, width, align="center", label="Calling kernel PTE manipulation", edgecolor="black", hatch=legend[1], color=legend_colors[1])
    # blt.bar(skip_ticks, skip, width, align="center", label="Custom PTE manipulation", edgecolor="black", hatch=legend[2], color=legend_colors[2])
    # blt.bar(shortest_skip_ticks, shortest_skip, width, align="center", label="Shortened custom PTE manipulation", edgecolor="black", hatch=legend[3], color=legend_colors[3])
    
    blt.plot(allow, naive,
    label="(a) munmap and mmap", color="gray", marker="o")
    blt.plot(allow, avoid_unmap, label="(b) Always reset COW", color="gray", marker="D")
    # blt.plot(allow, skip, label="(c) Skip if still COW", color="gray", marker="^")
    blt.plot(allow, shortest_skip, label="(c) Skip if still COW", color="gray", marker="v")


    print(naive)
    skip_over_shortest_skip = []
    for i in range(0, len(allow)):
        skip_over_shortest_skip.append(skip[i] / shortest_skip[i])
    print("skip/shortest_skip: %s" % skip_over_shortest_skip)

    blt.xticks(allow, allow)

    # shortest_skip = [ results["shortest-skip"]["none"]["mapping_count"].native.toggle_mappings[16*0x1000][item] for item in results["shortest-skip"]["none"]["mapping_count"].native.toggle_mappings[16*0x1000] if str(item) in labels]
    # skip = [ results["skip"]["none"]["mapping_count"].native.toggle_mappings[16*0x1000][item] for item in results["skip"]["none"]["mapping_count"].native.toggle_mappings[16*0x1000] if str(item) in labels]
    # avoid_unmap = [ results["no-unmap"]["none"]["mapping_count"].native.toggle_mappings[16*0x1000][item] for item in results["no-unmap"]["none"]["mapping_count"].native.toggle_mappings[16*0x1000] if str(item) in labels]
    # naive = [ results["naive"]["none"]["mapping_count"].native.toggle_mappings[16*0x1000][item] for item in results["naive"]["none"]["mapping_count"].native.toggle_mappings[16*0x1000] if str(item) in labels]
# 
    # naive = [ sum(average)/len(average) for average in naive]
    # avoid_unmap = [ sum(average)/len(average) for average in avoid_unmap]
    # skip = [ sum(average)/len(average) for average in skip]
    # shortest_skip = [ sum(average)/len(average) for average in shortest_skip]
# 
    # sixteen_pages.bar(naive_ticks, naive, width, align="center", label="baseline", edgecolor="black", hatch=legend[0], color=legend_colors[0])
    # sixteen_pages.bar(avoid_unmap_ticks, avoid_unmap, width, align="center", label="remon", edgecolor="black", hatch=legend[1], color=legend_colors[1])
    # sixteen_pages.bar(skip_ticks, skip, width, align="center", label="Custom PTE manipulation", edgecolor="black", hatch=legend[2], color=legend_colors[2])
    # sixteen_pages.bar(shortest_skip_ticks, shortest_skip, width, align="center", label="remon+ipmon", edgecolor="black", hatch=legend[3], color=legend_colors[3])
# 
    # sixteen_pages.title.set_text("(a) 16 pages")
    # sixteen_pages.set_xticks([1, 2, 3])
    # sixteen_pages.set_xticklabels(labels)
# 
    # maxy = max(four_pages.get_ylim()[1], sixteen_pages.get_ylim()[1])
    # four_pages.set_ylim([0, maxy])
    # sixteen_pages.set_ylim([0, maxy])
    
    blt.tight_layout(pad=0.5)
    blt.figlegend(loc="lower center", ncol=2, prop={'size': 15}, bbox_to_anchor=(0.5, -0.19))
    blt.savefig("module_impact.pdf", format="pdf", bbox_inches="tight")

pmvee_skip_server_results()


def nginx_progress_process():
    print("nginx progress results:")
    if "merge-pmd-shorter-skip" not in results or "pmvee" not in results["merge-pmd-shorter-skip"] or 10 not in results["merge-pmd-shorter-skip"]["pmvee"]:
        return
    server_data = results["merge-pmd-shorter-skip"]["pmvee"][10]

    

    if "nginx-4-baseline" not in server_data:
        print(" > missing baseline data")
        return
    nginx_baseline = sum([ element.reqsec for element in server_data["nginx-4-baseline"] ]) / len(server_data["nginx-4-baseline"])
    if "nginx-diffed-4-baseline" not in server_data:
        print(" > missing diffed baseline data")
        return
    nginx_diffed_baseline = sum([ element.reqsec for element in server_data["nginx-diffed-4-baseline"] ]) / len(server_data["nginx-diffed-4-baseline"])
    if "nginx-scan-4-baseline" not in server_data:
        print(" > missing scan baseline data")
        return
    nginx_scan_baseline = sum([ element.reqsec for element in server_data["nginx-scan-4-baseline"] ]) / len(server_data["nginx-scan-4-baseline"])

    if "nginx-4-pmvee-withipmon" not in server_data:
        print(" > missing pmvee data")
        return
    nginx_pmvee_withipmon = sum([ element.reqsec for element in server_data["nginx-4-pmvee-withipmon"] ]) / len(server_data["nginx-4-pmvee-withipmon"])
    if "nginx-diffed-4-pmvee-withipmon" not in server_data:
        print(" > missing pmvee diffed data")
        return
    nginx_diffed_pmvee_withipmon = sum([ element.reqsec for element in server_data["nginx-diffed-4-pmvee-withipmon"] ]) / len(server_data["nginx-diffed-4-pmvee-withipmon"])
    if "nginx-scan-4-pmvee-withipmon" not in server_data:
        print(" > missing pmvee scan data")
        return
    nginx_scan_pmvee_withipmon = sum([ element.reqsec for element in server_data["nginx-scan-4-pmvee-withipmon"] ]) / len(server_data["nginx-scan-4-pmvee-withipmon"])
    if "nginx-emulate--scan-4-pmvee-withipmon" not in server_data:
        print(" > missing emulated scan data")
        return
    nginx_emulate_scan_pmvee_withipmon = sum([ element.reqsec for element in server_data["nginx-emulate--scan-4-pmvee-withipmon"] ]) / len(server_data["nginx-emulate--scan-4-pmvee-withipmon"])

    global nginx_C2_manual_migration_handlers
    nginx_C2_manual_migration_handlers = nginx_pmvee_withipmon
    global nginx_C2_known_globals
    nginx_C2_known_globals = nginx_diffed_pmvee_withipmon
    global nginx_C2_pointer_scanning
    nginx_C2_pointer_scanning = nginx_scan_pmvee_withipmon
    # print(" > baseline:         %.2f" % nginx_baseline)
    # print(" > pmvee:            %.2f (%.2f)" % (nginx_pmvee_withipmon, 100*(nginx_pmvee_withipmon/nginx_baseline)))
    # print(" > baseline diffed:  %.2f" % nginx_diffed_baseline)
    # print(" > pmvee diffed:     %.2f (%.2f)" % (nginx_diffed_pmvee_withipmon, 100*(nginx_diffed_pmvee_withipmon/nginx_diffed_baseline)))
    # print(" > baseline scan:    %.2f" % nginx_scan_baseline)
    # print(" > pmvee scan:       %.2f (%.2f)" % (nginx_scan_pmvee_withipmon, 100*(nginx_scan_pmvee_withipmon/nginx_scan_baseline)))
    # print(" > baseline emulate: %.2f" % nginx_scan_baseline)
    # print(" > pmvee emulate:    %.2f (%.2f)" % (nginx_emulate_scan_pmvee_withipmon, 100*(nginx_emulate_scan_pmvee_withipmon/nginx_scan_baseline)))


nginx_progress_process()


def allocator_process():
    print("ällocator results:")
    if "merge-pmd-shorter-skip" not in results:
        return
    if "pmvee" not in results["merge-pmd-shorter-skip"] or 10 not in results["merge-pmd-shorter-skip"]["pmvee"]:
        return
    if "libc" not in results["merge-pmd-shorter-skip"] or 10 not in results["merge-pmd-shorter-skip"]["libc"]:
        return
    pmvee_alloc_data = results["merge-pmd-shorter-skip"]["pmvee"][10]
    libc_alloc_data = results["merge-pmd-shorter-skip"]["libc"][10]



    if "nginx-4-baseline" not in pmvee_alloc_data:
        print(" > missing baseline data")
        return
    nginx_pmvee_alloc_baseline = sum([ element.reqsec for element in pmvee_alloc_data["nginx-4-baseline"] ]) / len(pmvee_alloc_data["nginx-4-baseline"])
    if "nginx-4-baseline" not in libc_alloc_data:
        print(" > missing baseline data")
        return
    nginx_libc_alloc_baseline = sum([ element.reqsec for element in libc_alloc_data["nginx-4-baseline"] ]) / len(libc_alloc_data["nginx-4-baseline"])

    if "nginx-4-pmvee-withipmon" not in pmvee_alloc_data:
        print(" > missing pmvee-withipmon data")
        return
    nginx_pmvee_alloc_pmvee_withipmon = sum([ element.reqsec for element in pmvee_alloc_data["nginx-4-pmvee-withipmon"] ]) / len(pmvee_alloc_data["nginx-4-pmvee-withipmon"])
    if "nginx-4-pmvee-withipmon" not in libc_alloc_data:
        print(" > missing pmvee-withipmon data")
        return
    nginx_libc_alloc_pmvee_withipmon = sum([ element.reqsec for element in libc_alloc_data["nginx-4-pmvee-withipmon"] ]) / len(libc_alloc_data["nginx-4-pmvee-withipmon"])



    if "lighttpd-faster-baseline" not in pmvee_alloc_data:
        print(" > missing baseline data")
        return
    lighttpd_pmvee_alloc_baseline = sum([ element.reqsec for element in pmvee_alloc_data["lighttpd-faster-baseline"] ]) / len(pmvee_alloc_data["lighttpd-faster-baseline"])
    if "lighttpd-faster-baseline" not in libc_alloc_data:
        print(" > missing baseline data")
        return
    lighttpd_libc_alloc_baseline = sum([ element.reqsec for element in libc_alloc_data["lighttpd-faster-baseline"] ]) / len(libc_alloc_data["lighttpd-faster-baseline"])

    if "lighttpd-faster-pmvee-withipmon" not in pmvee_alloc_data:
        print(" > missing pmvee-withipmon data")
        return
    lighttpd_pmvee_alloc_pmvee_withipmon = sum([ element.reqsec for element in pmvee_alloc_data["lighttpd-faster-pmvee-withipmon"] ]) / len(pmvee_alloc_data["lighttpd-faster-pmvee-withipmon"])
    if "lighttpd-faster-pmvee-withipmon" not in libc_alloc_data:
        print(" > missing pmvee-withipmon data")
        return
    lighttpd_libc_alloc_pmvee_withipmon = sum([ element.reqsec for element in libc_alloc_data["lighttpd-faster-pmvee-withipmon"] ]) / len(libc_alloc_data["lighttpd-faster-pmvee-withipmon"])

    global nginx_C2_libc_allocator
    nginx_C2_libc_allocator = nginx_libc_alloc_pmvee_withipmon
    global nginx_C2_FORTDIVIDE_allocator
    nginx_C2_FORTDIVIDE_allocator = nginx_pmvee_alloc_pmvee_withipmon
    global lighttpd_C2_libc_allocator
    lighttpd_C2_libc_allocator = lighttpd_libc_alloc_pmvee_withipmon
    global lighttpd_C2_FORTDIVIDE_allocator
    lighttpd_C2_FORTDIVIDE_allocator = lighttpd_pmvee_alloc_pmvee_withipmon


    # print(" > nginx pmvee baseline: %.2f" % (nginx_pmvee_alloc_baseline))
    # print(" > nginx pmvee pmvee:    %.2f (%.2f)" % (nginx_pmvee_alloc_pmvee_withipmon, (nginx_pmvee_alloc_pmvee_withipmon/nginx_pmvee_alloc_baseline)*100))
    # print(" > nginx libc baseline:  %.2f" % (nginx_libc_alloc_baseline))
    # print(" > nginx libc pmvee:     %.2f (%.2f)" % (nginx_libc_alloc_pmvee_withipmon, (nginx_libc_alloc_pmvee_withipmon/nginx_libc_alloc_baseline)*100))
    # 
    # print(" > lighttpd pmvee baseline: %.2f" % (lighttpd_pmvee_alloc_baseline))
    # print(" > lighttpd pmvee pmvee:    %.2f (%.2f)" % (lighttpd_pmvee_alloc_pmvee_withipmon, (lighttpd_pmvee_alloc_pmvee_withipmon/lighttpd_pmvee_alloc_baseline)*100))
    # print(" > lighttpd libc baseline:  %.2f" % (lighttpd_libc_alloc_baseline))
    # print(" > lighttpd libc pmvee:     %.2f (%.2f)" % (lighttpd_libc_alloc_pmvee_withipmon, (lighttpd_libc_alloc_pmvee_withipmon/lighttpd_libc_alloc_baseline)*100))


allocator_process()

# Kernel module impact


if "shortest-skip" in results:
    if "libc" in results["shortest-skip"] and "pmvee" in results["shortest-skip"]:
        expected_len = len(results["shortest-skip"]["pmvee"]["nginx-full-4-baseline"])
        nginx_base = sum([ element.reqsec for element in results["shortest-skip"]["pmvee"]["nginx-full-4-baseline"] ]) / expected_len
        print("nginx_base: %.4f" % nginx_base)
        nginx_pmvee_ipmon = sum([ element.reqsec for element in results["shortest-skip"]["pmvee"]["nginx-full-4-pmvee-withipmon"] ]) / expected_len
        print("nginx_pmvee_ipmon: %.4f" % (nginx_pmvee_ipmon/nginx_base))
        if len(results["shortest-skip"]["pmvee"]["nginx-full-4-pmvee-withipmon"]) != expected_len:
            print("len(results[\"shortest-skip\"][\"pmvee\"][\"nginx-full-4-pmvee-withipmon\"]) != expected_len: %d != %d" % (len(results["shortest-skip"]["pmvee"]["nginx-full-4-pmvee-withipmon"]), expected_len))
            exit(0)
        lighttpd_base = sum([ element.reqsec for element in results["shortest-skip"]["pmvee"]["lighttpd-baseline"] ]) / expected_len
        print("lighttpd_base: %.4f" % lighttpd_base)
        if len(results["shortest-skip"]["pmvee"]["lighttpd-baseline"]) != expected_len:
            print("len(results[\"shortest-skip\"][\"pmvee\"][\"lighttpd-baseline\"]) != expected_len: %d != %d" % (len(results["shortest-skip"]["pmvee"]["lighttpd-baseline"]), expected_len))
            exit(0)
        lighttpd_pmvee_ipmon = sum([ element.reqsec for element in results["shortest-skip"]["pmvee"]["lighttpd-pmvee-withipmon"] ]) / expected_len
        print("lighttpd_pmvee_ipmon: %.4f" % (lighttpd_pmvee_ipmon/lighttpd_base))
        if len(results["shortest-skip"]["pmvee"]["lighttpd-pmvee-withipmon"]) != expected_len:
            print("len(results[\"shortest-skip\"][\"pmvee\"][\"lighttpd-pmvee-withipmon\"]) != expected_len: %d != %d" % (len(results["shortest-skip"]["pmvee"]["lighttpd-pmvee-withipmon"]), expected_len))
            exit(0)

        libc_nginx_base = sum([ element.reqsec for element in results["shortest-skip"]["libc"]["nginx-full-4-baseline"] ]) / expected_len
        print("libc_nginx_base: %.4f" % libc_nginx_base)
        libc_nginx_pmvee_ipmon = sum([ element.reqsec for element in results["shortest-skip"]["libc"]["nginx-full-4-pmvee-withipmon"] ]) / expected_len
        print("libc_nginx_pmvee_ipmon: %.4f" % (libc_nginx_pmvee_ipmon/libc_nginx_base))
        if len(results["shortest-skip"]["libc"]["nginx-full-4-pmvee-withipmon"]) != expected_len:
            print("len(results[\"shortest-skip\"][\"libc\"][\"nginx-full-4-pmvee-withipmon\"]) != expected_len: %d != %d" % (len(results["shortest-skip"]["libc"]["nginx-full-4-pmvee-withipmon"]), expected_len))
            exit(0)
        libc_lighttpd_base = sum([ element.reqsec for element in results["shortest-skip"]["libc"]["lighttpd-baseline"] ]) / expected_len
        print("libc_lighttpd_base: %.4f" % libc_lighttpd_base)
        if len(results["shortest-skip"]["libc"]["lighttpd-baseline"]) != expected_len:
            print("len(results[\"shortest-skip\"][\"libc\"][\"lighttpd-baseline\"]) != expected_len: %d != %d" % (len(results["shortest-skip"]["libc"]["lighttpd-baseline"]), expected_len))
            exit(0)
        libc_lighttpd_pmvee_ipmon = sum([ element.reqsec for element in results["shortest-skip"]["libc"]["lighttpd-pmvee-withipmon"] ]) / expected_len
        print("libc_lighttpd_pmvee_ipmon: %.4f" % (libc_lighttpd_pmvee_ipmon/libc_lighttpd_base))
        if len(results["shortest-skip"]["libc"]["lighttpd-pmvee-withipmon"]) != expected_len:
            print("len(results[\"shortest-skip\"][\"libc\"][\"lighttpd-pmvee-withipmon\"]) != expected_len: %d != %d" % (len(results["shortest-skip"]["libc"]["lighttpd-pmvee-withipmon"]), expected_len))
            exit(0)
        
print()


if "shortest-skip" in results and "pmvee" in results["shortest-skip"]:
    if "nginx-full-4-baseline" in results["shortest-skip"]["pmvee"] and \
            "nginx-full-4-pmvee-withipmon" in results["shortest-skip"]["pmvee"] and \
            "nginx-diffed-4-pmvee-withipmon" in results["shortest-skip"]["pmvee"] and \
            "nginx-scan-4-pmvee-withipmon" in results["shortest-skip"]["pmvee"]:
        expected_len = len(results["shortest-skip"]["pmvee"]["nginx-full-4-baseline"])
        nginx_base = sum([ element.reqsec for element in results["shortest-skip"]["pmvee"]["nginx-full-4-baseline"] ]) / expected_len 
        print("baseline nginx: %.4f" % nginx_base)
        
        nginx_pmvee_ipmon = sum([ element.reqsec for element in results["shortest-skip"]["pmvee"]["nginx-full-4-pmvee-withipmon"] ]) / expected_len
        print("regular pmvee with ipmon: %.4f" % (nginx_pmvee_ipmon/nginx_base))
        if len(results["shortest-skip"]["pmvee"]["nginx-full-4-pmvee-withipmon"]) != expected_len:
            print("len(results[\"shortest-skip\"][\"pmvee\"][\"nginx-full-4-pmvee-withipmon\"]) != expected_len: %d != %d" % (len(results["shortest-skip"]["pmvee"]["nginx-full-4-pmvee-withipmon"]), expected_len))
            exit(0)
        
        nginx_base = sum([ element.reqsec for element in results["shortest-skip"]["pmvee"]["nginx-diffed-4-baseline"] ]) / expected_len
        if len(results["shortest-skip"]["pmvee"]["nginx-diffed-4-baseline"]) != expected_len:
            print("len(results[\"shortest-skip\"][\"pmvee\"][\"nginx-diffed-4-baseline\"]) != expected_len: %d != %d" % (len(results["shortest-skip"]["pmvee"]["nginx-diffed-4-baseline"]), expected_len))
            exit(0)
        nginx_pmvee_ipmon = sum([ element.reqsec for element in results["shortest-skip"]["pmvee"]["nginx-diffed-4-pmvee-withipmon"] ]) / expected_len
        print("diffed pmvee with ipmon: %.4f" % (nginx_pmvee_ipmon/nginx_base))
        if len(results["shortest-skip"]["pmvee"]["nginx-diffed-4-pmvee-withipmon"]) != expected_len:
            print("len(results[\"shortest-skip\"][\"pmvee\"][\"nginx-diffed-4-pmvee-withipmon\"]) != expected_len: %d != %d" % (len(results["shortest-skip"]["pmvee"]["nginx-diffed-4-pmvee-withipmon"]), expected_len))
            exit(0)
        
        
        nginx_base = sum([ element.reqsec for element in results["shortest-skip"]["pmvee"]["nginx-scan-4-baseline"] ]) / expected_len
        if len(results["shortest-skip"]["pmvee"]["nginx-scan-4-baseline"]) != expected_len:
            print("len(results[\"shortest-skip\"][\"pmvee\"][\"nginx-scan-4-baseline\"]) != expected_len: %d != %d" % (len(results["shortest-skip"]["pmvee"]["nginx-scan-4-baseline"]), expected_len))
            exit(0)
        nginx_pmvee_ipmon = sum([ element.reqsec for element in results["shortest-skip"]["pmvee"]["nginx-scan-4-pmvee-withipmon"] ]) / expected_len
        print("scanning pmvee with ipmon: %.4f" % (nginx_pmvee_ipmon/nginx_base))
        if len(results["shortest-skip"]["pmvee"]["nginx-scan-4-pmvee-withipmon"]) != expected_len:
            print("len(results[\"shortest-skip\"][\"pmvee\"][\"nginx-scan-4-pmvee-withipmon\"]) != expected_len: %d != %d" % (len(results["shortest-skip"]["pmvee"]["nginx-scan-4-pmvee-withipmon"]), expected_len))
            exit(0)


results_string = f"""\
# Microbenchmarks

## Switching

- getpid:
  - CP-MON: {getpid_CPMON: .2f}us
  - IP-MON: {getpid_IPMON: .2f}us
- toggle MVX:
  - CP-MON: {toggle_MVX_CPMON: .2f}us (+{toggle_MVX_CPMON - getpid_CPMON: .2f} over equivalent getpid)
  - IP-MON: {toggle_MVX_IPMON: .2f}us (+{toggle_MVX_IPMON - getpid_IPMON: .2f} over equivalent getpid)
- fork: 
 - native:          {fork_native: .2f}us
 - CP-MON estimate: {fork_CPMON_estimate: .2f}us
 - IP-mON estimate: {fork_IPMON_estimate: .2f}us
- clone:
 - native:          {clone_native: .2f}us
 - CP-MON estimate: {clone_CPMON_estimate: .2f}us
 - IP-mON estimate: {clone_IPMON_estimate: .2f}us

## Mapping Count

### Lower Bound

![Mapping count micro benchmark - lower bound]({mapping_lower_path})

{mapping_lower_table}

### Upper Bound

![Mapping count micro benchmark - upper bound]({mapping_upper_path})

{mapping_upper_table}


## Migration

![Migration overhead]({migration_path})

{migration_table}

# Server Benchmarks

nginx C1: enter when `ngx_http_process_request_line` is called, exit when it returns
nginx C2: enter when `ngx_http_process_request_line` is called, exit when `ngx_http_handler` is called

lighttpd C1: enter when `connection_handle_read_state` is called, exit when it returns
lighttpd C1: enter when `http_request_headers_process` is called, exit when it returns

## server Latency

![Server latency graph]({latency_path})

- nginx
  - C1:
    - native:              {nginx_C1_latency_native: .2f}us
    - ReMon:               {nginx_C1_latency_ReMon: .2f}us
    - FORTDIVIDE:          {nginx_C1_latency_FORTDIVIDE: .2f}us
    - ReMon + IP-MON:      {nginx_C1_latency_ReMon_IPMON: .2f}us
    - FORTDIVIDE + IP-MON: {nginx_C1_latency_FORTDIVIDE_IPMON: .2f}us
  - C2:
    - native:              {nginx_C2_latency_native: .2f}us
    - ReMon:               {nginx_C2_latency_ReMon: .2f}us
    - FORTDIVIDE:          {nginx_C2_latency_FORTDIVIDE: .2f}us
    - ReMon + IP-MON:      {nginx_C2_latency_ReMon_IPMON: .2f}us
    - FORTDIVIDE + IP-MON: {nginx_C2_latency_FORTDIVIDE_IPMON: .2f}us
- lighttpd
  - C1:
    - native:              {lighttpd_C1_latency_native: .2f}us
    - ReMon:               {lighttpd_C1_latency_ReMon: .2f}us
    - FORTDIVIDE:          {lighttpd_C1_latency_FORTDIVIDE: .2f}us
    - ReMon + IP-MON:      {lighttpd_C1_latency_ReMon_IPMON: .2f}us
    - FORTDIVIDE + IP-MON: {lighttpd_C1_latency_FORTDIVIDE_IPMON: .2f}us
  - C2:
    - native:              {lighttpd_C2_latency_native: .2f}us
    - ReMon:               {lighttpd_C2_latency_ReMon: .2f}us
    - FORTDIVIDE:          {lighttpd_C2_latency_FORTDIVIDE: .2f}us
    - ReMon + IP-MON:      {lighttpd_C2_latency_ReMon_IPMON: .2f}us
    - FORTDIVIDE + IP-MON: {lighttpd_C2_latency_FORTDIVIDE_IPMON: .2f}us

## server Overhead

![Relative server overhead graph]({overhead_path})

- nginx
  - C1:
    - native:              - % ({nginx_C1_overhead_native: .2f} requests/sec)
    - ReMon:               {100 * (nginx_C1_overhead_ReMon / nginx_C1_overhead_native): .2f} % ({nginx_C1_overhead_ReMon: .2f} requests/sec)
    - FORTDIVIDE:          {100 * (nginx_C1_overhead_FORTDIVIDE / nginx_C1_overhead_native): .2f} % ({nginx_C1_overhead_FORTDIVIDE: .2f} requests/sec)
    - ReMon + IP-MON:      {100 * (nginx_C1_overhead_ReMon_IPMON / nginx_C1_overhead_native): .2f} % ({nginx_C1_overhead_ReMon_IPMON: .2f} requests/sec)
    - FORTDIVIDE + IP-MON: {100 * (nginx_C1_overhead_FORTDIVIDE_IPMON / nginx_C1_overhead_native): .2f} % ({nginx_C1_overhead_FORTDIVIDE_IPMON: .2f} requests/sec)
  - C2:
    - native:                -  % ({nginx_C2_overhead_native: .2f} requests/sec)
    - ReMon:               {100 * (nginx_C2_overhead_ReMon / nginx_C2_overhead_native): .2f} % ({nginx_C2_overhead_ReMon: .2f} requests/sec)
    - FORTDIVIDE:          {100 * (nginx_C2_overhead_FORTDIVIDE / nginx_C2_overhead_native): .2f} % ({nginx_C2_overhead_FORTDIVIDE: .2f} requests/sec)
    - ReMon + IP-MON:      {100 * (nginx_C2_overhead_ReMon_IPMON / nginx_C2_overhead_native): .2f} % ({nginx_C2_overhead_ReMon_IPMON: .2f} requests/sec)
    - FORTDIVIDE + IP-MON: {100 * (nginx_C2_overhead_FORTDIVIDE_IPMON / nginx_C2_overhead_native): .2f} % ({nginx_C2_overhead_FORTDIVIDE_IPMON: .2f} requests/sec)
- lighttpd
  - C1:
    - native:                -  % ({lighttpd_C1_overhead_native: .2f} requests/sec)
    - ReMon:               {100 * (lighttpd_C1_overhead_ReMon / lighttpd_C1_overhead_native): .2f} % ({lighttpd_C1_overhead_ReMon: .2f} requests/sec)
    - FORTDIVIDE:          {100 * (lighttpd_C1_overhead_FORTDIVIDE / lighttpd_C1_overhead_native): .2f} % ({lighttpd_C1_overhead_FORTDIVIDE: .2f} requests/sec)
    - ReMon + IP-MON:      {100 * (lighttpd_C1_overhead_ReMon_IPMON / lighttpd_C1_overhead_native): .2f} % ({lighttpd_C1_overhead_ReMon_IPMON: .2f} requests/sec)
    - FORTDIVIDE + IP-MON: {100 * (lighttpd_C1_overhead_FORTDIVIDE_IPMON / lighttpd_C1_overhead_native): .2f} % ({lighttpd_C1_overhead_FORTDIVIDE_IPMON: .2f} requests/sec)
  - C2:
    - native:                -  % ({lighttpd_C2_overhead_native: .2f} requests/sec)
    - ReMon:               {100 * (lighttpd_C2_overhead_ReMon / lighttpd_C2_overhead_native): .2f} % ({lighttpd_C2_overhead_ReMon: .2f} requests/sec)
    - FORTDIVIDE:          {100 * (lighttpd_C2_overhead_FORTDIVIDE / lighttpd_C2_overhead_native): .2f} % ({lighttpd_C2_overhead_FORTDIVIDE: .2f} requests/sec)
    - ReMon + IP-MON:      {100 * (lighttpd_C2_overhead_ReMon_IPMON / lighttpd_C2_overhead_native): .2f} % ({lighttpd_C2_overhead_ReMon_IPMON: .2f} requests/sec)
    - FORTDIVIDE + IP-MON: {100 * (lighttpd_C2_overhead_FORTDIVIDE_IPMON / lighttpd_C2_overhead_native): .2f} % ({lighttpd_C2_overhead_FORTDIVIDE_IPMON: .2f} requests/sec)

## Migration Strategy

- nginx C2:
  - manual migration handlers:                              {100 * (nginx_C2_manual_migration_handlers / nginx_C2_overhead_native): .2f} % ({nginx_C2_manual_migration_handlers: .2f} requests/sec)
  - known globals and manual pointer handlers for the heap: {100 * (nginx_C2_known_globals / nginx_C2_overhead_native): .2f} % ({nginx_C2_known_globals: .2f} requests/sec)
  - known globals and pointer scanning for the heap:        {100 * (nginx_C2_pointer_scanning / nginx_C2_overhead_native): .2f} % ({nginx_C2_pointer_scanning: .2f} requests/sec)

## Allocator Impact

- nginx C2:
  - libc allocator:       {100 * (nginx_C2_libc_allocator / nginx_C2_overhead_native): .2f} % ({nginx_C2_libc_allocator: .2f} requests/sec)
  - FORTDIVIDE allocator: {100 * (nginx_C2_FORTDIVIDE_allocator / nginx_C2_overhead_native): .2f} % ({nginx_C2_FORTDIVIDE_allocator: .2f} requests/sec) 
- lighttpd C2:
  - libc allocator:       {100 * (lighttpd_C2_libc_allocator / lighttpd_C2_overhead_native): .2f} % ({lighttpd_C2_libc_allocator: .2f} requests/sec)
  - FORTDIVIDE allocator: {100 * (lighttpd_C2_FORTDIVIDE_allocator / lighttpd_C2_overhead_native): .2f} % ({lighttpd_C2_FORTDIVIDE_allocator: .2f} requests/sec)
"""


with open("fortdivide-results.md", 'w') as fortdivide_results_file:
    fortdivide_results_file.write(results_string)