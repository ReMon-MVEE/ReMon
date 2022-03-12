import sys

latencies=[]
requests=[]
with open(sys.argv[1], 'r') as input_file:
    while True:
        line = input_file.readline()
        if not line:
            break
        if "Latency" in line:
            average = line.replace("Latency", '').replace(' ', '').split("s")[0]
            if average[-1] == "u":
                latencies.append(float(average[:-1]))
            elif average[-1] == "m":
                latencies.append(1000*float(average[:-1]))
            else:
                print(" something went wrong: %s" % average)
                exit(-1)
        elif "Requests/sec" in line:
            requests.append(float(line.replace(' ', '').split(':')[1]))

print("   > average latency:    %f us"           % (sum(latencies)/len(latencies)))
print("   > average throughput: %f requests/sec" % (sum(requests)/len(requests)))