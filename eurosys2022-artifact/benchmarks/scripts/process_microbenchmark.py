import sys


results={}
with open(sys.argv[1], 'r') as input_file:
    while True:
        line = input_file.readline()
        if not line:
            break
        line = line.replace(' ', '').replace('>','').replace("ns", '').split(':')
        if line[0] not in results:
            results[int(line[0])] = float(line[1])
        else:
            results[int(line[0])] += float(line[1])

for size in sorted(results):
    print("   > %s: %f ns" % (size, results[size]/10.0))
