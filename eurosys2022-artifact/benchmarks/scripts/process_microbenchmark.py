import sys


results = {}
max_size = 0
with open(sys.argv[1], 'r') as input_file:
    while True:
        line = input_file.readline()
        if not line:
            break
        line = line.replace(' ', '').replace('>','').replace("ns", '').split(':')
        if int(line[0]) not in results:
            max_size = max(max_size, int(line[0]))
            results[int(line[0])] = [float(line[1])]
        else:
            results[int(line[0])].append(float(line[1]))

for size in sorted(results):
    print("   > %s: %s(%s)/%d ns" % (size, ' '*(len(str(max_size))-len(str(size))), '+'.join(map(str, results[size])), len(results[size])))
