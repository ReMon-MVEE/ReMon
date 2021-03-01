import sys


def get_byte(string):
    return string.split("(")[1].split(")")[0]


if len(sys.argv) != 3:
    print("wrong number of arguments passed")
    exit(-1)

shm_table = {}

with open(sys.argv[1], 'r') as input_file:
    while True:
        line = input_file.readline()
        if not line:
            break
        if "#define" in line:
            continue

        if "BYTE_LOADER_DEFINITION" in line:
            byte = line.split("(")[1].split(")")[0]
            if byte not in shm_table:
                shm_table[byte] = ["&block_loader", "&block_emulator"]
            if "//" not in line:
                shm_table[byte][0] = "&BYTE_LOADER_NAME(%s)" % byte
        elif "BYTE_EMULATOR_DEFINITION" in line:
            byte = line.split("(")[1].split(")")[0]
            if byte not in shm_table:
                shm_table[byte] = ["&block_loader", "&block_emulator", "&block_check"]
            if "//" not in line:
                shm_table[byte][1] = "&BYTE_EMULATOR_NAME(%s)" % byte

with open(sys.argv[2], 'w') as output_file:
    output_file.write("#include \"shared_memory_emulation.h\"\n"
                      "// -----------------------------------------------------------------------------------------------------------------\n"
                      "//      lookup table\n"
                      "// -----------------------------------------------------------------------------------------------------------------\n"
                      "\n"
                      "constexpr const emulation_lookup instruction_intent_emulation::lookup_table[256] =\n"
                      "{\n")
    sorted_bytes = [byte for byte in shm_table]
    sorted_bytes.sort()
    for byte in sorted_bytes:
        output_file.write("\t{  /* %s */\n" % byte)
        for entry in shm_table[byte]:
            output_file.write("\t\t%s,\n" % entry)
        output_file.write("\t}, /* %s */\n" % byte)

    output_file.write(""
                      "};"
                      "")
