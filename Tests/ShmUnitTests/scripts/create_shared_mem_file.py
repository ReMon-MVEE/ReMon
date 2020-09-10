import sys


# main =================================================================================================================
def main():
    print("generating files of size %d bytes" % int(sys.argv[3]))
    with open(sys.argv[1], 'wb') as output_file_opened, open(sys.argv[2], 'wb') as output_sink_file_opened:
        for entry in range(0, int(sys.argv[3])):
            output_file_opened.write(bytearray([((entry % 15) + 1) | (((entry % 15) + 1) << 4)]))
            output_sink_file_opened.write(bytearray([0x00]))

    """txt
    with open(sys.argv[1], 'rb') as output_file_opened, open(sys.argv[2], 'rb') as output_sink_file_opened:
        line = 0
        while True:
            output_1 = output_file_opened.read(1)
            output_2 = output_sink_file_opened.read(1)
            line += 1

            if not output_1 and not output_2:
                break

            print("line %d: %s | %s" % (line,
                    hex(output_1[0]) if output_1[0] >= 0x10 else hex(output_1[0]).replace("0x", "0x0"),
                    hex(output_2[0]) if output_2[0] >= 0x10 else hex(output_2[0]).replace("0x", "0x0")))
    """

    print("test files created")
# main =================================================================================================================


if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("must provide path to output file, path to sink file, and size of files in bytes")
        exit(-1)
    main()
