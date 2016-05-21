#!/usr/bin/python

import sys
import re

def usage():
	print "Manually inline functions in assembly and inject prologues/epilogues into functions. Rather hacky and error-prone. The name is an UGent-joke on our binary rewriter :-)"
	print "Usage: diablo.py input.s output.s [--inline function_name_to_be_replaced file]* [--inject function_name prologue_file epilogue_file]*"
	sys.exit(-1)


def get_replacements(list):
	result = {}

	for (function_name_to_be_replaced, file_name) in list:
		with open(file_name, 'r') as file:
			content = file.read()
		result[function_name_to_be_replaced] = content

	return result

def inline(input_file, replacements):
	call_pattern = re.compile("\s*call\s*([^@]+)@PLT")

	output = []

	for line in input_file:
		match = call_pattern.match(line)
		if match is not None:
			function = match.group(1)
			if function in replacements:
				# Inline function call
				output.append("# BEGIN INLINED CALL TO %s\n" % function)
				output.append("%s\n" % replacements[function])
				output.append("# END INLINED CALL TO %s\n" % function)
			else:
				# Function call not to be inlined
				output.append("%s" % line)
		else:
			output.append("%s" % line)

	return output

# WARNING: this assumes that this function is relatively 'clean', and that the only ret instructions in it
# belong to that function, and that it doesn't contain multiple 'versions' that could be called into
def inject_prologue_epilogue(input_file, function_name, prologue, epilogue):
	function_start_marker = "%s:\n" % function_name
	function_end_marker = "\t.size\t%s, .-%s\n" % (function_name, function_name)
	return_statement = "\tret\n"

	in_function = False
	output = []

	for line in input_file:
		if line == function_start_marker:
			assert not in_function

			in_function = True

			output.append(line)
			output.append("# BEGIN INJECTED FUNCTION PROLOGUE FOR %s\n" % function_name)
			output.append("%s\n" % prologue)
			output.append("# END INJECTED FUNCTION PROLOGUE FOR %s\n" % function_name)

		elif line == function_end_marker:
			assert in_function
			in_function = False
		elif in_function and line == return_statement:
			output.append("# BEGIN INJECTED FUNCTION EPILOGUE FOR %s\n" % function_name)
			output.append("%s\n" % epilogue)
			output.append("# END INJECTED FUNCTION EPILOGUE FOR %s\n" % function_name)
		else:
			output.append(line)

	return output

if len(sys.argv) < 3:
	usage()

replacement_request = []
inject_requests = []

arg = 3
while arg < len(sys.argv):
	if sys.argv[arg] == "--inline":
		replacement_request.append( (sys.argv[arg+1], sys.argv[arg+2]) )
		arg += 2
	elif sys.argv[arg] == "--inject":
		with open(sys.argv[arg+2], 'r') as prologue_file:
			prologue = prologue_file.read()
		with open(sys.argv[arg+3], 'r') as epilogue_file:
			epilogue = epilogue_file.read()
		inject_requests.append( (sys.argv[arg+1], prologue, epilogue) )
		arg += 3
	else:
		usage()
	arg += 1

replacements = get_replacements(replacement_request)

input_file_lines = []
with open(sys.argv[1], "r") as input_file:
	for line in input_file:
		input_file_lines.append(line)

rewritten = inline(input_file_lines, replacements)

for (function_name, prologue, epilogue) in inject_requests:
	rewritten = inject_prologue_epilogue(rewritten, function_name, prologue, epilogue)

with open(sys.argv[2], "w") as output_file:
	for line in rewritten:
		output_file.write(line)
