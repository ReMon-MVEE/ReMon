#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

int main(int argc, char** argv)
{
  if (argc < 2)
    {
      printf("syntax: %s <atomic hdr>\n", argv[0]);
      return -1;
    }

  printf("Parsing header: %s\n", argv[1]);
  FILE* in = fopen(argv[1], "rb");
  if (!in)
    {
      printf("couldn't open file.\n");
      return -1;      
    }

  char* str = (char*)malloc(strlen(argv[1]) + 5);
  sprintf(str, "%s.new", argv[1]);

  printf("Writing to file: %s\n", str);
  FILE* out = fopen(str, "wb+");
  if (!out)
    {
      printf("couldn't open file.\n");
      return -1;
    }
  free(str);

  char* lineptr = NULL;
  size_t linesz = 0;

  while(getline(&lineptr, &linesz, in) != -1)
    {
      if (!strstr(lineptr, "#define"))
	{
	  fprintf(out, "%s", lineptr);
	}
      else
	{
	  char* atomic_name = NULL;
	  char* atomic_args = NULL;
	  char* tmplineptr = lineptr;
	 
	  while (*lineptr != ' ')
	    lineptr++;
	  lineptr++;

	  if (lineptr[strlen(lineptr)-1] == 10)
	    lineptr[strlen(lineptr)-1] = 0;

	  for (int i = 0; i < strlen(lineptr); ++i)
	    {
	      if (lineptr[i] == '(')
		{
		  lineptr[i] = '\0';
		  atomic_name = strdup(lineptr);
		  lineptr[i] = '(';
		  atomic_args = strdup(lineptr+i);
		}
	    }

	  if (atomic_name)
	    {
	      printf("atomic macro: %s -- args: %s\n", atomic_name, atomic_args);

	      fprintf(out, "#define %s%s \\\n", atomic_name, atomic_args);
	      fprintf(out, "({\\\n");
	      fprintf(out, "typeof(*mem) ____result; \\\n");
	      fprintf(out, "if (!mvee_should_sync())\\\n");
	      fprintf(out, "____result = orig_%s%s; \\\n", atomic_name, atomic_args);
	      fprintf(out, "else\\\n");
	      fprintf(out, "{\\\n");
	      fprintf(out, "mvee_check_buffer();\\\n");
	      fprintf(out, "if (mvee_master_variant)\\\n");
	      fprintf(out, "{\\\n");
	      fprintf(out, "mvee_write_lock_result_prepare();\\\n");
	      fprintf(out, "____result = orig_%s%s;\\\n", atomic_name, atomic_args);

	      char* upper = strdup(atomic_name);
	      for (int i = 0; i < strlen(atomic_name); ++i)
		upper[i] = toupper(upper[i]);
	      fprintf(out, "MVEE_WRITE_LOCK_RESULT_WRITE(%s, NULL, 0);\\\n", upper);
	      fprintf(out, "mvee_write_lock_result_adjust_pos();\\\n");
	      fprintf(out, "mvee_write_lock_result_finish();\\\n");
	      fprintf(out, "}\\\n");
	      fprintf(out, "else\\\n");
	      fprintf(out, "{\\\n");
	      fprintf(out, "MVEE_READ_LOCK_RESULT_WAIT(%s, NULL);\\\n", upper);
	      free(upper);
	      fprintf(out, "____result = orig_%s%s;\\\n", atomic_name, atomic_args);
	      fprintf(out, "mvee_read_lock_result_wake();\\\n");
	      fprintf(out, "}\\\n");
	      fprintf(out, "}\\\n");
	      fprintf(out, "____result;\\\n");
	      fprintf(out, "})\n\n\n");
	    }

	  lineptr = tmplineptr;
	}


      free(lineptr);
      lineptr = NULL;
      linesz = 0;
    }

  return 0;
}
