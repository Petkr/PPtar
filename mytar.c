#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/** Structure containing command line options and arguments.
 * Handles:
 *  -f <arg>
 *  -t
 *  -x
 *  -v
 *  free arguments
 */
typedef struct options
{
	bool f;
	const char* f_argument;
	bool t;
	bool x;
	bool v;

	const char** free_arguments;
	size_t free_arguments_count;

	int error_code;
} options_t;

/** Creates a default options_t with capacity for free arguments of
 * 'free_arguments_capacity'.
 */
static options_t options_default(size_t free_arguments_capacity)
{
	options_t options;

	options.error_code = 0;

	options.f = false;
	options.t = false;
	options.x = false;
	options.v = false;

	options.f_argument = NULL;

	options.free_arguments =
		malloc(sizeof(const char*) * (free_arguments_capacity + 1));
	options.free_arguments_count = 0;

	return options;
}

/** Checks if 'options' contains any free arguments. */
static bool options_has_free_arguments(const options_t* options)
{
	return options->free_arguments_count != 0;
}

/** Checks if 'options' contains a free argument equal to 'str' and marks it in
 * the 'free_arguments_found' array.
 */
static bool options_find_free_argument(const options_t* options,
									   const char* str,
									   bool* free_arguments_found)
{
	for (const char** i = options->free_arguments; *i != NULL;
		 ++i, ++free_arguments_found)
	{
		if (!*free_arguments_found && strcmp(*i, str) == 0)
		{
			*free_arguments_found = true;
			return true;
		}
	}
	return false;
}

static options_t parse_arguments_helper(size_t argc, char* const* argv)
{
	options_t options = options_default(argc);

	bool was_f = false;

	const char** free_argument_i = options.free_arguments;

	for (char* const* arg_i = argv + 1; *arg_i != NULL; ++arg_i)
	{
		const char* arg = *arg_i;

		size_t argument_length = strlen(arg);

		if (argument_length == 0)
		{
			fprintf(stderr, "mytar: there was an empty string argument\n");
			options.error_code = 2;
			return options;
		}

		if (was_f)
		{
			options.f_argument = arg;
			was_f = false;
		}
		else if (arg[0] == '-')
		{
			was_f = false;

			if (argument_length != 2)
			{
				fprintf(stderr, "mytar: invalid option format %s\n", arg);
				options.error_code = 3;
				return options;
			}

			char option = arg[1];

			switch (option)
			{
				case 'f':
					options.f = true;
					was_f = true;
					break;
				case 't':
					options.t = true;
					break;
				case 'x':
					options.x = true;
					break;
				case 'v':
					options.v = true;
					break;
				default:
					fprintf(stderr, "mytar: invalid option '%c'\n", option);
					options.error_code = 2;
					return options;
			}
		}
		else
		{
			*free_argument_i = *arg_i;
			++free_argument_i;
			++options.free_arguments_count;
		}
	}

	*free_argument_i = NULL;

	if (options.f && !options.f_argument)
	{
		fprintf(stderr, "mytar: option -f requires an argument\n");
		options.error_code = 5;
		return options;
	}

	if (!options.f)
	{
		fprintf(stderr, "mytar: no -f option\n");
		options.error_code = 2;
		return options;
	}

	if (options.x && options.t)
	{
		fprintf(stderr, "mytar: cannot specify -t and -x at once\n");
		options.error_code = 7;
		return options;
	}

	if (!options.x && !options.t)
	{
		fprintf(stderr, "mytar: must specify at least on of -tx\n");
		options.error_code = 8;
		return options;
	}

	return options;
}

/** Parses the command line for options. */
static options_t parse_arguments(size_t argc, char* const* argv)
{
	options_t options = parse_arguments_helper(argc, argv);

	if (options.error_code != 0)
		free(options.free_arguments);

	return options;
}

/** Structure representing a tar header block. */
typedef struct header
{
	char name[100];
	char mode[8];
	char uid[8];
	char gid[8];
	char size[12];
	char mtime[12];
	char chksum[8];
	char typeflag;
	char linkname[100];
	char magic[6];
	char version[2];
	char uname[32];
	char gname[32];
	char devmajor[8];
	char devminor[8];
	char prefix[155];

	char padding[12];
} header_t;

/** Size of one record in a tarball. */
#define RECORD_SIZE ((size_t)512)

/** Possible magic values in header block. */
#define TMAGIC "ustar"
#define TMAGICS "ustar "

/** Values used in typeflag field. */
#define REGTYPE '0'
#define AREGTYPE '\0'

typedef enum read_header_status
{
	READ_HEADER_EOF,
	READ_HEADER_PARTIAL,
	READ_HEADER_FULL
} read_header_status_t;

/** Attempts to read one header block from 'file'.
 * @return Success code.
 * @retval READ_HEADER_EOF - EOF (0 bytes left to read)
 * @retval READ_HEADER_PARTIAL - partial read (truncated file)
 * @retval READ_HEADER_FULL - read the full size of a header block
 */
static read_header_status_t read_header(FILE* file, header_t* header)
{
	size_t read_count = fread(header, sizeof(char), sizeof(header_t), file);

	return read_count == sizeof(header_t) ? READ_HEADER_FULL
		   : read_count == 0			  ? READ_HEADER_EOF
										  : READ_HEADER_PARTIAL;
}

/** Checks if 'header' contains the right magic value. */
static bool header_is_magic_valid(const header_t* header)
{
	const size_t magic_size = sizeof(header->magic);

	return strncmp(header->magic, TMAGIC, magic_size) == 0 ||
		   strncmp(header->magic, TMAGICS, magic_size) == 0;
}

/** Checks if 'header' corresponds to a regular file */
static bool header_is_regular_file(const header_t* header)
{
	return header->typeflag == REGTYPE || header->typeflag == AREGTYPE;
}

/** Checks validity of 'header' and prints an error message. */
static int header_check_valid(const header_t* header)
{
	if (!header_is_magic_valid(header))
	{
		fprintf(stderr,
				"mytar: This does not look like a tar archive\n"
				"mytar: Exiting with failure status due to previous errors\n");

		return 2;
	}
	else if (!header_is_regular_file(header))
	{
		fprintf(stderr,
				"mytar: Unsupported header type: %d\n",
				(int)header->typeflag);

		return 2;
	}

	return 0;
}

/** Checks if 'header' is a null block. */
static bool header_is_null(const header_t* header)
{
	for (const char* i = (char*)header; i != (char*)(header + 1); ++i)
		if (*i != 0)
			return false;

	return true;
}

/** Gets the size field from 'header'. */
static size_t header_get_size(const header_t* header)
{
	return (size_t)strtoull(header->size, NULL, 8);
}

/** Returns the number of records a file of size 'x' occupies. */
static size_t size_to_record_count(size_t x)
{
	return (x + RECORD_SIZE - 1) / RECORD_SIZE;
}

/** Prints errors about files from free arguments. */
static int check_files(const options_t* options,
					   const bool* free_arguments_found)
{
	bool some_was_not_found = false;

	const char** free_argument_i = options->free_arguments;

	for (const bool* i = free_arguments_found; *free_argument_i != NULL;
		 ++i, ++free_argument_i)
	{
		if (!*i)
		{
			printf("mytar: %s: Not found in archive\n",
				   *free_argument_i); // should print to stderr
			some_was_not_found = true;
		}
	}

	if (some_was_not_found)
	{
		printf("mytar: Exiting with failure status due to previous "
			   "errors\n"); // should print to stderr

		return 2;
	}

	return 0;
}

/** Allocates and initializes an array of bools indicating whether a file from
 * free arguments was found
 */
static bool* make_files_found(const options_t* options)
{
	bool* files_found = malloc(sizeof(bool) * options->free_arguments_count);

	for (bool* i = files_found;
		 i != files_found + options->free_arguments_count;
		 ++i)
		*i = false;

	return files_found;
}

/** Checks if the file corresponding to 'header' is to be considered.
 * Writes to 'files_found' the result of this search.
 */
static bool check_file_filter(const options_t* options,
							  const header_t* header,
							  bool* files_found)
{
	if (!options_has_free_arguments(options) ||
		options_find_free_argument(options, header->name, files_found))
	{
		if (options->t || (options->x && options->v))
			printf("%.*s\n", (int)sizeof(header->name), header->name);
		return true;
	}

	return false;
}

/** Tries to open the file from the argument of the -f option. */
static FILE* try_open_tarball(const options_t* options)
{
	FILE* file = fopen(options->f_argument, "rb");

	if (!file)
	{
		fprintf(stderr, "mytar: could not open file %s\n", options->f_argument);
		free(options->free_arguments);
	}

	return file;
}

int main(int argc, char* argv[])
{
	if (argc == 0)
	{
		fprintf(stderr, "mytar: argc was 0\n");
		return 1;
	}

	options_t options = parse_arguments((size_t)(argc - 1), argv);

	if (options.error_code != 0)
		return options.error_code;

	FILE* file = try_open_tarball(&options);
	if (!file)
		return 2;

	int return_code = 0;

	// Keeps track of blocks read.
	size_t block_index = 0;

	// If the last read block was a null block
	bool was_null_block = false;

	// Pointer to the current file being extracted or NULL
	FILE* file_output = NULL;

	bool* files_found = make_files_found(&options);

	while (true)
	{
		header_t header;

		read_header_status_t read_header_status = read_header(file, &header);

		if (read_header_status == READ_HEADER_EOF)
		{
			if (was_null_block)
				printf("mytar: A lone zero block at %zu\n", block_index);

			return_code = 0;
			break;
		}
		else if (read_header_status == READ_HEADER_PARTIAL)
		{
			printf("mytar: Unexpected EOF in archive\n"
				   "mytar: Error is not recoverable: exiting now\n");

			return_code = 2;
			break;
		}

		++block_index;

		if (header_is_null(&header))
		{
			if (was_null_block)
			{
				return_code = 0;
				break;
			}
			else
			{
				was_null_block = true;
				continue;
			}
		}

		if ((return_code = header_check_valid(&header)) != 0)
			break;

		if (check_file_filter(&options, &header, files_found) && options.x)
		{
			file_output = fopen(header.name, "wb");
			if (!file_output)
			{
				fprintf(stderr,
						"mytar: Couldn't create file %s\n",
						header.name);

				return_code = 9;
				break;
			}
		}

		size_t size = header_get_size(&header);
		size_t record_count = size_to_record_count(size);

		char buffer[RECORD_SIZE];

		for (size_t i = 0; i != record_count; ++i)
		{
			size_t read = fread(buffer, 1, RECORD_SIZE, file);

			if (file_output != NULL)
			{
				fwrite(buffer,
					   1,
					   read < RECORD_SIZE	 ? read
					   : size >= RECORD_SIZE ? RECORD_SIZE
											 : size,
					   file_output);
			}

			size -= read;

			if (read != RECORD_SIZE)
			{
				printf(
					"mytar: Unexpected EOF in archive\n"
					"mytar: Error is not recoverable: exiting now\n"); // should
																	   // print
																	   // to
																	   // stderr

				return_code = 2;
				break;
			}

			++block_index;
		}

		if (return_code != 0)
			break;

		if (file_output != NULL)
		{
			fclose(file_output);
			file_output = NULL;
		}
	}

	if (options.t && options_has_free_arguments(&options))
		return_code = check_files(&options, files_found);

	fclose(file);
	if (file_output)
		fclose(file_output);
	free(files_found);
	free(options.free_arguments);

	return return_code;
}
