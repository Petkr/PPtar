#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static bool options_has_free_arguments(const options_t* options)
{
	return options->free_arguments_count != 0;
}

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

static options_t parse_arguments(size_t argc, char* const* argv)
{
	options_t options = parse_arguments_helper(argc, argv);

	if (options.error_code != 0)
		free(options.free_arguments);

	return options;
}

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

#define RECORD_SIZE ((size_t)512)

#define TMAGIC "ustar"
#define TMAGICS "ustar "

/* Values used in typeflag field.  */
#define REGTYPE '0'	  /* regular file */
#define AREGTYPE '\0' /* regular file */
#define LNKTYPE '1'	  /* link */
#define SYMTYPE '2'	  /* reserved */
#define CHRTYPE '3'	  /* character special */
#define BLKTYPE '4'	  /* block special */
#define DIRTYPE '5'	  /* directory */
#define FIFOTYPE '6'  /* FIFO special */
#define CONTTYPE '7'  /* reserved */

typedef enum read_header_status
{
	READ_HEADER_EOF,
	READ_HEADER_PARTIAL,
	READ_HEADER_FULL
} read_header_status_t;

static read_header_status_t read_header(FILE* file, header_t* header)
{
	size_t read_count = fread(header, sizeof(char), sizeof(header_t), file);

	return read_count == sizeof(header_t) ? READ_HEADER_FULL
		   : read_count == 0			  ? READ_HEADER_EOF
										  : READ_HEADER_PARTIAL;
}

static bool header_is_magic_valid(const header_t* header)
{
	const size_t magic_size = sizeof(header->magic);

	return strncmp(header->magic, TMAGIC, magic_size) == 0 ||
		   strncmp(header->magic, TMAGICS, magic_size) == 0;
}

static bool header_is_regular_file(const header_t* header)
{
	return header->typeflag == REGTYPE || header->typeflag == AREGTYPE;
}

static bool header_is_null(const header_t* header)
{
	for (const char* i = (char*)header; i != (char*)(header + 1); ++i)
		if (*i != 0)
			return false;

	return true;
}

static size_t header_get_size(const header_t* header)
{
	return (size_t)strtoull(header->size, NULL, 8);
}

static size_t size_to_record_count(size_t x)
{
	return (x + RECORD_SIZE - 1) / RECORD_SIZE;
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

	FILE* file = fopen(options.f_argument, "rb");

	if (!file)
	{
		fprintf(stderr, "mytar: could not open file %s\n", options.f_argument);
		free(options.free_arguments);
		return 2;
	}

	bool header_was_null = false;

	bool has_free_arguments = options_has_free_arguments(&options);

	bool* free_arguments_found =
		malloc(sizeof(bool) * options.free_arguments_count);

	for (bool* i = free_arguments_found;
		 i != free_arguments_found + options.free_arguments_count;
		 ++i)
		*i = false;

	size_t block_index = 0;

	while (true)
	{
		FILE* file_output = NULL;

		header_t header;

		read_header_status_t read_header_status = read_header(file, &header);

		switch (read_header_status)
		{
			case READ_HEADER_EOF:
				if (header_was_null)
				{
					printf("mytar: A lone zero block at %zu\n", block_index);
				}
				fclose(file);
				if (file_output)
					fclose(file_output);
				free(free_arguments_found);
				free(options.free_arguments);
				return 0;
			case READ_HEADER_PARTIAL:
				printf("mytar: Unexpected EOF in archive\n"
					   "mytar: Error is not recoverable: exiting now\n");
				fclose(file);
				if (file_output)
					fclose(file_output);
				free(free_arguments_found);
				free(options.free_arguments);
				return 2;
			default:
				++block_index;
				break;
		}

		if (header_is_null(&header))
		{
			if (header_was_null)
				break;
			else
			{
				header_was_null = true;
				continue;
			}
		}

		if (!header_is_magic_valid(&header))
		{
			fprintf(
				stderr,
				"mytar: This does not look like a tar archive\n"
				"mytar: Exiting with failure status due to previous errors\n");

			fclose(file);
			if (file_output)
				fclose(file_output);
			free(free_arguments_found);
			free(options.free_arguments);
			return 2;
		}

		if (!header_is_regular_file(&header))
		{
			fprintf(stderr,
					"mytar: Unsupported header type: %d\n",
					(int)header.typeflag);

			fclose(file);
			if (file_output)
				fclose(file_output);
			free(free_arguments_found);
			free(options.free_arguments);
			return 2;
		}

		bool consider_this_file = false;

		if (!has_free_arguments ||
			options_find_free_argument(&options,
									   header.name,
									   free_arguments_found))
		{
			if (options.t || (options.x && options.v))
				printf("%.*s\n", (int)sizeof(header.name), header.name);
			consider_this_file = true;
		}

		if (options.x && consider_this_file)
		{
			file_output = fopen(header.name, "wb");
			if (!file_output)
			{
				fclose(file);
				free(free_arguments_found);
				free(options.free_arguments);

				return 69;
			}
		}

		size_t size = header_get_size(&header);
		size_t size512 = size_to_record_count(size);

		char buffer[RECORD_SIZE];

		for (size_t i = 0; i != size512; ++i)
		{
			size_t read = fread(buffer, 1, RECORD_SIZE, file);

			if (options.x && consider_this_file)
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
				printf("mytar: Unexpected EOF in archive\n"
					   "mytar: Error is not recoverable: exiting now\n");

				fclose(file);
				if (file_output)
					fclose(file_output);
				free(free_arguments_found);
				free(options.free_arguments);

				return 2;
			}

			++block_index;
		}

		if (options.x && consider_this_file)
		{
			fclose(file_output);
		}
	}

	if (options.t && has_free_arguments)
	{
		bool some_was_not_found = false;

		const char** free_argument_i = options.free_arguments;

		for (bool* i = free_arguments_found; *free_argument_i != NULL;
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

			fclose(file);
			free(free_arguments_found);
			free(options.free_arguments);
			return 2;
		}
	}

	fclose(file);
	free(free_arguments_found);
	free(options.free_arguments);

	return 0;
}
