#include <archive.h>
#include <archive_entry.h>
#include <cstdio>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <iostream>

/* Advanced Reliable Measurement Output Reproduction (ARMOR)
 * 
 * This small library embeds programmer selected files and command outputs
 * into the measurement result csv file, encoded as base64.
 * A user can simply execute the csv file and it extracts itself
 * putting all source files and system config into a subfolder.
 * To reproduce a measurement the extracted files can be compiled and
 * executed.
 * 
 * ARMOR consists of this header file and the Makefile. During
 * making, the source files are archived and the archive linked to 
 * the binary.
 * The Makefile installs libarchive-dev on debian based distributions if
 * it is not installed or prints an error message.
 * 
 * During execution, the function additional_archive_content() adds
 * additional files, like system configuration files and output from
 * commands to the archive.
 * The archive is then base64 encoded and written to the measurement output
 * csv file. The csv read used to open the output file must supported # 
 * for commends inside csv files.
 * The first line contains a shebang to extract the base64 encoded archive
 * to the directory supplied as the first argument or "source".
 * 
 * print_measurement_csv_header() must be called at the beginning of the 
 * program.
 */


void add_file_to_archive(archive *a, const char *path);
void add_command_output_to_archive(archive *a, const char *command, const char *path);
void extend_archive_with_system_config();
std::string get_archive_base64();

void additional_archive_content(archive *wa) {
  add_file_to_archive(wa, "/proc/cmdline");
  add_file_to_archive(wa, "/proc/cpuinfo");
  add_file_to_archive(wa, "/proc/modules");
  add_file_to_archive(wa, "/proc/version");
  add_file_to_archive(wa, "/proc/self/cmdline");

  add_command_output_to_archive(wa, "date", "commands/date");
  add_command_output_to_archive(wa, "uptime", "commands/uptime");
  add_command_output_to_archive(wa, "hostname", "commands/hostname");
  add_command_output_to_archive(wa, "pwd", "commands/pwd");
  add_command_output_to_archive(wa, "uname -r", "commands/uname");

  // other examples:
  //add_command_output_to_archive(wa, "dmesg 2>&1 | tail -c 1MB", "commands/dmesg");
  //add_command_output_to_archive(wa, "cpupower frequency-info", "commands/cpupower");
  //add_command_output_to_archive(wa, "undervolt -r", "commands/undervolt");
}


void print_measurement_csv_header() {
  fprintf(stderr, "#!/usr/bin/env -S bash -c \"if [ -z \"\\$1\" ]; then extract_dir=\"source\"; else extract_dir=\\$1; fi; mkdir \\$extract_dir; cat \\$0 | sed -n 3p | cut -c 3- | base64 -d | tar -xz -C \\$extract_dir -f - ; exit\"\n");
  fprintf(stderr, "# Execute this files to get all sources of the experiment. The optional second parameter is the directory where the files should be extracted to\n");
  
  extend_archive_with_system_config();
  
  std::cerr << "# " << get_archive_base64() << "\n";
}


//////////////////////////////////////////////////////////////////////////////////////


std::string base64_encode(uint8_t const* buf, unsigned int bufLen);

extern const uint8_t _binary_source_tar_gz_start[];
extern const uint8_t _binary_source_tar_gz_end[];

uint8_t *arch_buf = nullptr;
size_t arch_buf_used = 0;


std::string get_archive_base64() {
  if (arch_buf_used == 0) {
    return base64_encode(_binary_source_tar_gz_start, _binary_source_tar_gz_end - _binary_source_tar_gz_start);
  }

  return base64_encode(arch_buf, arch_buf_used);
}

void extend_archive_with_system_config() {
  constexpr size_t arch_buf_size = 1000UL * 1000 * 10;

  archive *ra, *wa;
  archive_entry *re, *we;
  uint8_t buffer[0x1000];
  int r;

  // we will construct the archive in memory, get a buffer for that
  arch_buf = (uint8_t*) malloc(arch_buf_size);

  // read from the embedded archive
  ra = archive_read_new();
  archive_read_support_filter_gzip(ra);
  archive_read_support_format_tar(ra);
  r = archive_read_open_memory(ra, _binary_source_tar_gz_start, _binary_source_tar_gz_end - _binary_source_tar_gz_start);
  if (r != ARCHIVE_OK) {
    printf("%s\n", archive_error_string(ra));
    exit(1);
  }

  // write to new archive
  wa = archive_write_new();
  archive_write_add_filter_gzip(wa);
  archive_write_set_format_gnutar(wa);
  r = archive_write_open_memory(wa, arch_buf, arch_buf_size, &arch_buf_used);
  if (r != ARCHIVE_OK) {
    printf("%s\n", archive_error_string(wa));
    exit(1);
  }

  // copy the archive
  while (archive_read_next_header(ra, &re) == ARCHIVE_OK) {
    we = archive_entry_clone(re);

    archive_write_header(wa, we);
    do {
      r = archive_read_data(ra, buffer, sizeof(buffer));
      if (r < 0) {
        printf("%s\n", archive_error_string(ra));
        exit(1);
      }
      if (r > 0) {
        archive_write_data(wa, buffer, r);
      }
    } while (r > 0);

    archive_write_finish_entry(wa);
    archive_entry_free(we);
  }

  // add new entries to archive containing the system information
  additional_archive_content(wa);

  r = archive_write_close(wa);
  if (r != ARCHIVE_OK)
    exit(1);

  r = archive_write_free(wa);
  if (r != ARCHIVE_OK)
    exit(1);

  r = archive_read_free(ra);
  if (r != ARCHIVE_OK)
    exit(1);
}


void add_file_to_archive(archive *a, const char *path) {
  uint8_t buffer[0x1000];
  size_t len, filesize = 0;
  int r;

  int fd = open(path, O_RDONLY);
  if (fd == -1) {
    printf("open %s failed %s\n", path, strerror(errno));
    exit(1);
  }

  archive_entry *entry = archive_entry_new();
  archive *ard = archive_read_disk_new();
  archive_read_disk_set_standard_lookup(ard);

  if (path[0] == '/')
    path = path + 1;

  archive_entry_copy_pathname(entry, path);
  r = archive_read_disk_entry_from_file(ard, entry, fd, NULL);
  if (r != ARCHIVE_OK) {
    printf("%s\n", archive_error_string(ard));
    exit(1);
  }

  // if it is a proc file read everything in a buffer to get the size
  if (archive_entry_size(entry) == 0) {
    size_t filebufsize = 1UL * 1024 * 1024;
    uint8_t *filebuf = (uint8_t*) malloc(filebufsize);
    filesize = 0;
    while ((len	= read(fd, filebuf + filesize, filebufsize - filesize))	> 0) {
      filesize += len;
    }
    archive_entry_set_size(entry, filesize);
    archive_write_header(a, entry);
    archive_write_data(a, filebuf, filesize);
    archive_write_finish_entry(a);

    free(filebuf);
  }
  else {
    archive_write_header(a, entry);
    while ((len	= read(fd, buffer, sizeof(buffer)))	> 0) {
      archive_write_data(a, buffer, len);
      filesize += len;
    }
    archive_write_finish_entry(a);
  }

  close(fd);
	archive_read_free(ard);
  archive_entry_free(entry);
}



void add_command_output_to_archive(archive *a, const char *command, const char *path) {
  int ret;
  size_t len = 0;
  archive_entry *entry = archive_entry_new();

  archive_entry_set_pathname(entry, path);
  archive_entry_set_filetype(entry, AE_IFREG);
  archive_entry_set_perm(entry, 0644);

  size_t outputbufsize = 1UL * 1024 * 1024 + 100;
  char *outputbuf = (char*) malloc(outputbufsize);

  std::string full_command = command;
  full_command += " 2>&1";

  FILE *fp = popen(full_command.c_str(), "r");
  if (fp == NULL) {
    printf("popen %s failed: %d %s\n", full_command.c_str(), errno, strerror(errno));
  }

  memset(outputbuf, 0, outputbufsize);

  while (fgets(outputbuf + len, outputbufsize - len, fp) != NULL) {
    len = strlen(outputbuf);
  }
  outputbufsize = strlen(outputbuf);

  archive_entry_set_size(entry, outputbufsize);

  archive_write_header(a, entry);
  archive_write_data(a, outputbuf, outputbufsize);
  archive_write_finish_entry(a);
  
  ret = pclose(fp);
  if (ret == -1) {
    printf("pclose %s failed: %d %s\n", full_command.c_str(), errno, strerror(errno));
    exit(1);
  }
  if (ret != 0) {
    printf("%s returned a failure code: %d\n", full_command.c_str(), ret);
    printf("command output:\n%s", outputbuf);
    exit(1);
  }

  free(outputbuf);

  archive_entry_free(entry);
}



// only used for debugging
void dump_files() {
  archive *a;
  archive_entry *entry;
  int r;
  uint8_t buffer[0x1000];

  a = archive_read_new();
  archive_read_support_filter_gzip(a);
  archive_read_support_format_tar(a);
  r = archive_read_open_memory(a, _binary_source_tar_gz_start, _binary_source_tar_gz_end - _binary_source_tar_gz_start);

  if (r != ARCHIVE_OK) {
    printf("%s\n", archive_error_string(a));
    exit(1);
  }

  while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
    printf("%ls\n", archive_entry_pathname_w(entry));
    //archive_read_data_skip(a);  // Note 2
    do {
      memset(buffer, 0, sizeof(buffer));
      r = archive_read_data(a, buffer, sizeof(buffer));
      if (r < 0) {
        printf("%s\n", archive_error_string(a));
        exit(1);
      }
      if (r > 0) {
        printf("%s", buffer);
      }
    } while (r > 0);

    printf("\n\n");
  }
  r = archive_read_free(a);  // Note 3
  if (r != ARCHIVE_OK)
    exit(1);
}


static const std::string base64_chars =
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";


static inline bool is_base64(uint8_t c) {
  return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string base64_encode(uint8_t const* buf, unsigned int bufLen) {
  std::string ret;
  int i = 0;
  int j = 0;
  uint8_t char_array_3[3];
  uint8_t char_array_4[4];

  while (bufLen--) {
    char_array_3[i++] = *(buf++);
    if (i == 3) {
      char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
      char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
      char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
      char_array_4[3] = char_array_3[2] & 0x3f;

      for(i = 0; (i <4) ; i++)
        ret += base64_chars[char_array_4[i]];
      i = 0;
    }
  }

  if (i)
  {
    for(j = i; j < 3; j++)
      char_array_3[j] = '\0';

    char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
    char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
    char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
    char_array_4[3] = char_array_3[2] & 0x3f;

    for (j = 0; (j < i + 1); j++)
      ret += base64_chars[char_array_4[j]];

    while((i++ < 3))
      ret += '=';
  }

  return ret;
}
