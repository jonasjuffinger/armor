# Advanced Reliable Measurement Output Reproduction (ARMOR)

This small library embeds programmer selected files and command outputs
into the measurement result csv file, encoded as base64.
A user can simply execute the csv file and it extracts itself
putting all source files and system config into a subfolder.
To reproduce a measurement the extracted files can be compiled and
executed.

ARMOR consists of the `armor.h` file and the `Makefile`. During
making, the source files are archived and the archive linked to 
the binary.

During execution, the function `additional_archive_content()` adds
additional files, like system configuration files and output from
commands to the archive.
The archive is then base64 encoded and written to the measurement output
csv file. The csv read used to open the output file must supported # 
for commends inside csv files.
The first line contains a shebang to extract the base64 encoded archive
to the directory supplied as the first argument or "source".

`print_measurement_csv_header()` must be called at the beginning of the 
program.
To test the supplied 1_experiment pipe the stderr output to a csv file
`./main 2> measurement.csv`

Requirements:
`libarchive-dev`
