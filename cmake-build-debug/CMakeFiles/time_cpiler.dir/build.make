# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /mnt/c/Users/limberg/hal-qos

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /mnt/c/Users/limberg/hal-qos/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/time_cpiler.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/time_cpiler.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/time_cpiler.dir/flags.make

CMakeFiles/time_cpiler.dir/time_test.c.o: CMakeFiles/time_cpiler.dir/flags.make
CMakeFiles/time_cpiler.dir/time_test.c.o: ../time_test.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/c/Users/limberg/hal-qos/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/time_cpiler.dir/time_test.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/time_cpiler.dir/time_test.c.o   -c /mnt/c/Users/limberg/hal-qos/time_test.c

CMakeFiles/time_cpiler.dir/time_test.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/time_cpiler.dir/time_test.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /mnt/c/Users/limberg/hal-qos/time_test.c > CMakeFiles/time_cpiler.dir/time_test.c.i

CMakeFiles/time_cpiler.dir/time_test.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/time_cpiler.dir/time_test.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /mnt/c/Users/limberg/hal-qos/time_test.c -o CMakeFiles/time_cpiler.dir/time_test.c.s

CMakeFiles/time_cpiler.dir/timehandler.c.o: CMakeFiles/time_cpiler.dir/flags.make
CMakeFiles/time_cpiler.dir/timehandler.c.o: ../timehandler.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/c/Users/limberg/hal-qos/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/time_cpiler.dir/timehandler.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/time_cpiler.dir/timehandler.c.o   -c /mnt/c/Users/limberg/hal-qos/timehandler.c

CMakeFiles/time_cpiler.dir/timehandler.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/time_cpiler.dir/timehandler.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /mnt/c/Users/limberg/hal-qos/timehandler.c > CMakeFiles/time_cpiler.dir/timehandler.c.i

CMakeFiles/time_cpiler.dir/timehandler.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/time_cpiler.dir/timehandler.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /mnt/c/Users/limberg/hal-qos/timehandler.c -o CMakeFiles/time_cpiler.dir/timehandler.c.s

# Object files for target time_cpiler
time_cpiler_OBJECTS = \
"CMakeFiles/time_cpiler.dir/time_test.c.o" \
"CMakeFiles/time_cpiler.dir/timehandler.c.o"

# External object files for target time_cpiler
time_cpiler_EXTERNAL_OBJECTS =

time_cpiler: CMakeFiles/time_cpiler.dir/time_test.c.o
time_cpiler: CMakeFiles/time_cpiler.dir/timehandler.c.o
time_cpiler: CMakeFiles/time_cpiler.dir/build.make
time_cpiler: CMakeFiles/time_cpiler.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/mnt/c/Users/limberg/hal-qos/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking C executable time_cpiler"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/time_cpiler.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/time_cpiler.dir/build: time_cpiler

.PHONY : CMakeFiles/time_cpiler.dir/build

CMakeFiles/time_cpiler.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/time_cpiler.dir/cmake_clean.cmake
.PHONY : CMakeFiles/time_cpiler.dir/clean

CMakeFiles/time_cpiler.dir/depend:
	cd /mnt/c/Users/limberg/hal-qos/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /mnt/c/Users/limberg/hal-qos /mnt/c/Users/limberg/hal-qos /mnt/c/Users/limberg/hal-qos/cmake-build-debug /mnt/c/Users/limberg/hal-qos/cmake-build-debug /mnt/c/Users/limberg/hal-qos/cmake-build-debug/CMakeFiles/time_cpiler.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/time_cpiler.dir/depend

