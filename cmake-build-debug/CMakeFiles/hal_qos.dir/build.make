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
include CMakeFiles/hal_qos.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/hal_qos.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/hal_qos.dir/flags.make

CMakeFiles/hal_qos.dir/classification.c.o: CMakeFiles/hal_qos.dir/flags.make
CMakeFiles/hal_qos.dir/classification.c.o: ../classification.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/c/Users/limberg/hal-qos/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/hal_qos.dir/classification.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/hal_qos.dir/classification.c.o   -c /mnt/c/Users/limberg/hal-qos/classification.c

CMakeFiles/hal_qos.dir/classification.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/hal_qos.dir/classification.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /mnt/c/Users/limberg/hal-qos/classification.c > CMakeFiles/hal_qos.dir/classification.c.i

CMakeFiles/hal_qos.dir/classification.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/hal_qos.dir/classification.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /mnt/c/Users/limberg/hal-qos/classification.c -o CMakeFiles/hal_qos.dir/classification.c.s

CMakeFiles/hal_qos.dir/queue.c.o: CMakeFiles/hal_qos.dir/flags.make
CMakeFiles/hal_qos.dir/queue.c.o: ../queue.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/c/Users/limberg/hal-qos/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/hal_qos.dir/queue.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/hal_qos.dir/queue.c.o   -c /mnt/c/Users/limberg/hal-qos/queue.c

CMakeFiles/hal_qos.dir/queue.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/hal_qos.dir/queue.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /mnt/c/Users/limberg/hal-qos/queue.c > CMakeFiles/hal_qos.dir/queue.c.i

CMakeFiles/hal_qos.dir/queue.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/hal_qos.dir/queue.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /mnt/c/Users/limberg/hal-qos/queue.c -o CMakeFiles/hal_qos.dir/queue.c.s

CMakeFiles/hal_qos.dir/timehandler.c.o: CMakeFiles/hal_qos.dir/flags.make
CMakeFiles/hal_qos.dir/timehandler.c.o: ../timehandler.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/c/Users/limberg/hal-qos/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/hal_qos.dir/timehandler.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/hal_qos.dir/timehandler.c.o   -c /mnt/c/Users/limberg/hal-qos/timehandler.c

CMakeFiles/hal_qos.dir/timehandler.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/hal_qos.dir/timehandler.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /mnt/c/Users/limberg/hal-qos/timehandler.c > CMakeFiles/hal_qos.dir/timehandler.c.i

CMakeFiles/hal_qos.dir/timehandler.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/hal_qos.dir/timehandler.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /mnt/c/Users/limberg/hal-qos/timehandler.c -o CMakeFiles/hal_qos.dir/timehandler.c.s

# Object files for target hal_qos
hal_qos_OBJECTS = \
"CMakeFiles/hal_qos.dir/classification.c.o" \
"CMakeFiles/hal_qos.dir/queue.c.o" \
"CMakeFiles/hal_qos.dir/timehandler.c.o"

# External object files for target hal_qos
hal_qos_EXTERNAL_OBJECTS =

hal_qos: CMakeFiles/hal_qos.dir/classification.c.o
hal_qos: CMakeFiles/hal_qos.dir/queue.c.o
hal_qos: CMakeFiles/hal_qos.dir/timehandler.c.o
hal_qos: CMakeFiles/hal_qos.dir/build.make
hal_qos: CMakeFiles/hal_qos.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/mnt/c/Users/limberg/hal-qos/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Linking C executable hal_qos"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/hal_qos.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/hal_qos.dir/build: hal_qos

.PHONY : CMakeFiles/hal_qos.dir/build

CMakeFiles/hal_qos.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/hal_qos.dir/cmake_clean.cmake
.PHONY : CMakeFiles/hal_qos.dir/clean

CMakeFiles/hal_qos.dir/depend:
	cd /mnt/c/Users/limberg/hal-qos/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /mnt/c/Users/limberg/hal-qos /mnt/c/Users/limberg/hal-qos /mnt/c/Users/limberg/hal-qos/cmake-build-debug /mnt/c/Users/limberg/hal-qos/cmake-build-debug /mnt/c/Users/limberg/hal-qos/cmake-build-debug/CMakeFiles/hal_qos.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/hal_qos.dir/depend

