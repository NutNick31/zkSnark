# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.27

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /home/rajesh/.local/lib/python3.10/site-packages/cmake/data/bin/cmake

# The command to remove a file.
RM = /home/rajesh/.local/lib/python3.10/site-packages/cmake/data/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/rajesh/Desktop/zkSnark

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/rajesh/Desktop/zkSnark/build

# Include any dependencies generated for this target.
include depends/libsnark/depends/CMakeFiles/zm.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include depends/libsnark/depends/CMakeFiles/zm.dir/compiler_depend.make

# Include the progress variables for this target.
include depends/libsnark/depends/CMakeFiles/zm.dir/progress.make

# Include the compile flags for this target's objects.
include depends/libsnark/depends/CMakeFiles/zm.dir/flags.make

depends/libsnark/depends/CMakeFiles/zm.dir/ate-pairing/src/zm.cpp.o: depends/libsnark/depends/CMakeFiles/zm.dir/flags.make
depends/libsnark/depends/CMakeFiles/zm.dir/ate-pairing/src/zm.cpp.o: /home/rajesh/Desktop/zkSnark/depends/libsnark/depends/ate-pairing/src/zm.cpp
depends/libsnark/depends/CMakeFiles/zm.dir/ate-pairing/src/zm.cpp.o: depends/libsnark/depends/CMakeFiles/zm.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/rajesh/Desktop/zkSnark/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object depends/libsnark/depends/CMakeFiles/zm.dir/ate-pairing/src/zm.cpp.o"
	cd /home/rajesh/Desktop/zkSnark/build/depends/libsnark/depends && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT depends/libsnark/depends/CMakeFiles/zm.dir/ate-pairing/src/zm.cpp.o -MF CMakeFiles/zm.dir/ate-pairing/src/zm.cpp.o.d -o CMakeFiles/zm.dir/ate-pairing/src/zm.cpp.o -c /home/rajesh/Desktop/zkSnark/depends/libsnark/depends/ate-pairing/src/zm.cpp

depends/libsnark/depends/CMakeFiles/zm.dir/ate-pairing/src/zm.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/zm.dir/ate-pairing/src/zm.cpp.i"
	cd /home/rajesh/Desktop/zkSnark/build/depends/libsnark/depends && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/rajesh/Desktop/zkSnark/depends/libsnark/depends/ate-pairing/src/zm.cpp > CMakeFiles/zm.dir/ate-pairing/src/zm.cpp.i

depends/libsnark/depends/CMakeFiles/zm.dir/ate-pairing/src/zm.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/zm.dir/ate-pairing/src/zm.cpp.s"
	cd /home/rajesh/Desktop/zkSnark/build/depends/libsnark/depends && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/rajesh/Desktop/zkSnark/depends/libsnark/depends/ate-pairing/src/zm.cpp -o CMakeFiles/zm.dir/ate-pairing/src/zm.cpp.s

depends/libsnark/depends/CMakeFiles/zm.dir/ate-pairing/src/zm2.cpp.o: depends/libsnark/depends/CMakeFiles/zm.dir/flags.make
depends/libsnark/depends/CMakeFiles/zm.dir/ate-pairing/src/zm2.cpp.o: /home/rajesh/Desktop/zkSnark/depends/libsnark/depends/ate-pairing/src/zm2.cpp
depends/libsnark/depends/CMakeFiles/zm.dir/ate-pairing/src/zm2.cpp.o: depends/libsnark/depends/CMakeFiles/zm.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/rajesh/Desktop/zkSnark/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object depends/libsnark/depends/CMakeFiles/zm.dir/ate-pairing/src/zm2.cpp.o"
	cd /home/rajesh/Desktop/zkSnark/build/depends/libsnark/depends && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT depends/libsnark/depends/CMakeFiles/zm.dir/ate-pairing/src/zm2.cpp.o -MF CMakeFiles/zm.dir/ate-pairing/src/zm2.cpp.o.d -o CMakeFiles/zm.dir/ate-pairing/src/zm2.cpp.o -c /home/rajesh/Desktop/zkSnark/depends/libsnark/depends/ate-pairing/src/zm2.cpp

depends/libsnark/depends/CMakeFiles/zm.dir/ate-pairing/src/zm2.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/zm.dir/ate-pairing/src/zm2.cpp.i"
	cd /home/rajesh/Desktop/zkSnark/build/depends/libsnark/depends && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/rajesh/Desktop/zkSnark/depends/libsnark/depends/ate-pairing/src/zm2.cpp > CMakeFiles/zm.dir/ate-pairing/src/zm2.cpp.i

depends/libsnark/depends/CMakeFiles/zm.dir/ate-pairing/src/zm2.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/zm.dir/ate-pairing/src/zm2.cpp.s"
	cd /home/rajesh/Desktop/zkSnark/build/depends/libsnark/depends && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/rajesh/Desktop/zkSnark/depends/libsnark/depends/ate-pairing/src/zm2.cpp -o CMakeFiles/zm.dir/ate-pairing/src/zm2.cpp.s

# Object files for target zm
zm_OBJECTS = \
"CMakeFiles/zm.dir/ate-pairing/src/zm.cpp.o" \
"CMakeFiles/zm.dir/ate-pairing/src/zm2.cpp.o"

# External object files for target zm
zm_EXTERNAL_OBJECTS =

depends/libsnark/depends/libzm.a: depends/libsnark/depends/CMakeFiles/zm.dir/ate-pairing/src/zm.cpp.o
depends/libsnark/depends/libzm.a: depends/libsnark/depends/CMakeFiles/zm.dir/ate-pairing/src/zm2.cpp.o
depends/libsnark/depends/libzm.a: depends/libsnark/depends/CMakeFiles/zm.dir/build.make
depends/libsnark/depends/libzm.a: depends/libsnark/depends/CMakeFiles/zm.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=/home/rajesh/Desktop/zkSnark/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking CXX static library libzm.a"
	cd /home/rajesh/Desktop/zkSnark/build/depends/libsnark/depends && $(CMAKE_COMMAND) -P CMakeFiles/zm.dir/cmake_clean_target.cmake
	cd /home/rajesh/Desktop/zkSnark/build/depends/libsnark/depends && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/zm.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
depends/libsnark/depends/CMakeFiles/zm.dir/build: depends/libsnark/depends/libzm.a
.PHONY : depends/libsnark/depends/CMakeFiles/zm.dir/build

depends/libsnark/depends/CMakeFiles/zm.dir/clean:
	cd /home/rajesh/Desktop/zkSnark/build/depends/libsnark/depends && $(CMAKE_COMMAND) -P CMakeFiles/zm.dir/cmake_clean.cmake
.PHONY : depends/libsnark/depends/CMakeFiles/zm.dir/clean

depends/libsnark/depends/CMakeFiles/zm.dir/depend:
	cd /home/rajesh/Desktop/zkSnark/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/rajesh/Desktop/zkSnark /home/rajesh/Desktop/zkSnark/depends/libsnark/depends /home/rajesh/Desktop/zkSnark/build /home/rajesh/Desktop/zkSnark/build/depends/libsnark/depends /home/rajesh/Desktop/zkSnark/build/depends/libsnark/depends/CMakeFiles/zm.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : depends/libsnark/depends/CMakeFiles/zm.dir/depend

