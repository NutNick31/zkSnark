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
include depends/libsnark/libsnark/CMakeFiles/profile_bacs_ppzksnark.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include depends/libsnark/libsnark/CMakeFiles/profile_bacs_ppzksnark.dir/compiler_depend.make

# Include the progress variables for this target.
include depends/libsnark/libsnark/CMakeFiles/profile_bacs_ppzksnark.dir/progress.make

# Include the compile flags for this target's objects.
include depends/libsnark/libsnark/CMakeFiles/profile_bacs_ppzksnark.dir/flags.make

depends/libsnark/libsnark/CMakeFiles/profile_bacs_ppzksnark.dir/zk_proof_systems/ppzksnark/bacs_ppzksnark/profiling/profile_bacs_ppzksnark.cpp.o: depends/libsnark/libsnark/CMakeFiles/profile_bacs_ppzksnark.dir/flags.make
depends/libsnark/libsnark/CMakeFiles/profile_bacs_ppzksnark.dir/zk_proof_systems/ppzksnark/bacs_ppzksnark/profiling/profile_bacs_ppzksnark.cpp.o: /home/rajesh/Desktop/zkSnark/depends/libsnark/libsnark/zk_proof_systems/ppzksnark/bacs_ppzksnark/profiling/profile_bacs_ppzksnark.cpp
depends/libsnark/libsnark/CMakeFiles/profile_bacs_ppzksnark.dir/zk_proof_systems/ppzksnark/bacs_ppzksnark/profiling/profile_bacs_ppzksnark.cpp.o: depends/libsnark/libsnark/CMakeFiles/profile_bacs_ppzksnark.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/rajesh/Desktop/zkSnark/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object depends/libsnark/libsnark/CMakeFiles/profile_bacs_ppzksnark.dir/zk_proof_systems/ppzksnark/bacs_ppzksnark/profiling/profile_bacs_ppzksnark.cpp.o"
	cd /home/rajesh/Desktop/zkSnark/build/depends/libsnark/libsnark && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT depends/libsnark/libsnark/CMakeFiles/profile_bacs_ppzksnark.dir/zk_proof_systems/ppzksnark/bacs_ppzksnark/profiling/profile_bacs_ppzksnark.cpp.o -MF CMakeFiles/profile_bacs_ppzksnark.dir/zk_proof_systems/ppzksnark/bacs_ppzksnark/profiling/profile_bacs_ppzksnark.cpp.o.d -o CMakeFiles/profile_bacs_ppzksnark.dir/zk_proof_systems/ppzksnark/bacs_ppzksnark/profiling/profile_bacs_ppzksnark.cpp.o -c /home/rajesh/Desktop/zkSnark/depends/libsnark/libsnark/zk_proof_systems/ppzksnark/bacs_ppzksnark/profiling/profile_bacs_ppzksnark.cpp

depends/libsnark/libsnark/CMakeFiles/profile_bacs_ppzksnark.dir/zk_proof_systems/ppzksnark/bacs_ppzksnark/profiling/profile_bacs_ppzksnark.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/profile_bacs_ppzksnark.dir/zk_proof_systems/ppzksnark/bacs_ppzksnark/profiling/profile_bacs_ppzksnark.cpp.i"
	cd /home/rajesh/Desktop/zkSnark/build/depends/libsnark/libsnark && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/rajesh/Desktop/zkSnark/depends/libsnark/libsnark/zk_proof_systems/ppzksnark/bacs_ppzksnark/profiling/profile_bacs_ppzksnark.cpp > CMakeFiles/profile_bacs_ppzksnark.dir/zk_proof_systems/ppzksnark/bacs_ppzksnark/profiling/profile_bacs_ppzksnark.cpp.i

depends/libsnark/libsnark/CMakeFiles/profile_bacs_ppzksnark.dir/zk_proof_systems/ppzksnark/bacs_ppzksnark/profiling/profile_bacs_ppzksnark.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/profile_bacs_ppzksnark.dir/zk_proof_systems/ppzksnark/bacs_ppzksnark/profiling/profile_bacs_ppzksnark.cpp.s"
	cd /home/rajesh/Desktop/zkSnark/build/depends/libsnark/libsnark && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/rajesh/Desktop/zkSnark/depends/libsnark/libsnark/zk_proof_systems/ppzksnark/bacs_ppzksnark/profiling/profile_bacs_ppzksnark.cpp -o CMakeFiles/profile_bacs_ppzksnark.dir/zk_proof_systems/ppzksnark/bacs_ppzksnark/profiling/profile_bacs_ppzksnark.cpp.s

# Object files for target profile_bacs_ppzksnark
profile_bacs_ppzksnark_OBJECTS = \
"CMakeFiles/profile_bacs_ppzksnark.dir/zk_proof_systems/ppzksnark/bacs_ppzksnark/profiling/profile_bacs_ppzksnark.cpp.o"

# External object files for target profile_bacs_ppzksnark
profile_bacs_ppzksnark_EXTERNAL_OBJECTS =

depends/libsnark/libsnark/profile_bacs_ppzksnark: depends/libsnark/libsnark/CMakeFiles/profile_bacs_ppzksnark.dir/zk_proof_systems/ppzksnark/bacs_ppzksnark/profiling/profile_bacs_ppzksnark.cpp.o
depends/libsnark/libsnark/profile_bacs_ppzksnark: depends/libsnark/libsnark/CMakeFiles/profile_bacs_ppzksnark.dir/build.make
depends/libsnark/libsnark/profile_bacs_ppzksnark: depends/libsnark/libsnark/libsnark.a
depends/libsnark/libsnark/profile_bacs_ppzksnark: depends/libsnark/depends/libff/libff/libff.a
depends/libsnark/libsnark/profile_bacs_ppzksnark: /usr/lib/x86_64-linux-gnu/libgmp.so
depends/libsnark/libsnark/profile_bacs_ppzksnark: /usr/lib/x86_64-linux-gnu/libgmp.so
depends/libsnark/libsnark/profile_bacs_ppzksnark: /usr/lib/x86_64-linux-gnu/libgmpxx.so
depends/libsnark/libsnark/profile_bacs_ppzksnark: depends/libsnark/depends/libzm.a
depends/libsnark/libsnark/profile_bacs_ppzksnark: depends/libsnark/libsnark/CMakeFiles/profile_bacs_ppzksnark.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=/home/rajesh/Desktop/zkSnark/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable profile_bacs_ppzksnark"
	cd /home/rajesh/Desktop/zkSnark/build/depends/libsnark/libsnark && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/profile_bacs_ppzksnark.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
depends/libsnark/libsnark/CMakeFiles/profile_bacs_ppzksnark.dir/build: depends/libsnark/libsnark/profile_bacs_ppzksnark
.PHONY : depends/libsnark/libsnark/CMakeFiles/profile_bacs_ppzksnark.dir/build

depends/libsnark/libsnark/CMakeFiles/profile_bacs_ppzksnark.dir/clean:
	cd /home/rajesh/Desktop/zkSnark/build/depends/libsnark/libsnark && $(CMAKE_COMMAND) -P CMakeFiles/profile_bacs_ppzksnark.dir/cmake_clean.cmake
.PHONY : depends/libsnark/libsnark/CMakeFiles/profile_bacs_ppzksnark.dir/clean

depends/libsnark/libsnark/CMakeFiles/profile_bacs_ppzksnark.dir/depend:
	cd /home/rajesh/Desktop/zkSnark/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/rajesh/Desktop/zkSnark /home/rajesh/Desktop/zkSnark/depends/libsnark/libsnark /home/rajesh/Desktop/zkSnark/build /home/rajesh/Desktop/zkSnark/build/depends/libsnark/libsnark /home/rajesh/Desktop/zkSnark/build/depends/libsnark/libsnark/CMakeFiles/profile_bacs_ppzksnark.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : depends/libsnark/libsnark/CMakeFiles/profile_bacs_ppzksnark.dir/depend

