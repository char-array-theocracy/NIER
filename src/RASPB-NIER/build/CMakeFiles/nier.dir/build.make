# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.30

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
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/clem/Projects/NIER/src/RASPB-NIER

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/clem/Projects/NIER/src/RASPB-NIER/build

# Include any dependencies generated for this target.
include CMakeFiles/nier.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/nier.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/nier.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/nier.dir/flags.make

CMakeFiles/nier.dir/main.c.o: CMakeFiles/nier.dir/flags.make
CMakeFiles/nier.dir/main.c.o: /home/clem/Projects/NIER/src/RASPB-NIER/main.c
CMakeFiles/nier.dir/main.c.o: CMakeFiles/nier.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/clem/Projects/NIER/src/RASPB-NIER/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/nier.dir/main.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/nier.dir/main.c.o -MF CMakeFiles/nier.dir/main.c.o.d -o CMakeFiles/nier.dir/main.c.o -c /home/clem/Projects/NIER/src/RASPB-NIER/main.c

CMakeFiles/nier.dir/main.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing C source to CMakeFiles/nier.dir/main.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/clem/Projects/NIER/src/RASPB-NIER/main.c > CMakeFiles/nier.dir/main.c.i

CMakeFiles/nier.dir/main.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling C source to assembly CMakeFiles/nier.dir/main.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/clem/Projects/NIER/src/RASPB-NIER/main.c -o CMakeFiles/nier.dir/main.c.s

CMakeFiles/nier.dir/mongoose.c.o: CMakeFiles/nier.dir/flags.make
CMakeFiles/nier.dir/mongoose.c.o: /home/clem/Projects/NIER/src/RASPB-NIER/mongoose.c
CMakeFiles/nier.dir/mongoose.c.o: CMakeFiles/nier.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/clem/Projects/NIER/src/RASPB-NIER/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/nier.dir/mongoose.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/nier.dir/mongoose.c.o -MF CMakeFiles/nier.dir/mongoose.c.o.d -o CMakeFiles/nier.dir/mongoose.c.o -c /home/clem/Projects/NIER/src/RASPB-NIER/mongoose.c

CMakeFiles/nier.dir/mongoose.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing C source to CMakeFiles/nier.dir/mongoose.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/clem/Projects/NIER/src/RASPB-NIER/mongoose.c > CMakeFiles/nier.dir/mongoose.c.i

CMakeFiles/nier.dir/mongoose.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling C source to assembly CMakeFiles/nier.dir/mongoose.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/clem/Projects/NIER/src/RASPB-NIER/mongoose.c -o CMakeFiles/nier.dir/mongoose.c.s

CMakeFiles/nier.dir/NIER.c.o: CMakeFiles/nier.dir/flags.make
CMakeFiles/nier.dir/NIER.c.o: /home/clem/Projects/NIER/src/RASPB-NIER/NIER.c
CMakeFiles/nier.dir/NIER.c.o: CMakeFiles/nier.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/clem/Projects/NIER/src/RASPB-NIER/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/nier.dir/NIER.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/nier.dir/NIER.c.o -MF CMakeFiles/nier.dir/NIER.c.o.d -o CMakeFiles/nier.dir/NIER.c.o -c /home/clem/Projects/NIER/src/RASPB-NIER/NIER.c

CMakeFiles/nier.dir/NIER.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing C source to CMakeFiles/nier.dir/NIER.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/clem/Projects/NIER/src/RASPB-NIER/NIER.c > CMakeFiles/nier.dir/NIER.c.i

CMakeFiles/nier.dir/NIER.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling C source to assembly CMakeFiles/nier.dir/NIER.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/clem/Projects/NIER/src/RASPB-NIER/NIER.c -o CMakeFiles/nier.dir/NIER.c.s

CMakeFiles/nier.dir/cJSON.c.o: CMakeFiles/nier.dir/flags.make
CMakeFiles/nier.dir/cJSON.c.o: /home/clem/Projects/NIER/src/RASPB-NIER/cJSON.c
CMakeFiles/nier.dir/cJSON.c.o: CMakeFiles/nier.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/clem/Projects/NIER/src/RASPB-NIER/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object CMakeFiles/nier.dir/cJSON.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/nier.dir/cJSON.c.o -MF CMakeFiles/nier.dir/cJSON.c.o.d -o CMakeFiles/nier.dir/cJSON.c.o -c /home/clem/Projects/NIER/src/RASPB-NIER/cJSON.c

CMakeFiles/nier.dir/cJSON.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing C source to CMakeFiles/nier.dir/cJSON.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/clem/Projects/NIER/src/RASPB-NIER/cJSON.c > CMakeFiles/nier.dir/cJSON.c.i

CMakeFiles/nier.dir/cJSON.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling C source to assembly CMakeFiles/nier.dir/cJSON.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/clem/Projects/NIER/src/RASPB-NIER/cJSON.c -o CMakeFiles/nier.dir/cJSON.c.s

# Object files for target nier
nier_OBJECTS = \
"CMakeFiles/nier.dir/main.c.o" \
"CMakeFiles/nier.dir/mongoose.c.o" \
"CMakeFiles/nier.dir/NIER.c.o" \
"CMakeFiles/nier.dir/cJSON.c.o"

# External object files for target nier
nier_EXTERNAL_OBJECTS =

/home/clem/Projects/NIER/src/RASPB-NIER/nier: CMakeFiles/nier.dir/main.c.o
/home/clem/Projects/NIER/src/RASPB-NIER/nier: CMakeFiles/nier.dir/mongoose.c.o
/home/clem/Projects/NIER/src/RASPB-NIER/nier: CMakeFiles/nier.dir/NIER.c.o
/home/clem/Projects/NIER/src/RASPB-NIER/nier: CMakeFiles/nier.dir/cJSON.c.o
/home/clem/Projects/NIER/src/RASPB-NIER/nier: CMakeFiles/nier.dir/build.make
/home/clem/Projects/NIER/src/RASPB-NIER/nier: /usr/lib/libssl.so
/home/clem/Projects/NIER/src/RASPB-NIER/nier: /usr/lib/libcrypto.so
/home/clem/Projects/NIER/src/RASPB-NIER/nier: CMakeFiles/nier.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=/home/clem/Projects/NIER/src/RASPB-NIER/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Linking C executable /home/clem/Projects/NIER/src/RASPB-NIER/nier"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/nier.dir/link.txt --verbose=$(VERBOSE)
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --blue --bold "Copying the executable to /build/Debug/outDebug"
	/usr/bin/cmake -E make_directory /home/clem/Projects/NIER/src/RASPB-NIER/build/Debug
	/usr/bin/cmake -E copy /home/clem/Projects/NIER/src/RASPB-NIER/nier /home/clem/Projects/NIER/src/RASPB-NIER/build/Debug/outDebug

# Rule to build all files generated by this target.
CMakeFiles/nier.dir/build: /home/clem/Projects/NIER/src/RASPB-NIER/nier
.PHONY : CMakeFiles/nier.dir/build

CMakeFiles/nier.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/nier.dir/cmake_clean.cmake
.PHONY : CMakeFiles/nier.dir/clean

CMakeFiles/nier.dir/depend:
	cd /home/clem/Projects/NIER/src/RASPB-NIER/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/clem/Projects/NIER/src/RASPB-NIER /home/clem/Projects/NIER/src/RASPB-NIER /home/clem/Projects/NIER/src/RASPB-NIER/build /home/clem/Projects/NIER/src/RASPB-NIER/build /home/clem/Projects/NIER/src/RASPB-NIER/build/CMakeFiles/nier.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : CMakeFiles/nier.dir/depend

