Packed Malware Analyzer (PACKMAN) is licensed under the MIT License. See LICENSE.txt

! Be aware that PACKMAN will run the executable being analyzed.
! Take precautions before running a malware under PACKMAN.
! Best practice is to run PACKMAN in a Virtual Machine.

==================
About directories:
==================
- "exe" directory:    
	directory for collecting the executables 
	in one location, just for convenience
- "out" directory:    
	output directory of PACKMAN
- "report" directory: 
	contains the report about PACKMAN
- "src" directory:    
	contains the source code of PACKMAN and a batch script
	script to run PACKMAN

==================
PACKMAN requirements:
==================
1 - Windows 7 x86 (PACKMAN is not tested with Windows 8 and above, or x86-64)
2 - PIN Binary instrumentation tool
3 - Microsoft Visual C++

==================
PACKMAN installation:
==================
1 - Set the WF_ROOT variable in src/packman.bat
	to the directory where this README file is located
2 - Set the PIN_ROOT variable in src/packman.bat
	to the directory where pin.exe is located

==================
== PACKMAN usage:  ==
==================
- Visual Studio Command Prompt must be used
- Working directory of the prompt has to be set to the "src" directory
- packman.bat is the script to run the tool
- options of packman.bat:
	-> To analyze an executable:   
		packman analyze <exe_file_location> 
	-> to compile PACKMAN:            
		packman compile
	-> To clean compilation files: 
		packman clean


