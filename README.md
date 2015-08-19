# FlyOnAShellCode

Created by: Sec-Mini-Projects (2015) under the MIT License - See "LICENSE" for Details. 

##Description:

Starts the execution of a x86 32 bit **ONLY** vulnerable program with optional command line parameters and hooks the API names read from a text file.  When these API calls are hit, the program will constantly run until return and check the return address for shellcode like characteristics.

**Hooking a large number of commonly called functions will slow down execution and may cause a crash.**

##Warnings

This program will RUN the supplied executable and malicious input file. USE ONLY IN MALWARE RESEARCH LABS.

##Notes

This program can be anywhere from very stable to very unstable depending on which APIs are hooked.
Avoid manually navigating the "File Open", etc dialogs from within the program will help eliminate crashes due to large delays in execution.

##Usage

Usage: Program.exe with:

--program[-p] <Program full path and name> <br>
--working_dir[-w] <working directory> <br>
--api_list[-a] <API hook list path and name> <br>
--cmd_line[-c] <Cmd line arguments> (Optional) <br>
--addr_exclude[-e] \<address exclude file> (Optional) <br>
--debug_mode[-d] - Enables debug mode (Optional) <br>


#####API_List library/names text file format (each library and api on a new line):

kernel32.dll,CreateFileA <br>
kernel32.dll,WriteFile <br>
....

#####Addr_Exclude exclusion text file format (each library and address on a new line)

mso.dll,0x2222 <br>
mso.dll,0x3333 <br>
....

The second paramter is the last two bytes of the address to be whitelisted. This is a hacky solution to avoid ASLR issues, there is a way to solve this issue.  This option may be required if a program executes legitimate code from RWX memory).  Add the library name and last two bytes of the address which calls into the RWX allocated memory.


##Compiling & Dependencies

Compiled & written using Visual Studio 2010.

Compile the latest TitanEngine project (http://reversinglabs.com/open-source/titanengine.html.) which is used as the debugging engine in this program.

**Example: Place the binaries and ".lib" file into the "<root>\TitanEngine\" folder and the dll into the same directory as the main .EXE**

Compile the latest scyllaHide project and place the dll and configuration file into the appropriate folder.

**Example: Place the SycllaHide dll file into the "<root>\Release\plugins\x86\" folder.**
