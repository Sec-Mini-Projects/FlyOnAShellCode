# FlyOnAShellCode


##Description:

Created by: Sec-Mini-Projects (2015) under the MIT License - See "LICENSE" for Details. 

##Warnings

This program will RUN the supplied executable and malicious input file. USE ONLY IN MALWARE RESEARCH LABS.

##Notes

This program can be anywhere from very stable to very unstable depending on which APIs are hooked.
Avoid manually navigating the \"File Open\", etc dialogs from within the program will help eliminate crashes.

##Usage

Usage: Program.exe with:

--program[-p] <Program full path and name>

--working_dir[-w] <working directory>

--api_list[-a] <API hook list path and name>

--cmd_line[-c] <Command line arguments> (Optional)

--addr_exclude[-e] <address exclude file> (Optional)

--debug_mode[-d] - Enables debug mode (Optional)


API library/names format is as seen within the example text file apis_to_hook.txt.

##Compiling & Dependencies

Compiled & written using Visual Studio 2010.

Compile the latest TitanEngine project (http://reversinglabs.com/open-source/titanengine.html.) which is used as the debugging engine in this program.

**Example: Place the binaries and ".lib" file in the "<root>\TitanEngine\" folder and the dll into the same directory as the main .EXE**

Compile the latest scyllaHide project and place the dll and configuration file within the appropriate folder.

**Example: Place the SycllaHide dll file in the "<root>\Release\plugins\x86\" folder.**
