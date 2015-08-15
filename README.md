# FlyOnAShellCode


##Description:

Created by: Sec-Mini-Projects (2015) under the MIT License - See "LICENSE" for Details. 

##Warnings

This program will RUN the supplied executable and malicious input file. USE ONLY IN MALWARE RESEARCH LABS.

##Notes

This program can be anywhere from very stable to very unstable depending on which APIs are hooked.\n\n
Avoid manually navigating the \"File Open\", etc dialogs from within the program will help eliminate crashes.\n\n

##Usage

Usage: \n--program[-p] <Program full path and name> \n--working_dir[-w] <working directory> \n--cmd_line[-c] <Command line arguments> (Optional)\n--api_list[-a] <API hook list path and name> \n--addr_exclude[-e] <address exclude file> (Optional)\n--debug_mode[-d] - Enables debug mode(Optional)
Usage - API library/names format is for each API call a new line matching (without the quotes) \"<lib name>,<api name>

##Dependencies

Compile the latest TitanEngine project (http://reversinglabs.com/open-source/titanengine.html.) which is used as the debugging engine in this program.

Place the binaries and ".lib" file in the "<root>\TitanEngine\" folder and the dll into the same directory as the main .EXE

Compile the latest scyllaHide project and place the dll and configuration file in appropriate folder.

Place the SycllaHide dll file in the "<root>\Release\plugins\x86\" folder.
