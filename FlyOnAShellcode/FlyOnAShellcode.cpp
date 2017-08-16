//Created by: Sec-Mini-Projects (2015) under the MIT License - See "LICENSE" for Details.
//Description: Checks whether shellcode is running within a program by hooking API calls using anti-anti-API Hooking techniques and memory forensics.
//Usage: Please run the program without any parameters to show the usage menu.
//TitanEngine is used as the debugging engine in this program - http://reversinglabs.com/open-source/titanengine.html.

#include "stdafx.h"
#define MAX_WHITELIST 200
#define MAX_BUF_LENGTH 600
ULONG_PTR ep = NULL;
PROCESS_INFORMATION * info = NULL;
LPSTR api_file = NULL;
LPSTR addr_exclude_file = NULL;
bool found_shellcode = false;
unsigned long exclude_addrs[MAX_WHITELIST];
LPSTR exclude_libs[MAX_WHITELIST];
bool debug_mode = false;

//Checks for shellcode located at the current IP
void __stdcall CheckForShellcode()
{
	ThreaderPauseAllThreads(false);
	if (found_shellcode == false)
	{
		ULONG_PTR ip = (ULONG_PTR)GetContextData(UE_EIP);
		LPSTR temp = (char*)calloc(255, sizeof(char));
		LPSTR mod_name = (LPSTR)calloc(MAX_BUF_LENGTH,1);
		GetMappedFileName(info->hProcess, (LPVOID)ip, (LPSTR)mod_name, MAX_BUF_LENGTH);
		unsigned short last_16_bits = (unsigned short)(ip);
		bool is_Avoid = false;
		//This will need to be changed for x64 bit code due to ALSR and other differences, as will other sections of this code.
		//The existing code deals with Microsoft doing something weird when processing OLE objects embedded in a DOCX/XLSX/etc file.
		int x = 0;
		while (x < MAX_WHITELIST && exclude_addrs[x] != NULL && exclude_libs[x] != NULL && is_Avoid == false)
		{
			char * dll_name = strrchr(mod_name, '\\');
			if (dll_name != NULL)
			{
				if (StrCmpI(dll_name + 1, exclude_libs[x]) == NULL)
				{
					if (last_16_bits == exclude_addrs[x])
					{
						is_Avoid = true;
					}
				}
			}
			x++;
		}
		if (is_Avoid == false)
		{
			LPSTR instr = _strlwr((char*)Disassemble((LPVOID)ip));
			MEMORY_BASIC_INFORMATION * mem_info = (MEMORY_BASIC_INFORMATION*)calloc(1, sizeof(MEMORY_BASIC_INFORMATION));
			SIZE_T temp = VirtualQueryEx(info->hProcess, (LPCVOID)ip, mem_info, sizeof(*mem_info));
			if (temp && mem_info)
			{
				if (mod_name == NULL || mem_info->Protect > 0x20 || StrRChr(mod_name, NULL, '.') == NULL)
				{
					LPSTR seg_dump_name = (LPSTR)calloc(MAX_BUF_LENGTH, sizeof(char));
					sprintf_s(seg_dump_name, MAX_BUF_LENGTH, "%x Seg Dump.bin", mem_info->BaseAddress);
					printf("Found exploit at address %x - creating full and partial dumps. Mod Name is: %s Mem Protect: %x\n(Note: If this was unexpected, please run using the \"-d\" option to retrieve the last 2 bytes of the address for whitelisting)", ip, mod_name, mem_info->Protect);
					DumpMemory(info->hProcess, mem_info->BaseAddress, mem_info->RegionSize, seg_dump_name);
					DumpRegions(info->hProcess, "Full Region Dump Files", false);
					DumpProcess(info->hProcess, (LPVOID)GetDebuggedFileBaseAddress(), "Full Memory Image Dump.bin", ep);
					found_shellcode = true;
					if (seg_dump_name)
						free(seg_dump_name);
					StopDebug();
					exit(1);
				}
				if (debug_mode == true)
				{
					printf("Checked for shellcode %s %x %s 4\n", instr, ip, mod_name);
				}
			}
			if (mem_info)
				free(mem_info);
			StepOver(OnStep);
		}
		if (mod_name)
			free(mod_name);
		if (temp)
			free(temp);
	}
	ThreaderResumeAllThreads(false);
}

//Steps over code, determining whether a return instruction has been encountered, if not, just keeps on stepping over.
void  __stdcall OnStep()
{
	ULONG_PTR ip = (ULONG_PTR)GetContextData(UE_EIP);
	LPSTR mod_name = NULL;
	unsigned char instr = NULL;
	SIZE_T bytes_read = NULL;
	bool is_ret = false;
	ReadProcessMemory(info->hProcess, (LPCVOID)ip, &instr, sizeof(instr), &bytes_read);
	if (bytes_read != NULL)
	{
		if (instr == 0xC2 || instr == 0xC3 || instr == 0xCA || instr == 0xCB)
		{
			StepOver(CheckForShellcode);
		}
		else
		{
			StepOver(OnStep);
		}
	}
}

void __stdcall OnSingleStepException(void* ExceptionData)
{
	SetNextDbgContinueStatus(DBG_CONTINUE);
	printf("***###Received### - Single step exception.***\n");
}

//Creates a thread for each breakpoint hit to reduce bottlenecks.
void __stdcall BPHandler()
{
	StepOver(OnStep);
}

//Searches for the first JXX or call and creates a breakpoint.
bool  __stdcall SetAPIBP(ULONG_PTR api_addr)
{
	bool found = false;
	ULONG_PTR addr = api_addr;
	LPSTR instr = NULL;
	if (addr != NULL)
	{
		while (found == false)
		{
			instr = _strlwr((LPSTR)Disassemble((LPVOID)addr));
			if (StrStrI(instr, "j") == NULL && StrStrI(instr, "call") == NULL && StrStrI(instr, "ret") == NULL)
			{
				addr = addr + LengthDisassembleEx(info->hProcess, (LPVOID)addr);
			}
			else
			{
				found = true;
			}
		}
		SetBPX(addr, UE_BREAKPOINT, BPHandler);
		//printf("Breakpoing set for instr %s at %x \n",instr,api_addr); 
	}
	else
	{
		found = false;
	}
	return found;
}

//Entry point handler for the program, reads the APIS to be hooked and applies them through the SetAPIBP function.
void __stdcall OnEntry()
{
	ep = GetContextData(UE_EIP);
	LPSTR buf = (LPSTR)calloc(MAX_BUF_LENGTH, sizeof(char));
	LPSTR exclude_buf = (LPSTR)calloc(MAX_BUF_LENGTH, sizeof(char));
	int temp = strlen(buf);
	FILE * f_api_file = fopen(api_file, "r");
	FILE * f_exclude_file = NULL;
	if (addr_exclude_file == NULL)
	{
		if (debug_mode == true)
			printf("***###LOGGING### - Address exclude file could not be found.***\n");
	}
	else
	{
		f_exclude_file = fopen(addr_exclude_file, "r");
		int x = 0;
		while (fgets(exclude_buf, MAX_BUF_LENGTH / sizeof(*exclude_buf), f_exclude_file) && x < MAX_WHITELIST)
		{
			LPSTR exclude_lib = strtok(exclude_buf, ",");
			LPSTR exclude_addr = strtok(NULL, ",");
			if (exclude_lib != NULL && exclude_addr != NULL)
			{
				bool dll_failed = false;
				if (exclude_addr[strlen(exclude_addr) - 1] == 0x0a)
					exclude_addr[strlen(exclude_addr) - 1] = 0x00;
				if (exclude_lib[strlen(exclude_lib) - 1] == 0x0a)
					exclude_lib[strlen(exclude_lib) - 1] = 0x00;
				long exclude_this_addr = strtol(exclude_addr, NULL, 16);
				exclude_libs[x] = (LPSTR)calloc(MAX_BUF_LENGTH, sizeof(char));
				exclude_addrs[x] = exclude_this_addr;
				strcpy_s(exclude_libs[x], MAX_BUF_LENGTH, exclude_lib);
				if (debug_mode == true)
					printf("***###LOGGING### - Read exclude addr entry: %s %x***\n", exclude_lib, exclude_this_addr);
			}
			x++;
		}
	}

	if (f_api_file == NULL)
	{
		printf("***###FATAL### - API's to hook file could not be found.***\n");
		StopDebug();
		exit(1);
	}
	else
	{
		while (fgets(buf, MAX_BUF_LENGTH / sizeof(*buf), f_api_file) != NULL)
		{
			LPSTR lib_name = strtok(buf, ",");
			LPSTR api_name = strtok(NULL, ",");
			bool dll_failed = false;
			if (api_name[strlen(api_name) - 1] == 0x0a)
				api_name[strlen(api_name) - 1] = 0x00;
			if (LoadLibrary(lib_name) == NULL)
			{
				if (debug_mode == true)
					printf("***###FAILED### - Could not load %s locally.***\n", lib_name);
			}
			else
			{
				if (debug_mode == true)
					printf("***###LOGGING### - Loaded %s locally.***\n", lib_name);
				if (LibrarianGetLibraryInfo(lib_name) == NULL)
				{
					if (RemoteLoadLibrary(info->hProcess, lib_name, false) == NULL)
					{
						if (debug_mode == true)
							printf("***###FAILED### - Could not load %s into the remote address space.***\n", lib_name);
						dll_failed = true;
					}
				}
				else
				{
					if (debug_mode == true)
						printf("***###LOGGING### - %s already loaded within the remote address space.***\n", lib_name);
				}
				if (!dll_failed)
				{
					ULONG_PTR api_addr = (ULONG_PTR)ImporterGetRemoteAPIAddressEx(lib_name, api_name);
					if (SetAPIBP(api_addr))
					{
						if (debug_mode == true)
							printf("***###LOGGING### - Breakpoint set for %s %x.***\n", api_name, api_addr);
					}
					else
					{
						if (debug_mode == true)
							printf("***###FAILED### - Breakpoint could not be set for %s.***\n", api_name);
					}
				}
			}
		}
	}
	if (f_api_file)
		fclose(f_api_file);
	if (f_exclude_file)
		fclose(f_exclude_file);
	if (buf)
		free(buf);
}

//Inits the debugger library and callbacks.
int main(int argc, char * argv[])
{

	int x = 1;
	LPSTR program = NULL;
	LPSTR working = NULL;
	LPSTR cmd_line = NULL;
	while (x < argc)
	{
		if (StrCmpI(argv[x], "--program") == 0 || StrCmpI(argv[x], "-p") == 0)
		{
			program = argv[x + 1];
		}
		else if (StrCmpI(argv[x], "--working_dir") == 0 || StrCmpI(argv[x], "-w") == 0)
		{
			working = argv[x + 1];
		}
		else if (StrCmpI(argv[x], "--cmd_line") == 0 || StrCmpI(argv[x], "-c") == 0)
		{
			cmd_line = argv[x + 1];
		}
		else if (StrCmpI(argv[x], "--api_list") == 0 || StrCmpI(argv[x], "-a") == 0)
		{
			api_file = argv[x + 1];
		}
		else if (StrCmpI(argv[x], "--addr_exclude") == 0 || StrCmpI(argv[x], "-e") == 0)
		{
			addr_exclude_file = argv[x + 1];
		}
		else if (StrCmpI(argv[x], "--debug_mode") == 0 || StrCmpI(argv[x], "-d") == 0)
		{
			debug_mode = true;
			x--;
		}
		x = x + 2;
	}
	if (program != NULL && working != NULL && api_file != NULL)
	{
		info = (PROCESS_INFORMATION *)InitDebugEx(program, cmd_line, working, OnEntry);
		SetCustomHandler(UE_CH_SINGLESTEP, OnSingleStepException);
		SetBPXOptions(UE_BREAKPOINT_INT3);
		if (info == NULL)
		{
			printf("***###FATAL### - Failed init.***\n");
		}
		else
		{
			DebugLoop();
		}
		printf("***###LOGGING### - Exiting.***\n");
	}
	else
	{
		printf("\nFlyOnAShellcode V3.1.\n");
		printf("Sec-Mini-Projects (2015) under the MIT License - See \"LICENSE\" for Details.\n");
		printf("TitanEngine is used as the debugging engine in this program - http://reversinglabs.com/open-source/titanengine.html.\n");
		printf("***WARNING*** - This program will RUN the supplied executable and malicious input file. USE ONLY IN MALWARE RESEARCH LABS.\n\n");
		printf("Note 1 - This program can be anywhere from very stable to very unstable depending on which APIs are hooked.\n\n");
		printf("Note 2 - Avoid manually navigating the \"File Open\", etc dialogs from within the program will help eliminate crashes.\n\n");
		printf("Usage: \n--program[-p] <Program full path and name> \n--working_dir[-w] <working directory> \n--cmd_line[-c] <Command line arguments> (Optional)\n--api_list[-a] <API hook list path and name> \n--addr_exclude[-e] <address exclude file> (Optional)\n--debug_mode[-d] - Enables debug mode(Optional)\n\n");
		printf("Usage - API library/names format is for each API call a new line matching (without the quotes) \"<lib name>,<api name>\"\n\n");
	}
	//printf("%x",argc);
	return 0;
}

