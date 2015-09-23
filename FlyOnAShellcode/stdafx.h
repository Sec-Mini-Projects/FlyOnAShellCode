// stdafx.h : Sec-Mini-Projects (2015) under the MIT License - See "LICENSE" for Details.

#pragma once

#include "targetver.h"
#include <stdio.h>
#include <iostream>
#include <tchar.h>
#include <TitanEngine.h>
#include <psapi.h>
#include <string.h>
#include <Shlwapi.h>

void __stdcall CheckForShellcode();
void  __stdcall OnStep();
void __stdcall BPHandler();
void __stdcall OnSingleStepException(void* ExceptionData);
bool  __stdcall SetAPIBP(ULONG_PTR api_addr);
void __stdcall OnEntry();
int main(int argc, char * argv[]);