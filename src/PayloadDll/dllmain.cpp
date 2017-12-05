// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <string>
#include <stdarg.h>
#include <fstream>

#include "angelscript.h"


#define PRINT_ERROR_OFFSET 0X1DDD80
#define ENGINE_PTR_OFFSET 0X432951
#define ACTIVECONTEXT_OFFSET 0x2EC2E7
#define ASGETTHREADMANAGER_OFFSET 0X587210
#define ASPREPAREMULTITHREAD_OFFSET 0X587680
#define ASCREATESCRIPTENGINE_OFFSET 0X594EB0
#define ASGETACTIVECONTEXT_OFFSET 0X580E30
#define DETOUR_OFFSET 0X2EC2E7

#define ORIGJUMP_OFFSET 0x2EC3B8
#define ORIG_SHELLCODE_OFFSET 0X2EC379

#define JMP_ORIG_RVA 0X2EC326

typedef int (__cdecl *Add)(int param1, int param2);
typedef int(__fastcall *AddDebugMessage)(char* format, ...);
typedef asIScriptEngine* (*T_asCreateScriptEngine)(int);
typedef int(*T_asPrepareMultithread)(asIThreadManager*);
typedef asIThreadManager* (*T_asGetThreadManager)();
typedef asIScriptContext* (*T_asGetActiveContext)();

class cVector2f
{
	float GetElement(uint64_t alIdx);
	void SetElement(uint64_t alIdx, float);
	float SqrLength();
	float Length();
	float Normalize();

	float x;
	float y;

};

HMODULE thisDll;

AddDebugMessage dbgMsg;
T_asCreateScriptEngine CreateScriptEngine;
T_asPrepareMultithread PrepareMultithread;
T_asGetThreadManager GetThreadManager;
T_asGetActiveContext GetActiveContext;
asIScriptEngine* engine = 0;
asIScriptContext* activeCtx = 0;

std::ofstream ofile;

BYTE shellcode[13] = { 0x49, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0xFF, 0xD1 };
BYTE orShellCode[] = { 0x48, 0x85, 0xC0, 0x0F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x10 };

extern "C" __int64 restoreCode();
extern "C" __int64 jmpOrig = 0;
extern "C" void* ctxAddr = nullptr;

void getRAX()
{
	//tiveCtx = (asIScriptContext*)_AddressOfReturnAddress();
	restoreCode();
	/*__int64 origAddr = (__int64)(GetModuleHandle(NULL) + ORIG_SHELLCODE_OFFSET);
	__int64 offset = (__int64)(GetModuleHandle(NULL) + ORIGJUMP_OFFSET);

	DWORD dwProtect;
	VirtualProtect((LPVOID)origAddr, 15, PAGE_EXECUTE_READWRITE, &dwProtect);
	memcpy(&shellcode[5], &offset, 8);
	WriteProcessMemory(GetCurrentProcess(), (LPVOID)origAddr, shellcode, 11, NULL);
	VirtualProtect((LPVOID)origAddr, 15, dwProtect, NULL);*/
	
}

void DetourAddress(LPVOID address, LPVOID hook)
{
	std::ofstream ofile("E:\\tmp.txt", std::ofstream::out);
	__int64 funcaddr = (__int64)hook;
	ofile << std::hex << hook << std::endl << funcaddr;
	DWORD dwProtect;
	ofile.close();
	VirtualProtect(address, 13, PAGE_EXECUTE_READWRITE, &dwProtect);
	/*DWORD offset = ((DWORD)hook - (DWORD)address - 5);
	ofile << std::hex << offset;
	
	*/
	
	memcpy(&shellcode[2], &funcaddr, 8);
	
	WriteProcessMemory(GetCurrentProcess(), address, shellcode, 13, NULL);
	VirtualProtect(address, 13, dwProtect, NULL);
}

void Patch()
{
	DWORD_PTR modBase = (DWORD_PTR)GetModuleHandle(NULL);
	dbgMsg = (AddDebugMessage)(modBase + PRINT_ERROR_OFFSET);
	//activeCtx = (asIScriptContext*)(modBase + ACTIVECONTEXT_OFFSET);
	CreateScriptEngine = (T_asCreateScriptEngine)(modBase + ASCREATESCRIPTENGINE_OFFSET);
	PrepareMultithread = (T_asPrepareMultithread)(modBase + ASPREPAREMULTITHREAD_OFFSET);
	GetThreadManager = (T_asGetThreadManager)(modBase + ASGETTHREADMANAGER_OFFSET);
	GetActiveContext = (T_asGetActiveContext)(modBase + ASGETACTIVECONTEXT_OFFSET);
	jmpOrig = (__int64)(modBase + JMP_ORIG_RVA);
	/*uintptr_t* vTable = *(uintptr_t**)engine;
	
	activeCtx = (GetActiveContext)0x00007FF676E40E30;
	
	getCount =  (asUINT(*)()) vTable[12];*/

	dbgMsg("Provaaaaaaaaa");
	//PrepareMultithread(GetThreadManager());
	//engine = CreateScriptEngine(ANGELSCRIPT_VERSION);
	DetourAddress((void*)(modBase + DETOUR_OFFSET), (LPVOID)&getRAX);
	//engine = activeCtx->GetEngine();
	//asIScriptModule* mod = engine->GetModuleByIndex(20);

	while (!ctxAddr) { dbgMsg("Loop");  if (ctxAddr) break; };

	activeCtx = (asIScriptContext*)ctxAddr;
	engine = activeCtx->GetEngine();
	//activeCtx = engine->CreateContext();
	asIScriptModule* mod = engine->GetModule("maps/test.hps");
	dbgMsg("Base Addr Module: %llx, ENGINE ADDR: %llx, CONTEXT ADDR: %llx, MOD ADDR:%llx", modBase, engine, activeCtx, mod);
	asIObjectType* type = mod->GetObjectTypeByName("cScrMap");
	asIScriptFunction* factory = type->GetFactoryByIndex(0);

	if (factory) dbgMsg("Factory Addr: %llx", factory);

	activeCtx->Prepare(factory);
	int rr = activeCtx->Execute();
	if (rr != asEXECUTION_FINISHED)
	{
		if (rr == asEXECUTION_ABORTED)
			dbgMsg("Execution aborted!");
		else if (rr == asEXECUTION_EXCEPTION)
		{
			asIScriptFunction *func = activeCtx->GetExceptionFunction();
			dbgMsg("func %s, mod %s, sect %s, line %d, desc %s", func->GetDeclaration(), func->GetModuleName(), func->GetScriptSectionName(), activeCtx->GetExceptionLineNumber(), activeCtx->GetExceptionString());

		}
	}
	else
		dbgMsg("Script executed");

	asIScriptObject* obj = *(asIScriptObject**)activeCtx->GetAddressOfReturnValue();
	obj->AddRef();


	asIScriptFunction* func = type->GetMethodByIndex(9);
	dbgMsg("%s ", type->GetMethodByIndex(9)->GetName());
	if (func) dbgMsg("Func addr: %llx", func);

	activeCtx->Prepare(func);
	activeCtx->SetObject(obj);
	

	int r = activeCtx->Execute();
	if (r != asEXECUTION_FINISHED)
	{
		if (r == asEXECUTION_ABORTED)
			dbgMsg("Execution aborted!");
		else if (r == asEXECUTION_EXCEPTION)
		{
			asIScriptFunction *func = activeCtx->GetExceptionFunction();
			dbgMsg("func %s, mod %s, sect %s, line %d, desc %s", func->GetDeclaration(), func->GetModuleName(), func->GetScriptSectionName(), activeCtx->GetExceptionLineNumber(), activeCtx->GetExceptionString());

		}
	}
	else
		dbgMsg("Script executed");

		
	/*std::ofstream omodule("E:\\modules.txt", std::ofstream::out);

	for (size_t i = 0; i < 188; i++)
	{
		omodule << "i: " << i << " -> " << engine->GetModuleByIndex(i)->GetName() << std::endl;
	}

	omodule.close();*/
	//dbgMsg("Vtable: %llx ", *vTable);
	

	/*std::ofstream omodule("E:\\maps_test_dump.txt", std::ofstream::out);
	omodule << "Type count: " << mod->GetObjectTypeCount() << std::endl;
	for (size_t i = 0; i < mod->GetObjectTypeCount(); i++)
	{
		omodule << std::setw(0);
		omodule << "id: " << i << "-> " << mod->GetObjectTypeByIndex(i)->GetName() << std::endl;
		omodule << std::setw(5);
		omodule << "Factory count: " << mod->GetObjectTypeByIndex(i)->GetFactoryCount() << std::endl;
		for (size_t j = 0; j < mod->GetObjectTypeByIndex(i)->GetFactoryCount(); j++)
		{
			omodule << "id: " << j << "-> " << mod->GetObjectTypeByIndex(i)->GetFactoryByIndex(j)->GetName() << std::endl;
			omodule << "declaration: " << mod->GetObjectTypeByIndex(i)->GetFactoryByIndex(j)->GetDeclaration() << std::endl;
		}

		omodule << std::setw(10);
		omodule << "Function count: " << mod->GetObjectTypeByIndex(i)->GetMethodCount() << std::endl;
		for (size_t h = 0; h < mod->GetObjectTypeByIndex(i)->GetMethodCount(); h++)
		{
			omodule << "id: " << h << "-> " << mod->GetObjectTypeByIndex(i)->GetMethodByIndex(h)->GetName() << std::endl;
			omodule << "declaration: " << mod->GetObjectTypeByIndex(i)->GetMethodByIndex(h)->GetDeclaration() << std::endl;
		}
		
		omodule << std::endl << std::endl;
	}

	omodule.close();*/

	//dbgMsg("Module count: %d, object type in effect_flash: %d", engine->GetModuleCount(), );
	
	if (!engine)
		dbgMsg("engine not found");
	//engine = ctx->GetEngine();
	dbgMsg("Opening file stream");
	ofile.open("E:\\dll.log", std::ofstream::out | std::ofstream::app);

	if (ofile)
	{
		dbgMsg("File stream open");

		ofile << "\n Dll attached!\n " << " base addr: " << std::hex << modBase;
		//if (!engine)
			//ofile << "Engine ptr null!";
	}
	else
		dbgMsg("File stream not open");

	ofile.close();

	
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	 

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:

		thisDll = hModule;
		Patch();
		

		//MessageBox(NULL, L"test", L"test", NULL);
		
		break;
	case DLL_THREAD_ATTACH:		
	case DLL_THREAD_DETACH:		
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

