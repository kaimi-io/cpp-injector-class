#include "injector.hpp"


unsigned int injector::inst_cnt_ = 0;
TOKEN_PRIVILEGES injector::old_tp_;

injector::injector()
	:is_blocking_(true)
{
	if(!inst_cnt_)
		adjust_privileges(true);

	inst_cnt_++;
}

injector::injector(const injector &inj)
	:is_blocking_(inj.is_blocking_)
{ 
	inst_cnt_++;
}

injector::~injector()
{
	inst_cnt_--;

	if(!inst_cnt_)
		adjust_privileges(false);
}

injector& injector::operator=(const injector& inj)
{
	if(&inj != this)
		is_blocking_ = inj.is_blocking_;
	return *this;
}

void injector::file_exists(const std::wstring& file_name)
{
	std::ifstream file;
	file.open(file_name, std::ios::in);
	
	if(file.is_open())
		return;
	else
		throw injector_exception(L"Can't open DLL", __LINE__);
}

void injector::adjust_privileges(bool debug_rights)
{
	TOKEN_PRIVILEGES tp;
	handle_helper token;
	DWORD tpSize = sizeof(TOKEN_PRIVILEGES);
	LUID luid;

	if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token.get()))
		if(GetLastError() != ERROR_CALL_NOT_IMPLEMENTED)
			throw injector_exception(L"OpenProcessToken", __LINE__);

	if(debug_rights)
	{
		if(!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
			throw injector_exception(L"LookupPrivilegeValue", __LINE__);

		ZeroMemory(&tp, sizeof(tp));
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	}
	else
	{
		ZeroMemory(&tp, sizeof(tp));
		tp = old_tp_;
	}

	if(!AdjustTokenPrivileges(token.get(), FALSE, &tp, sizeof(TOKEN_PRIVILEGES), &old_tp_, &tpSize))
		throw injector_exception(L"AdjustTokenPrivileges", __LINE__);
}

unsigned int injector::find_process_by_name(const std::wstring& proc_name)
{
	PROCESSENTRY32 pe32;
	unsigned int pid = 0;
	handle_helper ss;
	
	if( (ss = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPMODULE32, 0)).get() == INVALID_HANDLE_VALUE )
		throw injector_exception(L"CreateToolhelp32Snapshot", __LINE__);

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if(!Process32First(ss.get(), &pe32))
		throw injector_exception(L"Process32First", __LINE__);

	do
	{
		if(!proc_name.compare(pe32.szExeFile))
		{
			pid = pe32.th32ProcessID;
			break;
		}
	} while(Process32Next(ss.get(), &pe32));

	return pid;
}

void injector::init_injector_struct(injectorcode& cmds, const std::wstring& dll_name)
{
	if(dll_name.length() > bufsize)
		throw injector_exception(L"DLL name exceeds buffer size", __LINE__);
	
	wchar_t full_path[bufsize];
	if(!GetFullPathName(dll_name.c_str(), bufsize, full_path, NULL))
		throw injector_exception(L"GetFullPathName", __LINE__);
	else
		wcscpy_s(cmds.libraryname, bufsize, full_path);

#ifdef _WIN64
	//sub rsp, 8
	cmds.stack_init = 0x08EC8348;
	
	//sub rsp, 20
	cmds.loadlibrary_init_stack = 0x20EC8348;
	//lea rcx, eip+..
	cmds.instr_mov_loadlibrary.a = 0x48;
	cmds.instr_mov_loadlibrary.b = 0x8D;
	cmds.instr_mov_loadlibrary.c = 0x0D;
	
	cmds.loadlibrary_arg =  offsetof(injectorcode, libraryname) - offsetof(injectorcode, loadlibrary_arg);
	//call qword ptr...
	cmds.instr_call_loadlibrary = 0x15ff;
	cmds.adr_from_call_loadlibrary = offsetof(injectorcode, addr_loadlibrary) - offsetof(injectorcode, loadlibrary_clear_stack);
	//add rsp, 20
	cmds.loadlibrary_clear_stack = 0x20C48348;
	
	//sub rsp, 20
	cmds.exitthread_init_stack = 0x20EC8348;
	//mov rcx, 0
	cmds.instr_mov_exitthread.a = 0x48;
	cmds.instr_mov_exitthread.b = 0xC7;
	cmds.instr_mov_exitthread.c = 0xC1;
	cmds.exitthread_arg = 0;
	//call qword ptr...
	cmds.instr_call_exitthread = 0x15ff;
	cmds.adr_from_call_exitthread = offsetof(injectorcode, addr_exitthread) - offsetof(injectorcode, addr_loadlibrary);
	
	cmds.addr_loadlibrary = reinterpret_cast<QWORD>(GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW"));
	cmds.addr_exitthread = reinterpret_cast<QWORD>(GetProcAddress(GetModuleHandle(L"kernel32.dll"), "ExitThread"));
#else
	cmds.ebx_to_eax = 0xC38B;
	cmds.mov_eax_offset = 0xC083;
	cmds.loadlibrary_arg = offsetof(injectorcode, libraryname);
	
	cmds.instr_push_loadlibrary_arg = 0x50;

	cmds.instr_call_loadlibrary = 0x53ff;
	cmds.adr_from_call_loadlibrary = offsetof(injectorcode, addr_loadlibrary);
	

	cmds.instr_push_exitthread_arg  = 0x68;
	cmds.exitthread_arg = 0;

	cmds.instr_call_exitthread = 0x53ff;
	cmds.adr_from_call_exitthread =  offsetof(injectorcode, addr_exitthread);

	cmds.addr_loadlibrary = reinterpret_cast<DWORD>(GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW"));
	cmds.addr_exitthread = reinterpret_cast<DWORD>(GetProcAddress(GetModuleHandle(L"kernel32.dll"), "ExitThread"));
#endif
}

void * injector::open_and_alloc(handle_helper& process, unsigned int pid, unsigned long int size)
{
	void * base_addr = NULL;

	if( !(process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid)).get() )
	{
		process.reset();
		throw injector_exception(L"OpenProcess", __LINE__);
	}
	
	if( !(base_addr = reinterpret_cast<BYTE *>(VirtualAllocEx(process.get(), NULL, size, MEM_COMMIT, PAGE_READWRITE))) )
		throw injector_exception(L"VirtualAllocEx", __LINE__);

	return base_addr;
}

void injector::write_to_memory(handle_helper& process, void * base_addr, const BYTE * code, unsigned long int code_size)
{
	DWORD junk;

	if(!WriteProcessMemory(process.get(), base_addr, code, code_size, NULL))
		throw injector_exception(L"WriteProcessMemory", __LINE__);

	if(!VirtualProtectEx(process.get(), base_addr, code_size, PAGE_EXECUTE_READ, &junk))
		throw injector_exception(L"VirtualProtectEx", __LINE__);
}

void injector::run_remote_code(handle_helper& process, handle_helper& remote_thread, void * base_addr)
{
	if( !(remote_thread = CreateRemoteThread(process.get(), NULL, 0, reinterpret_cast<thr_rtn>(base_addr), base_addr, 0, NULL)).get() )
		throw injector_exception(L"CreateRemoteThread", __LINE__);
}

void injector::wait_and_free(handle_helper& process, handle_helper& remote_thread, void * base_addr)
{
	if(is_blocking_)
	{
		WaitForSingleObject(remote_thread.get(), INFINITE);
		
		if(!VirtualFreeEx(process.get(), base_addr, 0, MEM_RELEASE))
			throw injector_exception(L"VirtualFreeEx", __LINE__);
	}
}

void injector::inject(const std::wstring& proc_name, const BYTE * code, unsigned long int code_size)
{
	inject(find_process_by_name(proc_name), code, code_size);
}

void injector::inject(const std::wstring& proc_name, const std::wstring& dll_name)
{
	inject(find_process_by_name(proc_name), dll_name);
}

void injector::inject(unsigned int pid, const std::wstring& dll_name)
{
	file_exists(dll_name);
	
	injectorcode cmds;
	init_injector_struct(cmds, dll_name);
	inject(pid, reinterpret_cast<BYTE *>(&cmds), sizeof(injectorcode));
}

void injector::inject(unsigned int pid, const BYTE * code, unsigned long int code_size)
{
	if(!pid)
		throw injector_exception(L"Zero PID specified", __LINE__);
	
	handle_helper process, remote_thread;
	void * base_addr = NULL;

	try
	{
		 base_addr = open_and_alloc(process, pid, code_size);
		 write_to_memory(process, base_addr, code, code_size);

		 run_remote_code(process, remote_thread, base_addr);
		 wait_and_free(process, remote_thread, base_addr);
	}
	catch(const injector_exception&)
	{
		if(base_addr)
			VirtualFreeEx(process.get(), base_addr, 0, MEM_RELEASE);

		throw;
	}
}
