#include <iostream>
#include <fstream>

#include <Windows.h>
#include <Psapi.h>
#include <Tlhelp32.h>

#include "handle_helper.hpp"
#include "injector_exception.hpp"

class injector
{
	typedef unsigned long (__stdcall * thr_rtn)(void *);
	typedef ULONGLONG QWORD;

	public:
		injector();
		injector(const injector &inj);
		~injector();
		injector& operator=(const injector& inj);

		void inject(const std::wstring& proc_name, const std::wstring& dll_name);
		void inject(const std::wstring& proc_name, const BYTE * code, unsigned long int code_size);
		void inject(unsigned int pid, const std::wstring& dll_name);
		void inject(unsigned int pid, const BYTE * code, unsigned long int code_size);

		void set_blocking(bool active) { is_blocking_ = active; }
		void show() { std::cout<<is_blocking_<<std::endl; }

	private:
		struct injectorcode;
		struct triple_byte {BYTE a; BYTE b; BYTE c;};
		
		static const int bufsize = MAX_PATH;
		static unsigned int inst_cnt_;
		static TOKEN_PRIVILEGES old_tp_;
		bool is_blocking_;

		static void adjust_privileges(bool debug_rights);
		static void file_exists(const std::wstring& file_name);
		static void init_injector_struct(injectorcode& cmds, const std::wstring& dll_name);
		static unsigned int find_process_by_name(const std::wstring& proc_name);

		static void * open_and_alloc(handle_helper& process, unsigned int pid, unsigned long int size);
		static void write_to_memory(handle_helper& process, void * base_addr, const BYTE * code, unsigned long int code_size);
		static void run_remote_code(handle_helper& process, handle_helper& remote_thread, void * base_addr);
		void wait_and_free(handle_helper& process, handle_helper& remote_thread, void * base_addr);

#pragma pack(push, 1)
#ifdef _WIN64
		struct injectorcode
		{
			DWORD stack_init;
			
			//LoadLibrary(...)
			DWORD loadlibrary_init_stack;
			
			triple_byte instr_mov_loadlibrary;
			DWORD loadlibrary_arg;
			
			WORD instr_call_loadlibrary;
			DWORD adr_from_call_loadlibrary;

			DWORD loadlibrary_clear_stack;

			//ExitThread(0)
			DWORD exitthread_init_stack;

			triple_byte instr_mov_exitthread;
			DWORD exitthread_arg;

			WORD instr_call_exitthread;
			DWORD adr_from_call_exitthread;
			
			QWORD addr_loadlibrary;
			QWORD addr_exitthread;
			wchar_t libraryname[bufsize];

		};
#else
		struct injectorcode
		{
			WORD ebx_to_eax;
			WORD mov_eax_offset;
			BYTE loadlibrary_arg;

			BYTE instr_push_loadlibrary_arg;

			WORD instr_call_loadlibrary;
			BYTE adr_from_call_loadlibrary;

			BYTE instr_push_exitthread_arg;
			DWORD exitthread_arg;

			WORD instr_call_exitthread;
			BYTE adr_from_call_exitthread;

			DWORD addr_loadlibrary;
			DWORD addr_exitthread;
			wchar_t libraryname[bufsize];
		};
#endif
#pragma pack(pop, 1)
};
