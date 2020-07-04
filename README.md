# C++ Code Injector Class
[![CPP](https://img.shields.io/badge/cpp-green.svg)](https://en.wikipedia.org/wiki/C%2B%2B) [![License](https://img.shields.io/badge/license-MIT-red.svg)](https://raw.githubusercontent.com/kaimi-io/cpp-injector-class/master/LICENSE)

[![Telegram](https://img.shields.io/badge/Telegram--lightgrey?logo=telegram&style=social)](https://t.me/kaimi_io)
[![Twitter](https://img.shields.io/twitter/follow/kaimi_io?style=social)](https://twitter.com/kaimi_io)
## Description
### Available methods
```cpp
// Inject a DLL with the specified name in the process with the specified name
void inject(const std::wstring& proc_name, const std::wstring& dll_name);

// Inject a raw assembly code in the process with the specified name
void inject(const std::wstring& proc_name, const BYTE * code, unsigned long int code_size);

// Inject a DLL with the specified name in the process with the specified PID (Process Idenitifer)
void inject(unsigned int pid, const std::wstring& dll_name);

// Inject a raw assembly code in the process with the specified PID (Process Idenitifer)
void inject(unsigned int pid, const BYTE * code, unsigned long int code_size);

// Enable/Disable blocking mode (should we call WaitForSingleObject and VirtualFreeEx functions after creating a remote thread)
void set_blocking(bool active);
```
### Usage
```cpp
#include "injector.hpp"

// Inject x64.dll to the "CFF Explorer.exe" process in non-blocking mode
int main()
{
	injector a;
	a.set_blocking(false);
	
	try
	{
		a.inject(L"CFF Explorer.exe", L"x64.dll");
	}
	catch(const injector_exception& e)
	{
		e.show_error();
	}

	return 0;
}
```
## License
C++ Code Injector Class Copyright © 2011-2020 by Kaimi (Sergey Belov) - https://kaimi.io.

C++ Code Injector Class is free software: you can redistribute it and/or modify it under the terms of the Massachusetts Institute of Technology (MIT) License.

You should have received a copy of the MIT License along with C++ Code Injector Class. If not, see [MIT License](LICENSE).
