#include <iostream>

#include "injector.hpp"

int main()
{
	injector a;
	a.set_blocking(false);
	
	try
	{
		a.inject(L"putty.exe", L"x86.dll");
	}
	catch(const injector_exception &e)
	{
		std::wcout << e.get_error() << std::endl;
	}
	
	return 0;
}