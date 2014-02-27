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
		e.show_error();
	}
	
	return 0;
}