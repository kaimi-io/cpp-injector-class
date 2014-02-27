#include <iostream>

class injector_exception
{
	public:
		injector_exception(const std::wstring& err, long line)
			:error_text_(err), error_line_(line)
		{}
		virtual ~injector_exception() throw()
		{}

		void show_error() const
		{
			std::wcout<<"Exception: "<<error_text_.c_str()<<" | Code: "<<std::showbase<<std::hex<<GetLastError()<<std::dec<<" | Line: "<<error_line_<<std::endl;
		}
		
	private:
		std::wstring error_text_;
		long error_line_;
};
