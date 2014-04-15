#include <stdexcept>

class injector_exception : public std::runtime_error
{
	public:
		injector_exception(const std::wstring& err, long line)
			:std::runtime_error(""),
			error_text_(err), error_line_(line)
		{}

		const std::wstring& get_error() const
		{
			return error_text_;
		}
		
	private:
		std::wstring error_text_;
		long error_line_;
};
