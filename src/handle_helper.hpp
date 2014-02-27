#include <Windows.h>

class handle_helper
{
	public:
		handle_helper(HANDLE h)
			:h_(h)
		{}

		handle_helper(handle_helper& other)
			:h_(other.h_)
		{
			other.h_ = INVALID_HANDLE_VALUE;
		}

		handle_helper()
			:h_(INVALID_HANDLE_VALUE)
		{}

		handle_helper& operator=(handle_helper& other)
		{
			close();
			h_ = other.h_;
			other.h_ = INVALID_HANDLE_VALUE;
			return *this;
		}

		handle_helper& operator=(HANDLE h)
		{
			close();
			h_ = h;
			return *this;
		}
		
		HANDLE& get() { return h_; }

		~handle_helper()
		{
			close();
		}

		void close()
		{
			if(h_ != INVALID_HANDLE_VALUE)
			{
				CloseHandle(h_);
				h_ = INVALID_HANDLE_VALUE;
			}
		}

		void reset() { h_ = INVALID_HANDLE_VALUE; }

	private:
		HANDLE h_;
};