#include <pump/service.h>

#include <pump/codec/sha1.h>
#include <pump/codec/base64.h>

#include <pump/utils/bits.h>
#include <pump/utils/strings.h>

#include <pump/time/timer.h>
#include <pump/time/timestamp.h>

#include <pump/transports.h>

int main(int argc, const char **argv)
{
	char *p = new char[100];
	{
		std::string des(pump::codec::base64_encode_length("123"), 0);
		pump::codec::base64_encode("123", des);
	}
	
	return  0;
}