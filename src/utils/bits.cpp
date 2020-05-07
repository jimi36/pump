#include "pump/utils/bits.h"

namespace pump {
	namespace utils {

		bits_reader::bits_reader(c_uint8_ptr b, uint32 size) PUMP_NOEXCEPT :
			left_bc_(8),
			used_bc_(0),
			all_bc_(size*8),
			byte_pos_(b)
		{
			PUMP_ASSERT(b);
			PUMP_ASSERT(size > 0);
		}

		bool bits_reader::read(uint32 bc, uint8_ptr val)
		{
			if (bc > 8 || bc > all_bc_)
				return false;

			*val = __read_from_byte(bc);
			
			return true;
		}

		bool bits_reader::read(uint32 bc, uint16_ptr val)
		{
			if (bc > 16 || bc > all_bc_)
				return false;

			uint8 tmp[2] = { 0 };
			uint32 left = bc % 8;

#if defined(LITTLE_ENDIAN)
			int32 idx = bc / 8 + (left > 0 ? 0 : -1); int32 s = -1;
#elif defined(BIG_ENDIAN)
			int32 idx = 0; int32 s = 1;
#endif
			if (left > 0)
			{
				tmp[idx] = __read_from_byte(left);
				bc  -= left;
				idx += s;
			}
				
			while (bc > 0)
			{
				tmp[idx] = __read_from_byte(8);
				bc  -= 8;
				idx += s;
			}

			*val = *(uint16_ptr(tmp));

			return true;
		}

		bool bits_reader::read(uint32 bc, uint32_ptr val)
		{
			if (bc > 32 || bc > all_bc_)
				return false;

			uint8 tmp[4] = { 0 };
			uint32 left = bc % 8;

#if defined(LITTLE_ENDIAN)
			int32 idx = bc / 8 + (left > 0 ? 0 : -1); int32 s = -1;
#elif defined(BIG_ENDIAN)
			int32 idx = 0; int32 s = 1;
#endif
			if (left > 0)
			{
				tmp[idx] = __read_from_byte(left);
				bc  -= left;
				idx += s;
			}

			while (bc > 0)
			{
				tmp[idx] = __read_from_byte(8);
				bc  -= 8;
				idx += s;
			}

			*val = *(uint32_ptr(tmp));

			return true;
		}

		bool bits_reader::read(uint32 bc, uint64_ptr val)
		{
			if (bc > 64 || bc > all_bc_)
				return false;

			uint8 tmp[8] = { 0 };
			uint32 left = bc % 8;

#if defined(LITTLE_ENDIAN)
			int32 idx = bc / 8 + (left > 0 ? 0 : -1); int32 s = -1;
#elif defined(BIG_ENDIAN)
			int32 idx = 0; int32 s = 1;
#endif
			if (left > 0)
			{
				tmp[idx] = __read_from_byte(left);
				bc  -= left;
				idx += s;
			}

			while (bc > 0)
			{
				tmp[idx] = __read_from_byte(8);
				bc  -= 8;
				idx += s;
			}

			*val = *(uint64_ptr(tmp));

			return true;
		}

		uint8 bits_reader::__read_from_byte(uint32 bc)
		{
			uint8 val = 0;
			while (bc > 0)
			{
				uint8 rc = left_bc_ > bc ? bc : left_bc_;
				val = (val << rc) | (uint8((*byte_pos_) << (8 - left_bc_)) >> (8 - rc));

				bc       -= rc;
				left_bc_ -= rc;
				used_bc_ += rc;
				all_bc_  -= rc;

				if (left_bc_ == 0)
				{
					byte_pos_++;
					left_bc_ = 8;
				}
			}
			return val;
		}

		bits_writer::bits_writer(uint8_ptr b, uint32 size) PUMP_NOEXCEPT :
			left_bc_(8),
			used_bc_(0),
			all_bc_(size * 8),
			byte_pos_(b)
		{
			PUMP_ASSERT(b);
			PUMP_ASSERT(size > 0);
		}

		bool bits_writer::write(uint32 bc, uint8 val)
		{
			if (bc > 8 || bc > all_bc_)
				return false;

			__write_to_byte(bc, val);

			return true;
		}

		bool bits_writer::write(uint32 bc, uint16 val)
		{
			if (bc > 16 || bc > all_bc_)
				return false;

			uint32 left = bc % 8;
			uint8_ptr tmp = uint8_ptr(&val);

#if defined(LITTLE_ENDIAN)
			int32 idx = bc / 8 + (left > 0 ? 0 : -1); int32 s = -1;
#elif defined(BIG_ENDIAN)
			int32 idx = 0; int32 s = 1;
#endif
			if (left > 0)
			{
				__write_to_byte(left, tmp[idx]);
				bc  -= left;
				idx += s;
			}

			while (bc > 0)
			{
				__write_to_byte(8, tmp[idx]);
				bc  -= 8;
				idx += s;
			}

			return true;
		}

		bool bits_writer::write(uint32 bc, uint32 val)
		{
			if (bc > 32 || bc > all_bc_)
				return false;

			uint32 left = bc % 8;
			uint8_ptr tmp = uint8_ptr(&val);

#if defined(LITTLE_ENDIAN)
			int32 idx = bc / 8 + (left > 0 ? 0 : -1); int32 s = -1;
#elif defined(BIG_ENDIAN)
			int32 idx = 0; int32 s = 1;
#endif
			if (left > 0)
			{
				__write_to_byte(left, tmp[idx]);
				bc  -= left;
				idx += s;
			}

			while (bc > 0)
			{
				__write_to_byte(8, tmp[idx]);
				bc  -= 8;
				idx += s;
			}

			return true;
		}

		bool bits_writer::write(uint32 bc, uint64 val)
		{
			if (bc > 64 || bc > all_bc_)
				return false;

			uint32 left = bc % 8;
			uint8_ptr tmp = uint8_ptr(&val);

#if defined(LITTLE_ENDIAN)
			int32 idx = bc / 8 + (left > 0 ? 0 : -1); int32 s = -1;
#elif defined(BIG_ENDIAN)
			int32 idx = 0; int32 s = 1;
#endif
			if (left > 0)
			{
				__write_to_byte(left, tmp[idx]);
				bc  -= left;
				idx += s;
			}

			while (bc > 0)
			{
				__write_to_byte(8, tmp[idx]);
				bc  -= 8;
				idx += s;
			}

			return true;
		}

		void bits_writer::__write_to_byte(uint32 bc, uint8 val)
		{
			if (left_bc_ < bc)
			{
				*byte_pos_ |= ((val & (0xff >> (8 - left_bc_))) >> (bc - left_bc_));
				bc       -= left_bc_;
				used_bc_ += left_bc_;
				all_bc_  -= left_bc_;

				left_bc_ = 8;
				byte_pos_++;
			}

			*byte_pos_ |= ((val & (0xff >> (8 - bc))) << (left_bc_ - bc));
			left_bc_ -= bc;
			used_bc_ += bc;
			all_bc_  -= bc;

			if (left_bc_ == 0)
			{
				left_bc_ = 8;
				byte_pos_++;
			}
		}
	}
}
