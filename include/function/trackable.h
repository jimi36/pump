/*
 * The MIT License (MIT)
 *
 * Copyright (C) zhenghaitao
 * Contact mail with ming8ren@163.com
 *
 */

#ifndef	function_trackable_h
#define function_trackable_h

#include <memory>

using std::weak_ptr;
using std::shared_ptr;

namespace function {

typedef struct 
{
	bool trackable;
	weak_ptr<void> tracked_ptr;
} track_info;

class trackable
{
public:
	/*********************************************************************************
	 * Constructor
	 ********************************************************************************/
	trackable(): tracked_ptr_(static_cast<int*>(0))
	{
	}

	/*********************************************************************************
	 * Deconstructor
	 ********************************************************************************/
	virtual ~trackable() 
	{
	}

	/*********************************************************************************
	 * Get sahred ptr for checking
	 ********************************************************************************/
	const shared_ptr<void>& get_shared_ptr()
	{
		return tracked_ptr_;
	}

private:
	shared_ptr<void> tracked_ptr_;
};

} // namespace function

#endif