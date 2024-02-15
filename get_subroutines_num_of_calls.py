for func in bv.functions:
	num_of_callers = len(func.callers)
	if num_of_callers > 1: #change it for better filtering
		print(func.return_type, func.name, func.calling_convention, func.start, num_of_callers)
