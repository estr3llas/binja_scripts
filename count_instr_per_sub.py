# This is script comes from the fact that most obfuscators tend to protect and obfuscate harder subroutines which are somehow important to the code.
# Aware of that, the obfuscation comes in form of additional instructions, which, with this script, can lead you to identify those important subroutines.

function_counts = [(func, len(list(func.low_level_il))) for func in bv.functions]
function_counts.sort(key=lambda x: x[1], reverse=True)

for func, count in function_counts:
    print(f"{func.name}: {count} instructions.")
