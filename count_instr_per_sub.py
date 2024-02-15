# This script comes from the idea that most obfuscators tend to protect and obfuscate harder subroutines which are somehow important to the code.
# Obfuscators usually apply arithmetic and virtualization-based obfuscations, which increases a lot the size of the target subroutine.
# Aware of that, listing the instructions per subroutine can lead you to key subroutines in the binary.

function_counts = [(func, len(list(func.low_level_il))) for func in bv.functions]
function_counts.sort(key=lambda x: x[1], reverse=True)

for func, count in function_counts:
    print(f"{func.name}: {count} instructions.")
