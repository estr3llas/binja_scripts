target_reg = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp',
              'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rsp', 'rbp',
              'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']

# The following code iterates through each function to identify and display indirect calls, potentially generating a considerable amount of output.

#"""
for func in bv.functions:

    if len(func.indirect_branches) != 0:
        if current_function != func.name:
            if current_function:
                print()
            print(f'{func.name}:')
            current_function = func.name

        for indirect_branch in func.indirect_branches:
            bv.add_tag(indirect_branch.source_addr,"Important", "Indirect Call") 
            print(f'   {hex(indirect_branch.source_addr)} {bv.get_disassembly(indirect_branch.source_addr)}')

    for block in func.low_level_il:
        for instr in block:
            if len(instr.operands) > 0:
                operand = str(instr.operands[0])
    
                if instr.operation == LowLevelILOperation.LLIL_CALL and operand in target_reg:
                    bv.add_tag(instr.address,"Important", "Indirect Call") 
                    if current_function != func.name:
                        if current_function:
                            print()
                        print(f'{func.name}:')
                        current_function = func.name
                    print(f'   {hex(instr.address)} {instr}')
    
                if instr.operation == LowLevelILOperation.LLIL_JUMP and operand in target_reg:
                    bv.add_tag(instr.address,"Important", "Indirect Call") 
                    if current_function != func.name:
                        if current_function:
                            print()
                        print(f'{func.name}:')
                        current_function = func.name
                    print(f'   {hex(instr.address)} {instr}')
#"""

# Uncomment the following code to iterate specifically through the current function, which might be more appropriate for larger binaries.

"""
func = current_function

if len(func.indirect_branches) != 0:
    if current_function != func.name:
        if current_function:
            print()
        print(f'{func.name}:')
        current_function = func.name

    for indirect_branch in func.indirect_branches:
        bv.add_tag(indirect_branch.source_addr, "Important", "Indirect Call") 
        print(f'   {hex(indirect_branch.source_addr)} {bv.get_disassembly(indirect_branch.source_addr)}')

for block in func.low_level_il:
    for instr in block:
        if len(instr.operands) > 0:
            operand = str(instr.operands[0])

            if instr.operation == LowLevelILOperation.LLIL_CALL and operand in target_reg:
                bv.add_tag(instr.address, "Important", "Indirect Call") 
                if current_function != func.name:
                    if current_function:
                        print()
                    print(f'{func.name}:')
                    current_function = func.name
                print(f'   {hex(instr.address)} {instr}')

            if instr.operation == LowLevelILOperation.LLIL_JUMP and operand in target_reg:
                bv.add_tag(instr.address, "Important", "Indirect Call") 
                if current_function != func.name:
                    if current_function:
                        print()
                    print(f'{func.name}:')
                    current_function = func.name
                print(f'   {hex(instr.address)} {instr}')
"""  
