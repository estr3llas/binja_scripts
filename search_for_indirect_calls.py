target_reg = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp',
              'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rsp', 'rbp',
              'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']

for func in bv.functions:
    for block in func.low_level_il:
        for instr in block:
            if len(instr.operands) > 0:
                operand = str(instr.operands[0])
    
                if instr.operation == LowLevelILOperation.LLIL_CALL and operand in target_reg:
                    if current_function != func.name:
                        if current_function:
                            print()
                        print(f'{func.name}:')
                        current_function = func.name
                    print(f'   {hex(instr.address)} {instr}')
    
                if instr.operation == LowLevelILOperation.LLIL_JUMP and operand in target_reg:
                    if current_function != func.name:
                        if current_function:
                            print()
                        print(f'{func.name}:')
                        current_function = func.name
                    print(f'   {hex(instr.address)} {instr}')
