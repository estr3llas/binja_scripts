from binaryninja import PossibleValueSet

def main():
    print("VSA")
    # 3 @ 004027cd  eax = arg4 ; 1st assignment of arg4 (0xCB63A80F) to another variable
    arg4_var = current_mlil[3].vars_read[0]
    var_value = PossibleValueSet.constant(0xCB63A80F)
    current_function.set_user_var_value(arg4_var, current_function.start, var_value)

    # 64 @ 00402927  ecx_4 = ecx_3 & arg3 ; 1st assignment of arg3 (0x116216E2) to another variable
    arg3_var = current_mlil[64].vars_read[1]
    var_value = PossibleValueSet.constant(0x116216E2)
    current_function.set_user_var_value(arg3_var, current_function.start, var_value)

    current_function.reanalyze()
        
    # 004595b0  uint32_t crc32_table[0x100] = ...
    refs = current_view.get_code_refs(0x004595b0)
    
    refs = current_view.get_code_refs(0x004595b0)
    with open(r'output.txt', 'w') as fp:
        for ea in refs:
            if hasattr(ea.mlil, 'operation') and ea.mlil.operation == MediumLevelILOperation.MLIL_SET_VAR:
                fp.write(f"{hex(ea.address)}: {ea.mlil.src.get_possible_values()}\n")
    
    # current_function.clear_all_user_var_values()


main()
