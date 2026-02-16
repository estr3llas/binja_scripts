OUTPUT_FILE = r'C:\Users\User\Documents\RUST_STRINGS.txt'


def get_ro_sections_segments():
    ro = []
    seen = set()
    
    for section in bv.sections.values():
        if section.semantics == SectionSemantics.ReadOnlyDataSectionSemantics:
            key = (section.start, section.end)
            if key not in seen:
                seen.add(key)
                ro.append(section)
    
    for segment in bv.segments:
        if segment.readable and not segment.writable and not segment.executable:
            key = (segment.start, segment.end)
            if key not in seen:
                seen.add(key)
                ro.append(segment)

    # Won't remove relocs, exception data, synthetic builtins, etc...  
    # As they will likely not pass our constraints to actually consider some memory as a str

    return ro


def get_data_vars_from_ro_sections(ro) -> list[DataVariable]:
    ro_ranges = [(section.start, section.end) for section in ro]
    
    ro_vars = []
    for (addr, candidate) in bv.data_vars.items():
        if candidate.type.type_class == TypeClass.PointerTypeClass:
            if any(start <= candidate.value < end for start, end in ro_ranges):
                ro_vars.append(candidate)
                # print(f"found candidate {candidate}")
    
    return ro_vars


def read_string_from_mapping(mapping) -> dict[str, str]:
    utf8_strings = {}

    for ptr, length in mapping.items():
        candidate_slice = bv.read(ptr.value, length)

        try:
            decoded = candidate_slice.decode("utf-8")
        except UnicodeDecodeError:
            continue

        utf8_strings[f"0x{ptr.value:x}"] = decoded

    return utf8_strings


def create_mapping_from_data_ref(ro_vars) -> dict[DataVariable, int]:
    lengths = {}

    for var in ro_vars:
        # treat the address following the variable as its length.
        # the length's size is of 8 bytes because it is defined as "usize" in Rust's runtime
        len_addr = var.address + var.type.width

        if (var_at_len_addr := bv.get_data_var_at(len_addr)) is not None and \
           var_at_len_addr.type.type_class != TypeClass.IntegerTypeClass:
            continue

        candidate_len_value = bv.read_int(
            len_addr,
            bv.arch.address_size,
            False,
            bv.arch.endianness
        )

        if candidate_len_value <= 0 or candidate_len_value >= 0x200:
            continue

        lengths[var] = candidate_len_value

    return lengths


def create_mapping_from_code_ref(ro_vars) -> dict[DataVariable, int]:

    lengths = {}

    for var in ro_vars:
        for code_ref in bv.get_code_refs(var.address):

            mlil = code_ref.mlil
            if mlil is None:
                continue

            # The instruction that messes with the string length's is likely a "lea"
            # lea     r8, [rel data_140063dc8]
            # MLIL:  r8_2 = "..."
            if mlil.instr.operation == MediumLevelILOperation.MLIL_SET_VAR or mlil.instr.operation == MediumLevelILOperation.MLIL_SET_VAR_FIELD:
                # print(mlil.instr)
                # At some point, the instructions which follows our "lea" will mov an immediate (the string's length) onto some register/mm
                for instr in code_ref.mlil.il_basic_block:
                    #print(instr)
                    if instr.instr_index < code_ref.mlil.instr_index:
                        continue
                    
                    # Retrieve the actual imm value
                    for operand in instr.detailed_operands:
                        if operand[0] == "src" and isinstance(operand[1], MediumLevelILConst):
                            len_value = candidate_string_slice_len = operand[1].value.value

                            if len_value <= 0 or len_value >= 0x200:
                                continue

                            lengths[var] = len_value
                            break

                    if var in lengths:
                        break
    return lengths


def from_data_xrefs(ro_vars) -> dict[str, str]:
    data_var_mapping = create_mapping_from_data_ref(ro_vars)
    utf8_strings = read_string_from_mapping(data_var_mapping)

    return utf8_strings

"""
    print("From Data:")
    for k, v in utf8_strings.items():
        print(f"{k}: \"{v}\"\n")

    return utf8_strings
"""


def from_code_xrefs(ro_vars) -> dict[str, str]:
    code_var_mapping = create_mapping_from_code_ref(ro_vars)
    utf8_strings = read_string_from_mapping(code_var_mapping)

    return utf8_strings

"""    
    print("From Code:")
    for k, v in utf8_strings.items():
        print(f"{k}: \"{v}\"\n")

    return utf8_strings
"""


def main():
    ro = get_ro_sections_segments()

    if not ro:
        print("No read-only sections found. Exiting...")
        bv.update_analysis()
        return

    ro_vars = get_data_vars_from_ro_sections(ro)

    all_strings = {}
    all_strings.update(from_data_xrefs(ro_vars))
    all_strings.update(from_code_xrefs(ro_vars))

    seen_values = set()
    unique_strings = {}
    
    for addr in sorted(all_strings.keys(), key=lambda x: int(x, 16)):
        val = all_strings[addr]
        if val not in seen_values:
            seen_values.add(val)
            unique_strings[addr] = val

    with open(OUTPUT_FILE, "w", encoding='utf-8') as fp:
        for addr, string in unique_strings.items():
            escaped = string.replace('\\', '\\\\').replace('"', '\\"')
            fp.write(f"{addr}: \"{escaped}\"\n")

    print(f"Retrieved {len(unique_strings)} unique strings written to: {OUTPUT_FILE}")
    bv.update_analysis()


print("Starting rust_strings.py :P")
main()
