data_size = 8 # qword
start_addr = 0x180162ec8
end_addr = 0x180162ee0 + data_size

# [ScriptingProvider] (<type: immutable:PointerTypeClass 'int64_t const*'>, '')
# get 1st element, that is, 'int64_t const*'
new_type = bv.parse_type_string("int64_t const*")[0]

for addr in range(start_addr, end_addr, data_size):
    var = bv.get_data_var_at(addr)
    if var:
        type_str = var.type.get_string()
        # We are only instered in data that is marked as 'void*', for example:
        #   void* data_180162ec8 = 0xa93a47807b5b0961
        #   void* data_180162ed0 = 0xa93a47807b5b0848
        #   void* data_180162ed8 = 0x5b13a269118c3dd7
        #   void* data_180162ee0 = 0x5b13a269118c3d6e
        if type_str == 'void*':

            # Change previous 'void*' var to 'int64_t const*', enabling 
            # constant folding/propagation analysis by the disassembler
            bv.define_user_data_var(addr, new_type)

bv.update_analysis_and_wait()
