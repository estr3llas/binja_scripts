import os
from binaryninja.warp import WarpContainer, WarpFunction, WarpTarget

functions_addresses: list = [
    0x14001fab0,
    0x14001e220,
    0x14001e440,
    0x14001e660,
    # ...
]


def get_objects_for_root_functions(function_addresses: list):
    objects = []
    for i in function_addresses:
        found = bv.get_function_at(i)
        if found:
            objects.append(found)

    return objects


def get_all_callees_recursive(func, visited=None):
    if visited is None:
        visited = set()
    
    if func in visited:
        return visited

    if func.symbol and not func.symbol.auto:
        visited.add(func)
    
    for callee in func.callees:
        get_all_callees_recursive(callee, visited)
    
    return visited

# https://github.com/Vector35/binaryninja-api/blob/dev/plugins/warp/examples/create_signatures.py
def main():
    container = WarpContainer.by_name("User")
    output_file = f"{binaryninja.user_directory()}/signatures/{os.path.basename(bv.file.filename)}.warp"

    target = WarpTarget(bv.platform)    
    source = container.add_source(str(output_file))
    
    root_funcs = get_objects_for_root_functions(functions_addresses)
    to_be_warped = set()
    for root_func in root_funcs:
        callees = get_all_callees_recursive(root_func)
        to_be_warped.update(callees)

    warp_functions = [WarpFunction(func) for func in to_be_warped]
    container.add_functions(target, source, warp_functions)
    container.commit_source(source)
    print(f"committed {len(warp_functions)} functions to {output_file}")

print("WARPing Recursively :^)!")
main()
