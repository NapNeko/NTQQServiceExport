from quickScanPe import *
import pefile
from capstone import *
import os
import frida
import sys

napi_disable_functions = ['NodeIKernelNodeMiscService/sendLog']
def find_service_register_calls(pe, offset_qqnt_service, pe_image_base, max_bytes=1024):
    """
    反汇编指定位置的代码，查找 mov rcx, rdi; mov rdx, rsi; call <target> 的指令序列
    返回所有匹配的call目标地址
    """
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.skipdata = True
    code_base = offset_qqnt_service
    code_bytes = pe.get_data(code_base, max_bytes)

    service_registers_function = []
    prev_mov_rcx_rdi = False
    prev_mov_rdx_rsi = False

    for insn in md.disasm(code_bytes, code_base + pe_image_base):
        # 检查retn
        if insn.mnemonic == 'ret' or insn.mnemonic == 'retn':
            break

        # 检查mov rcx, rdi
        if insn.mnemonic == 'mov' and insn.op_str == 'rcx, rdi':
            prev_mov_rcx_rdi = True
            continue

        # 检查mov rdx, rsi
        if prev_mov_rcx_rdi and insn.mnemonic == 'mov' and insn.op_str == 'rdx, rsi':
            prev_mov_rdx_rsi = True
            continue

        # 检查call
        if prev_mov_rcx_rdi and prev_mov_rdx_rsi and insn.mnemonic == 'call':
            # 解析call目标
            if insn.op_str.startswith('0x'):
                call_addr = int(insn.op_str, 16)
            else:
                # 处理相对call
                call_offset = insn.address + insn.size + int(insn.op_str, 0)
                call_addr = call_offset
            service_registers_function.append(call_addr)
            print(f"[result] Found call at 0x{insn.address:x} -> 0x{call_addr:x}")
            # 重置状态，继续查找下一个
            prev_mov_rcx_rdi = False
            prev_mov_rdx_rsi = False
            continue

        # 状态重置
        prev_mov_rcx_rdi = False
        prev_mov_rdx_rsi = False

    return service_registers_function

def read_utf8_string(pe, rva):
    """
    从给定的RVA位置读取UTF-8字符串，直到遇到0字节为止
    """
    string_bytes = bytearray()
    while True:
        byte = pe.get_data(rva, 1)
        if not byte or byte == b'\x00':
            break
        string_bytes.extend(byte)
        rva += 1
    return string_bytes.decode('utf-8', errors='ignore')

def extract_service_info(pe, func_rva, image_base, max_bytes=512):
    """
    提取注册函数中的vtable_address和service_name地址
    返回 (vtable_address, service_name, r8d_imm)
    """
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.skipdata = True
    code_bytes = pe.get_data(func_rva, max_bytes)
    vtable_address = None
    service_name = None
    lea_targets = []
    r8d_imm = None  # 新增

    for insn in md.disasm(code_bytes, func_rva + image_base):
        # 支持
        # lea rdx, [rip+imm]
        # lea rsi, [rip+imm]
        if insn.mnemonic == 'lea' and (insn.op_str.startswith('rdx, [rip + ') or insn.op_str.startswith('rsi, [rip + ')):
            try:
                imm_str = insn.op_str.split('+')[1].strip(' ]')
                imm = int(imm_str, 16) if imm_str.startswith('0x') else int(imm_str)
                target_addr = insn.address + insn.size + imm
                lea_targets.append(target_addr)
            except Exception:
                continue
        # 新增对 mov r8d, imm32 的解析
        if insn.mnemonic == 'mov' and insn.op_str.startswith('r8d, '):
            try:
                imm_str = insn.op_str.split(',')[1].strip()
                r8d_imm = int(imm_str, 16) if imm_str.startswith('0x') else int(imm_str)
            except Exception:
                pass
        # 找到两个call后就可以退出
        if (insn.mnemonic == 'call' or (insn.mnemonic == 'movsq' and 'rep' in insn.prefix)):
            if len(lea_targets) >= 2:
                break
    # 按顺序返回
    if len(lea_targets) >= 2:
        vtable_address = lea_targets[0]
        service_name = lea_targets[1]
    elif len(lea_targets) == 1:
        vtable_address = lea_targets[0]
        service_name = None

    return vtable_address, service_name, r8d_imm

def read_aligned_qword(pe, addr):
    """
    跳过8字节对齐的0字节，读取下一个非零的8字节qword，返回(qword, next_addr)
    如果到达区间末尾或读取失败，返回(None, addr)
    """
    cur_addr = addr
    while True:
        qword_bytes = pe.get_data(cur_addr, 8)
        if not qword_bytes or len(qword_bytes) < 8:
            return None, cur_addr
        qword = int.from_bytes(qword_bytes, 'little')
        if qword != 0:
            return qword, cur_addr + 8
        cur_addr += 8

def read_aligned_utf8_string(pe, addr):
    """
    跳过8字节对齐的0字节，读取下一个非零的8字节qword作为字符串地址，读取字符串
    返回(function_name, next_addr)。如果失败，返回(None, next_addr)
    """
    string_addr, next_addr = read_aligned_qword(pe, addr)
    if not string_addr:
        return None, next_addr
    # 计算RVA
    rva = string_addr - pe.OPTIONAL_HEADER.ImageBase
    function_name = read_utf8_string(pe, rva)
    if not function_name or function_name.strip() == "":
        return None, next_addr
    return function_name, next_addr

pe = pefile.PE("F:\\IDA-Wrapper\\35341\\wrapper.node")
pe_image_base = pe.OPTIONAL_HEADER.ImageBase

# 加载段区
section_rdata_range = get_section_range_rva(pe, '.rdata')
rdata_start, rdata_end = section_rdata_range

section_text_range = get_section_range_rva(pe, '.text')
text_start, text_end = section_text_range

section_data_range = get_section_range_rva(pe, '.data')
data_start, data_end = section_data_range

offset_qqnt_base = search_bytes(pe, rdata_start, rdata_end, b'\x00QQNT\x00') + 0x1
# 搜索QQNT 并定位到字符串头部
if not offset_qqnt_base:
    print("[result] not found")
    exit(0)

print('[debug] offset_qqnt_base: ', hex(offset_qqnt_base))

# QQNT字符串绝对位置
address_qqnt_base = offset_qqnt_base + pe_image_base
print('[debug] offset_qqnt_base_little: ', address_qqnt_base.to_bytes(8, 'little').hex())

# 来到虚表附近
offset_db_qqnt_service = search_bytes(pe, data_start, data_end, address_qqnt_base.to_bytes(8, 'little')) - 0x8
if not offset_db_qqnt_service:
    print("[result] not found")
    exit(0)
print('[debug] offset_db_qqnt_service: ', hex(offset_db_qqnt_service))

# Service注册函数
offset_qqnt_service = int.from_bytes(pe.get_data(offset_db_qqnt_service, 8), 'little') - pe_image_base
print('[debug] offset_qqnt_service: ', hex(offset_qqnt_service))

# 反汇编查找所有注册函数
service_registers_function = find_service_register_calls(pe, offset_qqnt_service, pe_image_base)

if not service_registers_function:
    print("[result] No matching call found")

# 开始解析Service注册函数
# lea     rdx, off_xxxxxxxx or rsi, off_xxxxxxxx
# ...
# call xxxx
# lea     rdx, utf8name 48 8D 15 3D 4D 18 03
# ...
# call xxxxx
# 提取每个注册函数里面的off_xxxxxxxx utf8name的地址
result_dict = {}

for service_register in service_registers_function:
    vtable_address, service_name, descriptor_size = extract_service_info(pe, service_register - pe_image_base, pe_image_base)
    if vtable_address and service_name:
        service_name_rva = service_name - pe_image_base
        service_name_str = read_utf8_string(pe, service_name_rva)
        print(f"[result] service_name: {service_name_str}")
        print(f"[result] vtable_address: {hex(vtable_address)}")
        if descriptor_size is not None:
            print(f"[result] descriptor_size: {hex(descriptor_size)}")
        else:
            descriptor_size = 16 * 8 # napi_property_descriptor properties[16];
            print(f"[result] descriptor_size: {hex(descriptor_size)} (default)")
        # 解析方法表
        cur_addr = vtable_address - pe_image_base
        while True:
            try:
                function_name, next_addr = read_aligned_utf8_string(pe, cur_addr)
                cur_addr = next_addr
                function_addr, next_addr = read_aligned_qword(pe, cur_addr)
                cur_addr = next_addr
                if not function_addr:
                    break
                if not (text_start <= function_addr - pe_image_base < text_end):
                    break
                if descriptor_size and vtable_address + descriptor_size < cur_addr + pe_image_base:
                    break
                if len(function_name) >1 and function_name.find('@') == -1 and function_name.find('$') == -1:
                    print(f"Service: {service_name_str}/{function_name} addr: {hex(function_addr)}")
                    napi_func_name = f"{service_name_str}/{function_name}"
                    if napi_func_name in napi_disable_functions:
                        print(f"[skip] {napi_func_name} is in disable list")
                        continue
                    napi_func_rva = function_addr - pe_image_base
                    result_dict[napi_func_name] = napi_func_rva
            except Exception as e:
                print(f"[error] Exception while parsing method table: {e}")
                break

print("[result] All services and functions:")
output_lines = ['const target_func_list = {']
items = list(result_dict.items())
for idx, (k, v) in enumerate(items):
    comma = ',' if idx < len(items) - 1 else ''
    output_lines.append(f"    '{k}': {hex(v)}{comma}")
output_lines.append('};')
output_text = '\n'.join(output_lines)
print(output_text)

template = ""
with open('template.js', 'r', encoding='utf-8') as f:
    template = f.read()

if os.path.exists('frida-generate.js'):
    os.remove('frida-generate.js')

with open('frida-generate.js', 'w', encoding='utf-8') as f:
    f.write(output_text)
    f.write(template)

print("[result] frida-generate.js has been generated successfully.")

def on_message(message, data):
    print(message)

def main():
    pid = frida.spawn(program="D:\\AppD\\QQNT\\QQ.exe", argv=["--enable-logging"])
    session = frida.attach(pid)
    frida.resume(pid)
    print(f"Attached to process {pid}")

    while True:
        with open("frida-generate.js", encoding="utf-8") as f:
            script = session.create_script(f.read())
            script.on("message", on_message)
            script.load()
        sys.stdin.readline()
main()
