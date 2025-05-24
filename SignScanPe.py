from quickScanPe import *
import pefile
from capstone import *

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
    返回 (vtable_address, service_name)
    """
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.skipdata = True
    code_bytes = pe.get_data(func_rva, max_bytes)
    vtable_address = None
    service_name = None
    lea_targets = []

    for insn in md.disasm(code_bytes, func_rva + image_base):
        # 支持
        # lea rdx, [rip+imm]
        # lea rsi, [rip+imm]
        # movaps  xmm0, xmmword ptr cs:off_183ABB920
        if insn.mnemonic == 'lea' and (insn.op_str.startswith('rdx, [rip + ') or insn.op_str.startswith('rsi, [rip + ')):
            # 提取偏移
            try:
                imm_str = insn.op_str.split('+')[1].strip(' ]')
                imm = int(imm_str, 16) if imm_str.startswith('0x') else int(imm_str)
                target_addr = insn.address + insn.size + imm
                lea_targets.append(target_addr)
            except Exception:
                continue
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

    return vtable_address, service_name

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


for service_register in service_registers_function:
    vtable_address, service_name = extract_service_info(pe, service_register - pe_image_base, pe_image_base)
    if vtable_address and service_name:
        service_name_rva = service_name - pe_image_base
        service_name_str = read_utf8_string(pe, service_name_rva)
        print(f"[result] service_name: {service_name_str}")