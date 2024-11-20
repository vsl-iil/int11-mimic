from capstone import *
from capstone.x86 import *
import pefile
import sys
import logging
import re
import json

ImageBase = 0x400000 # одинаковый для всех исполняемых PE
                     # https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32

# InternetOpenW
# 6a 00           PUSH       0x0
# 6a 00           PUSH       0x0
# 6a 00           PUSH       0x0
# 6a 01           PUSH       0x1
# 68 20 45        PUSH       u_Mozilla/5.0_(Windows_NT_10.0;_Wi_00404520      = u"Mozilla/5.0 (Windows NT 10.0
# 40 00
# ff 15 9c        CALL       dword ptr [->WININET.DLL::InternetOpenW]         = 00004b08
# 40 40 00

# c3              RET


pattern_internetopenw = (
	b"\x6a\x00"
	b"\x6a\x00"
	b"\x6a\x00"
	b"\x6a\x01"
	b"\x68.{2,5}"
    b"\xff.{2,5}"
	b"\xc3"
)


# InternetConnect
# e8 24 e5        CALL       InitInternetConnection                           undefined InitInternetConnection
# ff ff
# 85 c0           TEST       hInternet,hInternet
# 74 f7           JZ         LAB_00403487
# 6a 50           PUSH       80
# 68 20 47        PUSH       u_65.20.106.109_00404720                         = u"65.20.106.109"
# 40 00
# 50              PUSH       hInternet
# e8 f3 e4        CALL       InternetConnect                                  undefined InternetConnect(undefi
# ff ff
pattern_internetconnect = (
	b"\xe8.{2,5}"
    b"\x85."
    b"\x74."
    b"\x6a."
	b"\x68.{2,5}"
	b"\x50"
	b"\xe8.{2,5}"
)

def get_text_section(pe, entry):
    for section in pe.sections:
        if section.contains_rva(entry):
            return section

    return None

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True

def get_useragent_addr(data):
    r = re.search(pattern_internetopenw, data)
    span_start = r.span()[0]
    span_end = r.span()[1]

    dataspan = data[span_start:span_end]
    length = span_end-span_start+1

    for insn in md.disasm(dataspan, length):
        if insn.mnemonic == 'push' and insn.bytes[0] == 0x68 and insn.operands[0].type == X86_OP_IMM:
            return insn.operands[0].value.imm

def get_internetconnect(data):
    #print(pattern_internetconnect)
    r = re.search(pattern_internetconnect, data)
    #print(data)
    span_start = r.span()[0]
    span_end = r.span()[1]

    dataspan = data[span_start:span_end]
    length = span_end-span_start+1

    port = 0
    ip_ptr = 0
    for insn in md.disasm(dataspan, length):
        if insn.mnemonic == 'push' and insn.operands[0].type == X86_OP_IMM:
            if insn.bytes[0] == 0x6a: 
                port = insn.operands[0].value.imm
            elif insn.bytes[0] == 0x68:
                ip_ptr = insn.operands[0].value.imm

    return (ip_ptr, port)


def trunc_utf16(bytestr):
    prev0 = False
    counter = 0
    for b in bytestr:
        if prev0:
            if b == 0:
                return bytestr[:counter+2].decode('utf-16-le')[:-1]
            else:
                prev0 = False
        else:
            prev0 = (b == 0)

        counter += 1
    return None


def main():
    logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s')
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)

    if len(sys.argv) < 2:
        print(f"Использование: {sys.argv[0]} <имя файла>.exe")
        exit(-1)

    path = sys.argv[1]
    pe = pefile.PE(sys.argv[1], fast_load=True)
    addr_entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint

    logger.debug("Точка входа: 0x%X", addr_entry)

    section = pe.get_section_by_rva(addr_entry)

    if not section:
        logger.error("Не найдена секция, содержащая виртуальный адрес 0x%X", addr_entry)
        exit(-1)

    data = pe.get_memory_mapped_image()

    useragent_addr = get_useragent_addr(data)
    useragent = trunc_utf16(pe.get_data(useragent_addr-ImageBase))
    logger.info("Useragent = %s", useragent)

    ip_ptr, port = get_internetconnect(data)
    ip = trunc_utf16(pe.get_data(ip_ptr-ImageBase))
    logger.info("IP: %s | Порт: %d", ip, port)

    with open('config.json', 'w') as f:
        cfg = {
                "useragent": useragent,
                "ipaddr": ip,
                "port": port
        }

        json.dump(cfg, f)
        logger.info("Данные для репликатора записаны в config.json")


if __name__ == "__main__":
    main()
