import math

DEBUG_MODE = False
# DEBUG_MODE = True

PAGE_SIZE = 32  # Bytes
VIRTUAL_ADDR_SPACE = 32  # KB
PHYSICAL_ADDR_SPACE = 4  # KB
PTE_SIZE = [1, 1]  # in Bytes
PT_SIZE = [32, 32]  # in Bytes
PDBR_HEX = "220"
PDBR = int(PDBR_HEX, 16)
LEVELS = 2
if DEBUG_MODE: print(f"PDBR: {PDBR}")

PAS_FILE_PATH = "./data.txt"
HEX_TO_BIN = '-->'

# Calculate bit lengths
offset_bits = int(math.log2(PAGE_SIZE))
if DEBUG_MODE: print(f"Offset bit length: {offset_bits}")

virtual_addr_size = VIRTUAL_ADDR_SPACE * 1024  # Bytes
virtual_addr_bits = int(math.log2(virtual_addr_size))
if DEBUG_MODE: print(f"Virtual Address bit length: {virtual_addr_bits}")
vpn_bits = virtual_addr_bits - offset_bits
if DEBUG_MODE: print(f"VPN bit length: {vpn_bits}")

physical_addr_size = PHYSICAL_ADDR_SPACE * 1024  # Bytes
physical_addr_bits = int(math.log2(physical_addr_size))
if DEBUG_MODE: print(f"Physical Address bit length: {physical_addr_bits}")
ppn_bits = physical_addr_bits - offset_bits
if DEBUG_MODE: print(f"PPN bit length: {ppn_bits}")

# Convert PTE sizes to bits
pte_bit_sizes = [pte * 8 for pte in PTE_SIZE]
if DEBUG_MODE: print(f"PTE size in bits: {pte_bit_sizes}")
pfn_bit_sizes = [pte_bit - 1 for pte_bit in pte_bit_sizes]
if DEBUG_MODE: print(f"PFN size in bits: {pfn_bit_sizes}")

# Read PAS file
with open(PAS_FILE_PATH) as file:
    content = file.readlines()
    memory_bytes = []

    for line in content:
        if line.strip():
            hex_values = line.split(':')[1].strip().split()
            memory_bytes.extend(int(value, 16) for value in hex_values)

if DEBUG_MODE: print(memory_bytes)

# Function to translate Virtual Address
def translate_virtual_address(va_hex):
    print(f"Virtual Address: 0x{va_hex}")
    va = int(va_hex, 16)
    va_bin = f"{va:0{virtual_addr_bits}b}"
    if DEBUG_MODE: print(f"Virtual address: 0x{va:04x} = 0b{va_bin}")

    # Split into offset and VPN
    offset = int(va_bin[-offset_bits:], 2)
    if DEBUG_MODE: print(f"Offset (PPO): 0b{offset:0{offset_bits}b}")

    vpn = va_bin[:-offset_bits]
    if DEBUG_MODE: print(f"VPN: 0b{vpn}")

    # Extract PTE index from VPN
    pte_index_bits = [int(math.log2(pt_size // pte_size)) for pt_size, pte_size in zip(PT_SIZE, PTE_SIZE)]
    if DEBUG_MODE: print(f"PTE index bit lengths: {pte_index_bits}")
    assert sum(pte_index_bits) == vpn_bits, "PTE index bit lengths mismatch with VPN"

    pte_indices = []
    start_bit = 0
    for level, bits in enumerate(pte_index_bits):
        pte_idx = int(vpn[start_bit:start_bit + bits], 2)
        pte_indices.append(pte_idx)
        start_bit += bits
        if DEBUG_MODE: print(f"Level {level} PTE index: 0b{vpn[start_bit - bits:start_bit]}")

    pt_base = PDBR
    for level in range(LEVELS):
        pte_idx = pte_indices[level]
        pte_value = memory_bytes[pt_base + pte_idx]
        pte_bin = f"{pte_value:0{pte_bit_sizes[level]}b}"
        pte_valid_bit = int(pte_bin[0])
        pfn = int(pte_bin[1:], 2)

        if DEBUG_MODE: print(f"Level {level} PTE value: 0x{pte_value:02x} => 0b{pte_bin} (valid {pte_valid_bit}, PFN 0x{pfn:02x})")

        if pte_valid_bit == 0:
            print("\t" * (level + 1) + HEX_TO_BIN + f"pt[{level}]e index: {pte_idx} (invalid)")
            print("\t" * (level + 2) + HEX_TO_BIN + "Fault: Invalid PTE")
            return

        pt_base = pfn * PT_SIZE[level]

    ppn = pfn
    physical_addr_base = ppn * PAGE_SIZE
    physical_addr = physical_addr_base + offset
    value = memory_bytes[physical_addr]
    print(f"\t" * (LEVELS + 1) + HEX_TO_BIN + f"Physical Address: 0x{physical_addr:04x} = 0b{physical_addr:0{physical_addr_bits}b} => Value: 0x{value:02x}")

# List of virtual addresses to translate
virtual_addresses = [
    "6c74", "6b22", "03df", "69dc", "317a",
    "4546", "2c03", "7fd7", "390e", "748b"
]

for va_hex in virtual_addresses:
    translate_virtual_address(va_hex)
