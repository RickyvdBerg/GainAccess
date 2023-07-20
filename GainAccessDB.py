import struct
import sys

MDB_MAX_SIZE = 4096
JET3, JET4, ACCDB2007, ACCDB2010 = 0, 1, 0x02, 0x0103

JET3_KEY = [0x86,0xfb,0xec,0x37,0x5d,0x44,0x9c,0xfa,0xc6,0x5e,0x28,0xe6,0x13,0xb6,0x8a,0x60,0x54,0x94]
JET4_KEY = [0x6aba,0x37ec,0xd561,0xfa9c,0xcffa,0xe628,0x272f,0x608a,0x0568,0x367b,0xe3c9,0xb1df,0x654b,0x4313,0x3ef3,0x33b1,0xf008,0x5b79,0x24ae,0x2a7c]

def read_mdb(file_path, page_size):
    try:
        with open(file_path, 'rb') as file:
            return file.read(page_size)
    except IOError:
        sys.exit(f"ERROR: could not open or read {file_path}")

def process_mdb(buffer, file_path):
    version = struct.unpack_from("<i", buffer, 0x14)[0]
    version_map = {
        JET3: "JET 3",
        JET4: "JET 4",
        ACCDB2007: "AccessDB 2007",
        ACCDB2010: "AccessDB 2010"
    }
    
    if version not in version_map:
        sys.exit(f"ERROR: Unknown version: {hex(version)}")

    print(f"File: {file_path} | {version_map[version]}")

    password = bytearray(40)
    if version == JET3:
        password[:20] = buffer[0x42:0x62]
        for i in range(18):
            password[i] ^= JET3_KEY[i]
    elif version == JET4:
        password[:40] = buffer[0x42:0x82]
        magic = struct.unpack_from("<h", buffer, 0x66)[0]
        magic ^= JET4_KEY[18]
        for i in range(18):
            val = password[i*2] | password[i*2+1]<<8
            val ^= JET4_KEY[i]
            if val > 255:
                val ^= magic
            password[i] = val & 0xFF

    print(f"Password: {password[:18].decode(errors='ignore')}")

if len(sys.argv) < 2:
    sys.exit("Missing: file")

print("== GainAccessDB ==")
print("Tool used to retrieve passwords from supported access DB's\n")
process_mdb(read_mdb(sys.argv[1], MDB_MAX_SIZE), sys.argv[1])
