import os
import struct
import dis
import argparse
import hashlib

class BinaryAnalyzer:
    def __init__(self, file_path):
        self.file_path = file_path
        self.headers = {}

    def read_headers(self):
        with open(self.file_path, 'rb') as f:
            self.headers['Magic Number'] = f.read(4)
            self.headers['File Size'] = struct.unpack('<I', f.read(4))[0]
            self.headers['Reserved'] = struct.unpack('<I', f.read(4))[0]
            self.headers['Data Offset'] = struct.unpack('<I', f.read(4))[0]
        return self.headers

    def calculate_hash(self, algorithm='md5'):
        hash_func = hashlib.new(algorithm)
        with open(self.file_path, 'rb') as f:
            while chunk := f.read(8192):
                hash_func.update(chunk)
        return hash_func.hexdigest()

class Disassembler:
    def __init__(self, bytecode):
        self.bytecode = bytecode

    def disassemble(self):
        return dis.dis(self.bytecode)

class PEHeaderParser:
    def __init__(self, file_path):
        self.file_path = file_path
        self.pe_headers = {}

    def parse_pe_header(self):
        with open(self.file_path, 'rb') as f:
            f.seek(0x3C)
            pe_offset = struct.unpack('<I', f.read(4))[0]
            f.seek(pe_offset)
            self.pe_headers['Signature'] = f.read(4)
            self.pe_headers['Machine'] = struct.unpack('<H', f.read(2))[0]
            self.pe_headers['NumberOfSections'] = struct.unpack('<H', f.read(2))[0]
            f.seek(pe_offset + 0x18)
            self.pe_headers['SizeOfOptionalHeader'] = struct.unpack('<H', f.read(2))[0]
        return self.pe_headers

class HexDumper:
    def __init__(self, file_path):
        self.file_path = file_path

    def dump_hex(self):
        with open(self.file_path, 'rb') as f:
            offset = 0
            while byte := f.read(16):
                hex_values = ' '.join(f'{b:02x}' for b in byte)
                ascii_repr = ''.join((chr(b) if 32 <= b <= 126 else '.') for b in byte)
                print(f'{offset:08x}  {hex_values:<39}  |{ascii_repr}|')
                offset += 16

class FileManipulator:
    def __init__(self, file_path):
        self.file_path = file_path

    def overwrite_bytes(self, offset, data):
        with open(self.file_path, 'r+b') as f:
            f.seek(offset)
            f.write(data)

    def append_data(self, data):
        with open(self.file_path, 'ab') as f:
            f.write(data)

def main():
    parser = argparse.ArgumentParser(description='Reverse Engineering Tools Suite')
    parser.add_argument('action', choices=['analyze', 'disassemble', 'parse', 'dump', 'manipulate'], 
                        help='Action to perform')
    parser.add_argument('file', help='File to operate on')
    parser.add_argument('--hash', help='Hashing algorithm to use', default='md5')
    parser.add_argument('--offset', type=int, help='Offset for byte manipulation')
    parser.add_argument('--data', help='Data to write or append')

    args = parser.parse_args()

    if args.action == 'analyze':
        analyzer = BinaryAnalyzer(args.file)
        headers = analyzer.read_headers()
        file_hash = analyzer.calculate_hash(args.hash)
        print('Headers:', headers)
        print('File Hash:', file_hash)

    elif args.action == 'disassemble':
        with open(args.file, 'rb') as f:
            bytecode = f.read()
            disassembler = Disassembler(bytecode)
            disassembler.disassemble()

    elif args.action == 'parse':
        parser = PEHeaderParser(args.file)
        headers = parser.parse_pe_header()
        print('PE Headers:', headers)

    elif args.action == 'dump':
        dumper = HexDumper(args.file)
        dumper.dump_hex()

    elif args.action == 'manipulate':
        if args.data is None or args.offset is None:
            print("Both --data and --offset must be provided for manipulation.")
            return
        manipulator = FileManipulator(args.file)
        data_bytes = bytes.fromhex(args.data)
        manipulator.overwrite_bytes(args.offset, data_bytes)
        print(f'Bytes overwritten at offset {args.offset}')

if __name__ == "__main__":
    main()