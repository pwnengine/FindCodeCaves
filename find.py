import pefile

def find_cave(pe, min_cave_size):
  print('Attemping to find a code cave for payload.')
  # Traverse the sections in the pe
  for section in pe.sections:
    # Make sure the section is usable
    if section.SizeOfRawData == 0:
      continue
    if not (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']):
      continue
    if not (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE']):
      continue
        
    data = section.get_data()
    count = 0
    # Count the bytes null bytes in the section until we have a good sized cave for the payload
    for position, byte in enumerate(data):
      if byte == 0x00:
        count += 1
      else:
        if count >= min_cave_size:
          cave_rva = section.VirtualAddress + position - count
          # Convert RVA to file offset
          cave_offset = pe.get_offset_from_rva(cave_rva)
          print(f"Found code cave at RVA: 0x{cave_rva:X}, File Offset: 0x{cave_offset:X}")
          return cave_rva, cave_offset
        count = 0
    # Check if cave is at the end of section
    if count >= min_cave_size:
        cave_rva = section.VirtualAddress + len(data) - count
        cave_offset = pe.get_offset_from_rva(cave_rva)
        print(f"Found code cave at RVA: 0x{cave_rva:X}, File Offset: 0x{cave_offset:X}")
        return cave_rva, cave_offset
  return 0, 0

if __name__ == '__main__':
  binary = input('Enter the path to the binary: ')
  size = input('Enter the minimum cave size: ')
  pe = pefile.PE(binary)
  find_cave(pe, size)
