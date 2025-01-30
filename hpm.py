import ctypes
import time
import json
import argparse
import os
from signer import RSASigner
import tempfile
import hashlib


HPMFWUPG_IMAGE_SIGNATURE = "PICMGFWU"
HPMFWUPG_IMAGE_SIGNATURE_LENGTH = 8
HPMFWUPG_MANUFACTURER_ID_LENGTH = 3
HPMFWUPG_FIRMWARE_VERSION_LENGTH = 6
HPMFWUPG_DESCRIPTION_LENGTH = 21
HPMFWUPG_OEM_SIGNATURE = "OEM"
HPMFWUPG_OEM_SIGNATURE_LENGTH = 4
HPMFWUPG_OEM_CHARS_LENGTH = 5

HPMFWUPG_SIGNATURE_LENGTH = 256
HPMFWUPG_MAGIC_WORD_LENGTH = 8
HPMFWUPG_MD5_CHECKSUM_LENGTH = 16

uint8_t = ctypes.c_uint8
uint16_t = ctypes.c_uint16
uint32_t = ctypes.c_uint32

class Header(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("signature", uint8_t * HPMFWUPG_IMAGE_SIGNATURE_LENGTH),
        ("format_version", uint8_t),
        ("device_id", uint8_t),
        ("manufacturer_id", uint8_t * HPMFWUPG_MANUFACTURER_ID_LENGTH),
        ("prodcut_id", uint16_t),
        ("time_stamp", uint32_t),
        ("image_capabilities", uint8_t),
        ("component_bitmask", uint8_t),
        ("selftest_timeout", uint8_t),
        ("rollback_timeout", uint8_t),
        ("inaccessibility_timeout", uint8_t),
        ("earliest_compat_rev", uint16_t),
        ("fw_version", uint8_t * HPMFWUPG_FIRMWARE_VERSION_LENGTH),
        ("oem_data_length", uint16_t),
        ("img_hdr_check", uint8_t)
        ]
    def print_header(self):
        print("signature: ", "".join([chr(x) for x in self.signature]))
        print("format_version: ", hex(self.format_version))
        print("device_id: ", hex(self.device_id))
        print("manufacturer_id: ", "".join([chr(x) for x in self.manufacturer_id]))
        print("prodcut_id: ", hex(self.prodcut_id))
        print("time_stamp: ", hex(self.time_stamp))
        print("image_capabilities: ", hex(self.image_capabilities))
        print("component_bitmask: ", hex(self.component_bitmask))
        print("selftest_timeout: ", hex(self.selftest_timeout))
        print("rollback_timeout: ", hex(self.rollback_timeout))
        print("inaccessibility_timeout: ", hex(self.inaccessibility_timeout))
        print("earliest_compat_rev: ", hex(self.earliest_compat_rev))
        print("fw_version: ", "".join([chr(x) for x in self.fw_version]))
        print("oem_data_length: ", hex(self.oem_data_length))
        print("img_hdr_check: ", hex(self.img_hdr_check))

class UpgradeActionRecord(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("upgrade_action", uint8_t),
        ("components", uint8_t),
        ("header_checksum", uint8_t),
        ("fw_version", uint8_t * HPMFWUPG_FIRMWARE_VERSION_LENGTH),
        ("fw_description", uint8_t * HPMFWUPG_DESCRIPTION_LENGTH),
        ("fw_length", uint32_t)
    ]
    def print_upgrade_action(self):
        print("upgrade_action: ", hex(self.upgrade_action))
        print("components: ", hex(self.components))
        print("header_checksum: ", hex(self.header_checksum))
        print("fw_version: ", "".join([chr(x) for x in self.fw_version]))
        print("fw_description: ", "".join([chr(x) for x in self.fw_description]))
        print("fw_length: ", hex(self.fw_length))

class OEMData(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("signature", uint8_t * HPMFWUPG_OEM_SIGNATURE_LENGTH),
        ("section_flashing", uint32_t),
        ("signed_hash_support", uint8_t),
        ("hash_length", uint16_t),
        ("reserved", uint8_t * HPMFWUPG_OEM_CHARS_LENGTH),
    ]
    def print_oem_data(self):
        print("signature: ", "".join([chr(x) for x in self.signature]))
        print("section_flashing: ", hex(self.section_flashing))
        print("signed_hash_support: ", hex(self.signed_hash_support))
        print("hash_length: ", hex(self.hash_length))
        print("reserved: ", "".join([chr(x) for x in self.reserved]))

# the number of seconds since the epoch (1/1/1970), least significant byte first
def get_time_stamp():
    return int(time.time())

def get_byte_for_zero_checksum(byte_array):
    checksum = 0
    for i in range(len(byte_array)):
        checksum += byte_array[i]
    print("checksum: ", hex(checksum))
    zero_checksum = ((checksum & 0xFF) ^ 0xFF) + 1
    print("zero_checksum: ", hex(zero_checksum))
    return zero_checksum

def struct_to_byte_array(struct):
    return bytearray( (uint8_t* ctypes.sizeof(struct)).from_buffer(struct) )

def generate_hpm_img():

    # parse command line arguments
    parser = argparse.ArgumentParser(description='Generate HPM image header')
    parser.add_argument('-f', '--file', help='JSON file containing HPM header data')
    parser.add_argument('-i', '--input', help='Input file name', required=True)
    parser.add_argument('-o', '--output', help='Output file name', required=True)   
    parser.add_argument('-v', '--version', help='You must input firmware version', required=True)
    parser.add_argument('--key', help='Path to the private key')
    parser.add_argument('--vault-key', help='Path to the vault key')
    parser.add_argument('-t', '--target', help='Taregt could be CPLD or BIOS', required=True)
    parser.add_argument('-p', '--passphrase', help='Passphrase for the private key')
    args = parser.parse_args()

    bin_image_path = args.input
    hpm_image_path = args.output
    image_type = args.target.upper()

    if args.passphrase:
        passphrase = args.passphrase
    else:
        passphrase = None
    
    hash_type = 'sha256'

    if args.key:
        signer = RSASigner(args.key, passphrase, hash_type)
    elif args.vault_key:
        pass
    else:
        print("Private key is required")
        exit(1)

    pub_pem = signer.get_public_key_pem()
    
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(pub_pem)

    with open(bin_image_path, 'rb') as f:
        bin_image = f.read()

    sig = signer.sign(bin_image)

    with open('signature.bin', 'wb') as f:
        f.write(sig)

    if args.version and args.version.startswith("0x"):
        fw_version = int(args.version, 16)
    else:
        fw_version = int(args.version)
   
    if image_type == "CPLD":
        component_bitmask = 0x20
    elif image_type == "BIOS":
        component_bitmask = 0x04
    else:
        print("Invalid target")
        exit(1)

    with open('hpm_data.json', 'r') as f:
        data = json.load(f)


    # generate header
    header = Header()
    header.signature = (uint8_t * HPMFWUPG_IMAGE_SIGNATURE_LENGTH)(*(HPMFWUPG_IMAGE_SIGNATURE.encode('ascii')))
    header.format_version = int(data['HPMHeader']['FormatVersion'], 16)
    header.device_id = int(data['HPMHeader']['DeviceID'], 16)
    header.manufacturer_id = (uint8_t * HPMFWUPG_MANUFACTURER_ID_LENGTH)(int(data['HPMHeader']['ManufacturerID'], 16))
    header.prodcut_id = int(data['HPMHeader']['ProductID'], 16)
    header.time_stamp = uint32_t(get_time_stamp())
    header.image_capabilities = int(data['HPMHeader']['ImageCapabilities'], 16)
    header.component_bitmask = component_bitmask
    header.selftest_timeout = int(data['HPMHeader']['SelfTestTimeout'], 16)
    header.rollback_timeout = int(data['HPMHeader']['RollbackTimeout'], 16)
    header.inaccessibility_timeout = int(data['HPMHeader']['InaccessibilityTimeout'], 16)
    header.earliest_compat_rev = int(data['HPMHeader']['EarliestCompatRev'], 16)
    header.fw_version = (uint8_t * HPMFWUPG_FIRMWARE_VERSION_LENGTH)(*(data['HPMHeader']['FirmwareRevision'].encode('ascii')))
    header.oem_data_length = int(data['HPMHeader']['OEMDataLength'], 16)
    header.img_hdr_check = 0
    tmp = (uint8_t * ctypes.sizeof(header)).from_buffer(header)
    header.img_hdr_check = get_byte_for_zero_checksum(tmp)
    header.print_header()

    # generate upgrade action
    upgrade_action = UpgradeActionRecord()
    upgrade_action.upgrade_action = int(data['UpgradeRecord']['UpgradeAction'], 16)
    upgrade_action.components = component_bitmask
    upgrade_action.header_checksum = 0
    tmp = (uint8_t * ctypes.sizeof(upgrade_action)).from_buffer(upgrade_action)
    upgrade_action.header_checksum = get_byte_for_zero_checksum(tmp)
    upgrade_action.fw_version = (uint8_t * HPMFWUPG_FIRMWARE_VERSION_LENGTH)(fw_version) 
    upgrade_action.fw_description = (uint8_t * HPMFWUPG_DESCRIPTION_LENGTH)(*(image_type.encode('ascii')))
    # payload size is the size of the image plus the 256B signature, 8B magic word, and 16B MD5 checksum
    upgrade_action.fw_length = uint32_t(os.path.getsize(bin_image_path) +
                                        HPMFWUPG_SIGNATURE_LENGTH + 
                                        HPMFWUPG_MAGIC_WORD_LENGTH +
                                        HPMFWUPG_MD5_CHECKSUM_LENGTH)
    upgrade_action.print_upgrade_action()
    
    # generate oem data
    oem_data = OEMData()
    oem_data.signature = (uint8_t * HPMFWUPG_OEM_SIGNATURE_LENGTH)(*(HPMFWUPG_OEM_SIGNATURE.encode('ascii')))
    oem_data.section_flashing = int(data['OEMData']['SectionFlashing'], 16)
    oem_data.signed_hash_support = int(data['OEMData']['SignedHashSupported'], 16)
    oem_data.hash_length = 0x0108 # 256 bytes signature + 8 bytes magic word
    oem_data.reserved = (uint8_t * HPMFWUPG_OEM_CHARS_LENGTH)(int(data['OEMData']['Reserved'], 16))
    oem_data.print_oem_data()

    # join all the data together
    header_data = struct_to_byte_array(header) + struct_to_byte_array(upgrade_action) + struct_to_byte_array(oem_data)

    # define magic word
    magic_word = (uint8_t * HPMFWUPG_MAGIC_WORD_LENGTH)(*(B'\xEF\xBE\xAD\xDE\xEF\xBE\xAD\xDE'))

    # calculate the MD5 checksum for the header + bin image + signature + magic word
    md5sum_data = header_data + bin_image + sig + magic_word
    md5_chksum = (uint8_t * HPMFWUPG_MD5_CHECKSUM_LENGTH)(*(hashlib.md5(md5sum_data).digest()))

    # write output image to the file
    with open(hpm_image_path, 'wb') as f:
        f.write(header_data)
        f.write(bin_image)
        f.write(sig)
        f.write(magic_word)
        f.write(md5_chksum)
    
    print("HPM file is generated successfully")

# add main function to all generate_hpm_img_header() from being called when imported
if __name__ == "__main__":
    generate_hpm_img()




