# HPM Signing

## Overview
HPM Signing is a project designed to facilitate the implementation of Hardware Platform Management (HPM.1, the IPM Controller Firmware Upgrade specification). This tool ensures the integrity and authenticity of firmware through a secure signing process.

## Features
- Scripts to generate a siging key pair
- Scripts to sign BIOS/CPLD
This repository includes scripts to generate binary images following the HPM.1 specification. The HPM.1 specification is a standard for hardware platform management, particularly for IPM (Intelligent Platform Management) controllers.
For more information on the HPM.1 specification, you can refer to the following links:
- [Hardware Platform Management Overview](https://www.picmg.org/openstandards/hardware-platform-management/)
- [HPM.1 IPM Controller Firmware Upgrade Specification](https://www.picmg.org/product/hardware-platform-management-ipm-controller-firmware-upgrade-specification/)

## Usage
To use the HPM Signing tool, follow these steps:

1. Create a RSA key pair:
    ```sh
    python3 keys.py
    ```
    A key pair private_key.pem and public_key.pem will be generated.
2. For demo purpose, create a binary file using dd:
    ```sh
    dd if=/dev/random of=dummy.bin bs=4M count=1
    ```
    Feel free to skip this step, if you have a binary file to be signed.
3. Check hpm_data.json file and change the value if necessary.
4. Put everything together. Assume we have a BIOS binary dummy.bin with version 0x86:
    ```sh
    sudo python3 hpm.py -i dummy2.bin -o out_file.hpm --key private_key.pem -t BIOS -v 86 -f hpm_data.json
    ```
    The final HPM file out_file.hpm will be generated.

## Contact
For any questions or feedback, please contact [Jim Yuan](mailto:zheng3@msn.com).
