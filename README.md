# FortiGate gadgets

The tools in this repository are intended for security research purposes only and should not be used in production environments.

## License

Note: Only tested on FortiGate VM appliance. 

The "license_old.py" script is used for older versions. eg: FortiGate VM64 v7.4.1

The "license_new.py" script is used for newer versions. eg: FortiGate VM64 v7.4.3

### Base license

For older versions, executing the command `python3 license_old.py` will generate the `License.lic` file. Just import the file into the system.

For newer versions, you need to patch `flatkc` and `init` first. Please follow the steps below.

```
1. Import the ovf template and start the system. Wait for the system to complete initialization
2. Shut down the VM and remove the first vm disk (2GB)
3. Install the vm disk on another Linux system
4. Mount the root partition (FORTIOS) and extract the "flatkc" and "rootfs.gz" files, make sure to backup them
5. Run command: 'python3 decrypt.py -f rootfs.gz -k flatkc' to decrypt the rootfs.gz file
6. Uncompress the rootfs.gz and the bin.tar.xz files, you need to be root when doing this
       gzip -d ./dec.gz
       mkdir rootfs
       cd rootfs && mv ../dec ./
       sudo su
       cpio -idmv < ./dec
       rm -rf ./dec
       xz -d ./bin.tar.xz && tar -xvf ./bin.tar && rm -rf ./bin.tar
       cd .. && mv ./rootfs/bin/init ./
7. Run command: 'python3 patch.py init' to patch the init file
8. You can add other files (busybox etc) if you want. Then re-compress the rootfs.gz
       chmod 755 ./init.patched && mv ./init.patched ./rootfs/bin/init
       cd rootfs
       tar -cvf bin.tar bin && xz bin.tar && rm -rf bin
       find . | cpio -H newc -o > ../rootfs.raw && cd ..
       cat ./rootfs.raw | gzip > rootfs.gz
9. Run command: 'python3 patch.py flatkc' to patch the flatkc file
10. Overwrite rootfs.gz and flatkc.patched to the vm disk
11. Uninstall the vm disk from Linux system and install it to the original system
12. Boot the system
```

After starting the system, run the `python3 license_new.py` command and import the generated `License.lic` file to the system.

Note: You may need to change the network adapter IP address again after restarting the system

Please see https://wzt.ac.cn/2024/04/02/fortigate_debug_env2/ for more details.

### VDOM license

You need to install libssl-dev first.

Compile: `gcc vdom.c -o vdom -lssl -lcrypto -lz`

Run: `./vdom FGVMPG0000000000 15`

Import the license: `execute upd-vd-license xxx`

If you see `Error: VDOM number (xxx) exceeds limit for this model` then your base license does not support too many vdoms.
