# Fortigate gadgets

## Generate license

In "gen_license" folder.

The "gen_license_old.py" script is used for older versions. eg: Fortigate VM64 v7.4.1

The "gen_license_new.py" script is used for newer versions. eg: Fortigate VM64 v7.4.3

### Usage

For older versions, executing the command `python3 gen_license_old.py` will generate the `License.lic` file. Just import the file into the system.

For newer versions, you need to unpack the `init` file first and then execute the `python3 patcher.py init` command to patch the file. After starting the system, run the `python3 gen_license_new.py` command and import the generated `License.lic` file to the system.

For newer versions, you also need to patch the `flatkc` file to disable rootfs checks. Please see https://wzt.ac.cn/2024/04/02/fortigate_debug_env2/ for more details.
