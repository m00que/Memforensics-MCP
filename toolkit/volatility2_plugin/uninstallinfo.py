# pylint: disable-msg=C0111

import volatility.plugins.registry.registryapi as registryapi
import volatility.win32.hive as hivemod
import volatility.win32.rawreg as rawreg
import volatility.debug as debug
import volatility.utils as utils
import volatility.plugins.registry.hivelist as hivelist

def vol(k):
    return bool(k.obj_offset & 0x80000000)

class UninstallInfo(hivelist.HiveList):
    """Extract installed software info from Uninstall registry key"""

    meta_info = {
        'author': 'Dave Lassalle',
        'copyright': 'Copyright (c) 2014 Dave Lassalle',
        'contact': 'dave@superponible.com',
        'license': 'GNU General Public License 2.0 or later',
        'url': 'http://superponible.com/',
        'os': 'WIN_32_XP_SP3',
        'version': '1.0',
        'optimization': 'Tokeii',
    }

    def __init__(self, config, *args, **kwargs):
        super(UninstallInfo, self).__init__(config, *args, **kwargs)
        config.add_option('HIVE-OFFSET', short_option='o',
                          help='SOFTWARE Hive offset (virtual)', type='int')

    def hive_name(self, hive):
        return (hive.FileFullPath.v() or hive.FileUserName.v() or 
                hive.HiveRootPath.v() or "[no name]")

    def calculate(self):
        addr_space = utils.load_as(self._config)
        regapi = registryapi.RegistryApi(self._config)

        software_hive = "SOFTWARE"
        uninstall = "Microsoft\\Windows\\CurrentVersion\\Uninstall"

        hive_offsets = []

        if self._config.HIVE_OFFSET:
            hive_offsets = [("User Specified", self._config.HIVE_OFFSET)]
        else:
            for h in hivelist.HiveList.calculate(self):
                hive_name = self.hive_name(h)
                if software_hive in hive_name:
                    hive_offsets.append((hive_name, h.obj_offset))

        hive_offsets = set(hive_offsets)

        for name, hoff in hive_offsets:
            h = hivemod.HiveAddressSpace(addr_space, self._config, hoff)
            root = rawreg.get_root(h)
            if not root:
                if self._config.HIVE_OFFSET:
                    debug.error("Unable to find root key. Is the hive offset correct?")
                continue

            uninstall_key = rawreg.open_key(root, uninstall.split('\\'))
            if uninstall_key:
                yield name, uninstall_key
            else:
                outfd.write("The requested key could not be found in the hive(s) searched\n")

    def voltext(self, key):
        return "(V)" if vol(key) else "(S)"

    def render_text(self, outfd, data):
        print_values = {5: 'InstallSource', 6: 'InstallLocation', 3: 'Publisher',
                        1: 'DisplayName', 2: 'DisplayVersion', 4: 'InstallDate'}
        outfd.write("Legend: (S) = Stable   (V) = Volatile\n\n")
        keyfound = False

        for reg, key in data:
            if key:
                keyfound = True
                outfd.write("----------------------------\n")
                outfd.write("Registry: {0}\n".format(reg))
                outfd.write("Key name: {0} {1:3s}\n".format(key.Name, self.voltext(key)))
                outfd.write("Last updated: {0}\n\n".format(key.LastWriteTime))
                outfd.write("Subkeys:\n")

                for s in rawreg.subkeys(key):
                    key_info = {
                        'Name': s.Name,
                        'LastUpdated': s.LastWriteTime
                    }

                    for v in rawreg.values(s):
                        if v.Name in print_values.values():
                            tp, dat = rawreg.value_data(v)
                            if tp in ['REG_BINARY', 'REG_NONE']:
                                dat = "\n" + "\n".join(
                                    ["{0:#010x}  {1:<48}  {2}".format(o, h, ''.join(c))
                                     for o, h, c in utils.Hexdump(dat)]
                                )
                            elif tp in ['REG_SZ', 'REG_EXPAND_SZ', 'REG_LINK']:
                                dat = dat.encode("ascii", 'backslashreplace')
                            elif tp == 'REG_MULTI_SZ':
                                dat = [d.encode("ascii", 'backslashreplace') for d in dat]

                            key_info[str(v.Name)] = dat

                    outfd.write("Subkey: {0}\n".format(key_info.get('Name', '')))
                    outfd.write("  LastUpdated     : {0}\n".format(key_info.get('LastUpdated', '')))
                    for k, v in sorted(print_values.items()):
                        val = key_info.get(v, '')
                        if val:
                            outfd.write("  {0:16}: {1}\n".format(v, val))
                    outfd.write("\n")
