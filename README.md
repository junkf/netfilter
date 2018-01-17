# iptables configurations

This is a project to figure out how to use iptables to configure firewalls for 

+ a dedicated firewall
+ workstations behind the firewall
+ maybe some other configurations

Files here include versions of:
 + the iptables.sh script that loads modules, flushes current rules, and sets new policies and rules.
 + ipt.save files that are generated by `iptables-save > ipt.save` after rules are loaded.
 + ipt.save files can be loaded with `iptables-restore < ipt.save` without going through iptables.sh again.
 + BUT mind that the .save files presume network device names, `net0, net1, etc.` --- if those don't match, you will have to regenerate with the iptables.sh script...
 + You can change the device name by defining the name manually with an udev-rule. For example:

```/etc/udev/rules.d/10-network.rules
SUBSYSTEM=="net", ACTION=="add", ATTR{address}=="aa:bb:cc:dd:ee:ff", NAME="net1"
SUBSYSTEM=="net", ACTION=="add", ATTR{address}=="ff:ee:dd:cc:bb:aa", NAME="net0" ```

These rules will be applied automatically at boot. Note: When changing the naming scheme, do not forget to update all network-related configuration files and custom systemd unit files to reflect the change.

