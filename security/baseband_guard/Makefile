# SPDX-License-Identifier: GPL-2.0-only
obj-$(CONFIG_BBG) += baseband_guard.o
ccflags-y += -I$(srctree)/security/selinux -I$(srctree)/security/selinux/include

# SELinux's private credential headers include generated flask definitions.
# Generate our own copies through Kbuild; do not race selinux/ in parallel builds.
$(obj)/baseband_guard.o: $(obj)/flask.h
quiet_cmd_bbg_flask = GEN     $(obj)/flask.h $(obj)/av_permissions.h
      cmd_bbg_flask = $< $(obj)/flask.h $(obj)/av_permissions.h
targets += flask.h av_permissions.h
$(obj)/flask.h: scripts/selinux/genheaders/genheaders FORCE
	$(call if_changed,bbg_flask)
