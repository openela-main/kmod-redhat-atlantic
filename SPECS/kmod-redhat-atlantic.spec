%define kmod_name		atlantic
%define kmod_vendor		redhat
%define kmod_rpm_name		kmod-redhat-atlantic
%define kmod_driver_version	4.18.0_255.el8_dup8.3
%define kmod_driver_epoch	%{nil}
%define kmod_rpm_release	1
%define kmod_kernel_version	4.18.0-240.el8
%define kmod_kernel_version_min	%{nil}
%define kmod_kernel_version_dep	%{nil}
%define kmod_kbuild_dir		drivers/net/ethernet/aquantia/atlantic
%define kmod_dependencies       %{nil}
%define kmod_dist_build_deps	%{nil}
%define kmod_build_dependencies	%{nil}
%define kmod_provides           %{nil}
%define kmod_devel_package	0
%define kmod_devel_src_paths	%{nil}
%define kmod_install_path	extra/kmod-redhat-atlantic
%define kernel_pkg		kernel
%define kernel_devel_pkg	kernel-devel
%define kernel_modules_pkg	kernel-modules

%{!?dist: %define dist .el8_3}
%{!?make_build: %define make_build make}

%if "%{kmod_kernel_version_dep}" == ""
%define kmod_kernel_version_dep %{kmod_kernel_version}
%endif

%if "%{kmod_dist_build_deps}" == ""
%if (0%{?rhel} > 7) || (0%{?centos} > 7)
%define kmod_dist_build_deps redhat-rpm-config kernel-abi-whitelists elfutils-libelf-devel kernel-rpm-macros kmod
%else
%define kmod_dist_build_deps redhat-rpm-config kernel-abi-whitelists
%endif
%endif

Source0:	%{kmod_name}-%{kmod_vendor}-%{kmod_driver_version}.tar.bz2
# Source code patches
Patch0:	0001-netdrv-treewide-Replace-GPLv2-boilerplate-reference-.patch
Patch1:	0002-netdrv-treewide-Replace-GPLv2-boilerplate-reference-.patch
Patch2:	0003-netdrv-net-aquantia-replace-internal-driver-version-.patch
Patch3:	0004-netdrv-net-aquantia-make-all-files-GPL-2.0-only.patch
Patch4:	0005-netdrv-net-aquantia-added-vlan-offload-related-macro.patch
Patch5:	0006-netdrv-net-aquantia-adding-fields-and-device-feature.patch
Patch6:	0007-netdrv-net-aquantia-vlan-offloads-logic-in-datapath.patch
Patch7:	0008-netdrv-net-aquantia-implement-vlan-offload-configura.patch
Patch8:	0009-netdrv-net-aquantia-fix-removal-of-vlan-0.patch
Patch9:	0010-netdrv-net-aquantia-fix-limit-of-vlan-filters.patch
Patch10:	0011-netdrv-net-aquantia-linkstate-irq-should-be-oneshot.patch
Patch11:	0012-netdrv-net-aquantia-fix-out-of-memory-condition-on-r.patch
Patch12:	0013-netdrv-net-aquantia-Fix-aq_vec_isr_legacy-return-val.patch
Patch13:	0014-netdrv-net-aquantia-temperature-retrieval-fix.patch
Patch14:	0015-netdrv-net-aquantia-when-cleaning-hw-cache-it-should.patch
Patch15:	0016-netdrv-net-aquantia-do-not-pass-lro-session-with-inv.patch
Patch16:	0017-netdrv-net-aquantia-correctly-handle-macvlan-and-mul.patch
Patch17:	0018-netdrv-net-aquantia-add-an-error-handling-in-aq_nic_.patch
Patch18:	0019-netdrv-net-aquantia-PTP-skeleton-declarations-and-ca.patch
Patch19:	0020-netdrv-net-aquantia-unify-styling-of-bit-enums.patch
Patch20:	0021-netdrv-net-aquantia-add-basic-ptp_clock-callbacks.patch
Patch21:	0022-netdrv-net-aquantia-add-PTP-rings-infrastructure.patch
Patch22:	0023-netdrv-net-aquantia-styling-fixes-on-ptp-related-fun.patch
Patch23:	0024-netdrv-net-aquantia-implement-data-PTP-datapath.patch
Patch24:	0025-netdrv-net-aquantia-rx-filters-for-ptp.patch
Patch25:	0026-netdrv-net-aquantia-add-support-for-ptp-ioctls.patch
Patch26:	0027-netdrv-net-aquantia-implement-get_ts_info-ethtool.patch
Patch27:	0028-netdrv-net-aquantia-add-support-for-Phy-access.patch
Patch28:	0029-netdrv-net-aquantia-add-support-for-PIN-funcs.patch
Patch29:	0030-netdrv-net-aquantia-fix-var-initialization-warning.patch
Patch30:	0031-netdrv-net-aquantia-fix-warnings-on-endianness.patch
Patch31:	0032-netdrv-net-aquantia-disable-ptp-object-build-if-no-c.patch
Patch32:	0033-netdrv-net-aquantia-fix-spelling-mistake-tx_queus-tx.patch
Patch33:	0034-netdrv-net-aquantia-fix-unintention-integer-overflow.patch
Patch34:	0035-netdrv-net-aquantia-make-two-symbols-be-static.patch
Patch35:	0036-netdrv-net-aquantia-remove-unused-including-linux-ve.patch
Patch36:	0037-netdrv-net-aquantia-fix-error-handling-in-aq_ptp_pol.patch
Patch37:	0038-netdrv-net-aquantia-fix-return-value-check-in-aq_ptp.patch
Patch38:	0039-netdrv-net-atlantic-update-firmware-interface.patch
Patch39:	0040-netdrv-net-atlantic-implement-wake_phy-feature.patch
Patch40:	0041-netdrv-net-atlantic-refactoring-pm-logic.patch
Patch41:	0042-netdrv-net-atlantic-add-msglevel-configuration.patch
Patch42:	0043-netdrv-net-atlantic-adding-ethtool-physical-identifi.patch
Patch43:	0044-netdrv-net-atlantic-add-fw-configuration-memory-area.patch
Patch44:	0045-netdrv-net-atlantic-loopback-tests-via-private-flags.patch
Patch45:	0046-netdrv-net-atlantic-code-style-cleanup.patch
Patch46:	0047-netdrv-net-atlantic-stylistic-renames.patch
Patch47:	0048-netdrv-net-atlantic-update-flow-control-logic.patch
Patch48:	0049-netdrv-net-atlantic-implement-UDP-GSO-offload.patch
Patch49:	0050-netdrv-net-atlantic-change-email-domains-to-Marvell.patch
Patch50:	0051-netdrv-net-atlantic-make-symbol-aq_pm_ops-static.patch
Patch51:	0052-netdrv-net-atlantic-make-function-aq_ethtool_get_pri.patch
Patch52:	0053-netdrv-net-atlantic-Signedness-bug-in-aq_vec_isr_leg.patch
Patch53:	0054-netdrv-net-atlantic-broken-link-status-on-old-fw.patch
Patch54:	0055-netdrv-net-atlantic-loopback-configuration-in-improp.patch
Patch55:	0056-netdrv-net-atlantic-remove-duplicate-entries.patch
Patch56:	0057-netdrv-net-atlantic-checksum-compat-issue.patch
Patch57:	0058-netdrv-net-atlantic-check-rpc-result-and-wait-for-rp.patch
Patch58:	0059-netdrv-net-atlantic-ptp-gpio-adjustments.patch
Patch59:	0060-netdrv-net-atlantic-better-loopback-mode-handling.patch
Patch60:	0061-netdrv-net-atlantic-fix-use-after-free-kasan-warn.patch
Patch61:	0062-netdrv-net-atlantic-fix-potential-error-handling.patch
Patch62:	0063-netdrv-net-atlantic-possible-fault-in-transition-to-.patch
Patch63:	0064-netdrv-net-atlantic-fix-out-of-range-usage-of-active.patch
Patch64:	0065-netdrv-net-aquantia-Delete-module-version.patch
Patch65:	0066-netdrv-net-atlantic-Replace-zero-length-array-with-f.patch
Patch66:	0067-netdrv-net-aquantia-reject-all-unsupported-coalescin.patch
Patch67:	0068-netdrv-net-atlantic-MACSec-offload-statistics-implem.patch
Patch68:	0069-netdrv-aquantia-Fix-the-media-type-of-AQC100-etherne.patch
Patch69:	0070-netdrv-net-atlantic-update-company-name-in-the-drive.patch
Patch70:	0071-netdrv-net-atlantic-add-A2-device-IDs.patch
Patch71:	0072-netdrv-net-atlantic-add-defines-for-10M-and-EEE-100M.patch
Patch72:	0073-netdrv-net-atlantic-add-hw_soft_reset-hw_prepare-to-.patch
Patch73:	0074-netdrv-net-atlantic-simplify-hw_get_fw_version-usage.patch
Patch74:	0075-netdrv-net-atlantic-make-hw_get_regs-optional.patch
Patch75:	0076-netdrv-net-atlantic-move-IS_CHIP_FEATURE-to-aq_hw.h.patch
Patch76:	0077-netdrv-net-atlantic-A2-driver-firmware-interface.patch
Patch77:	0078-netdrv-net-atlantic-minimal-A2-HW-bindings-required-.patch
Patch78:	0079-netdrv-net-atlantic-minimal-A2-fw_ops.patch
Patch79:	0080-netdrv-net-atlantic-A2-hw_ops-skeleton.patch
Patch80:	0081-netdrv-net-atlantic-HW-bindings-for-A2-RFP.patch
Patch81:	0082-netdrv-net-atlantic-add-A2-RPF-hw_ops.patch
Patch82:	0083-netdrv-net-atlantic-HW-bindings-for-basic-A2-init-de.patch
Patch83:	0084-netdrv-net-atlantic-common-functions-needed-for-basi.patch
Patch84:	0085-netdrv-net-atlantic-basic-A2-init-deinit-hw_ops.patch
Patch85:	0086-netdrv-net-atlantic-A2-ingress-egress-hw-configurati.patch
Patch86:	0087-netdrv-net-atlantic-use-__packed-instead-of-the-full.patch
Patch87:	0088-netdrv-net-atlantic-rename-AQ_NIC_RATE_2GS-to-AQ_NIC.patch
Patch88:	0089-netdrv-net-atlantic-remove-TPO2-check-from-A0-code.patch
Patch89:	0090-netdrv-net-atlantic-remove-hw_atl_b0_hw_rss_set-call.patch
Patch90:	0091-netdrv-net-atlantic-remove-check-for-boot-code-survi.patch
Patch91:	0092-netdrv-net-atlantic-unify-MAC-generation.patch
Patch92:	0093-netdrv-net-atlantic-changes-for-multi-TC-support.patch
Patch93:	0094-netdrv-net-atlantic-move-PTP-TC-initialization-to-a-.patch
Patch94:	0095-netdrv-net-atlantic-changes-for-multi-TC-support.patch
Patch95:	0096-netdrv-net-atlantic-QoS-implementation-multi-TC-supp.patch
Patch96:	0097-netdrv-net-atlantic-per-TC-queue-statistics.patch
Patch97:	0098-netdrv-net-atlantic-make-TCVEC2RING-accept-nic_cfg.patch
Patch98:	0099-netdrv-net-atlantic-QoS-implementation-max_rate.patch
Patch99:	0100-netdrv-net-atlantic-automatically-downgrade-the-numb.patch
Patch100:	0101-netdrv-net-atlantic-always-use-random-TC-queue-mappi.patch
Patch101:	0102-netdrv-net-atlantic-change-the-order-of-arguments-fo.patch
Patch102:	0103-netdrv-net-atlantic-QoS-implementation-min_rate.patch
Patch103:	0104-netdrv-net-atlantic-proper-rss_ctrl1-54c0-initializa.patch
Patch104:	0105-netdrv-net-atlantic-A2-half-duplex-support.patch
Patch105:	0106-netdrv-net-atlantic-remove-baseX-usage.patch
Patch106:	0107-netdrv-net-atlantic-A2-EEE-support.patch
Patch107:	0108-netdrv-net-atlantic-A2-flow-control-support.patch
Patch108:	0109-netdrv-net-atlantic-A2-report-link-partner-capabilit.patch
Patch109:	0110-netdrv-net-atlantic-A2-phy-loopback-support.patch
Patch110:	0111-netdrv-net-atlantic-fix-variable-type-in-aq_ethtool_.patch
Patch111:	0112-netdrv-net-atlantic-Replace-ENOTSUPP-usage-to-EOPNOT.patch
Patch112:	0113-netdrv-net-atlantic-make-aq_pci_func_init-static.patch
Patch113:	0114-netdrv-net-atlantic-fix-typo-in-aq_ring_tx_clean.patch
Patch114:	0115-netdrv-net-atlantic-missing-space-in-a-comment-in-aq.patch
Patch115:	0116-netdrv-net-atlantic-add-alignment-checks-in-hw_atl2_.patch
Patch116:	0117-netdrv-net-atlantic-put-ptp-code-under-IS_REACHABLE-.patch
Patch117:	0118-netdrv-net-aquantia-fix-aq_ndev_start_xmit-s-return-.patch
Patch118:	0119-netdrv-net-atlantic-fix-ip-dst-and-ipv6-address-filt.patch
Patch119:	0120-netdrv-net-atlantic-disable-PTP-on-AQC111-AQC112.patch
Patch120:	0121-netdrv-net-atlantic-align-return-value-of-ver_match-.patch
Patch121:	0122-netdrv-net-atlantic-add-support-for-FW-4.x.patch
Patch122:	0123-netdrv-net-atlantic-move-FRAC_PER_NS-to-aq_hw.h.patch
Patch123:	0124-netdrv-net-atlantic-use-simple-assignment-in-_get_st.patch
Patch124:	0125-netdrv-net-atlantic-make-_get_sw_stats-return-count-.patch
Patch125:	0126-netdrv-net-atlantic-split-rx-and-tx-per-queue-stats.patch
Patch126:	0127-netdrv-net-atlantic-use-u64_stats_update_-to-protect.patch
Patch127:	0128-netdrv-net-atlantic-additional-per-queue-stats.patch
Patch128:	0129-netdrv-net-atlantic-PTP-statistics.patch
Patch129:	0130-netdrv-net-atlantic-enable-ipv6-support-for-TCP-LSO-.patch
Patch130:	0131-netdrv-net-atlantic-add-support-for-64-bit-reads-wri.patch
Patch131:	0132-netdrv-net-atlantic-use-U32_MAX-in-aq_hw_utils.c.patch
Patch132:	0133-netdrv-net-atlantic-use-intermediate-variable-to-imp.patch
Patch133:	0134-netdrv-net-atlantic-A0-ntuple-filters.patch
Patch134:	0135-netdrv-net-atlantic-add-hwmon-getter-for-MAC-tempera.patch
Patch135:	0136-netdrv-net-atlantic-fix-PTP-on-AQC10X.patch
Patch136:	0137-netdrv-net-ethernet-aquantia-Fix-wrong-return-value.patch
Patch137:	0138-netdrv-net-atlantic-Use-readx_poll_timeout-for-large.patch
Patch138:	0139-netdrv-net-atlantic-fix-build-when-object-tree-is-se.patch
Patch139:	9000-add-driver-version.patch

%define findpat %( echo "%""P" )
%define __find_requires /usr/lib/rpm/redhat/find-requires.ksyms
%define __find_provides /usr/lib/rpm/redhat/find-provides.ksyms %{kmod_name} %{?epoch:%{epoch}:}%{version}-%{release}
%define sbindir %( if [ -d "/sbin" -a \! -h "/sbin" ]; then echo "/sbin"; else echo %{_sbindir}; fi )
%define dup_state_dir %{_localstatedir}/lib/rpm-state/kmod-dups
%define kver_state_dir %{dup_state_dir}/kver
%define kver_state_file %{kver_state_dir}/%{kmod_kernel_version}.%(arch)
%define dup_module_list %{dup_state_dir}/rpm-kmod-%{kmod_name}-modules

Name:		kmod-redhat-atlantic
Version:	%{kmod_driver_version}
Release:	%{kmod_rpm_release}%{?dist}
%if "%{kmod_driver_epoch}" != ""
Epoch:		%{kmod_driver_epoch}
%endif
Summary:	atlantic kernel module for Driver Update Program
Group:		System/Kernel
License:	GPLv2
URL:		https://www.kernel.org/
BuildRoot:	%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
BuildRequires:	%kernel_devel_pkg = %kmod_kernel_version
%if "%{kmod_dist_build_deps}" != ""
BuildRequires:	%{kmod_dist_build_deps}
%endif
ExclusiveArch:	x86_64
%global kernel_source() /usr/src/kernels/%{kmod_kernel_version}.$(arch)

%global _use_internal_dependency_generator 0
%if "%{?kmod_kernel_version_min}" != ""
Provides:	%kernel_modules_pkg >= %{kmod_kernel_version_min}.%{_target_cpu}
%else
Provides:	%kernel_modules_pkg = %{kmod_kernel_version_dep}.%{_target_cpu}
%endif
Provides:	kmod-%{kmod_name} = %{?epoch:%{epoch}:}%{version}-%{release}
Requires(post):	%{sbindir}/weak-modules
Requires(postun):	%{sbindir}/weak-modules
Requires:	kernel >= 4.18.0-240.el8

Requires:	kernel < 4.18.0-241.el8
%if 0
Requires: firmware(%{kmod_name}) = ENTER_FIRMWARE_VERSION
%endif
%if "%{kmod_build_dependencies}" != ""
BuildRequires:  %{kmod_build_dependencies}
%endif
%if "%{kmod_dependencies}" != ""
Requires:       %{kmod_dependencies}
%endif
%if "%{kmod_provides}" != ""
Provides:       %{kmod_provides}
%endif
# if there are multiple kmods for the same driver from different vendors,
# they should conflict with each other.
Conflicts:	kmod-%{kmod_name}

%description
atlantic kernel module for Driver Update Program

%if 0

%package -n kmod-redhat-atlantic-firmware
Version:	ENTER_FIRMWARE_VERSION
Summary:	atlantic firmware for Driver Update Program
Provides:	firmware(%{kmod_name}) = ENTER_FIRMWARE_VERSION
%if "%{kmod_kernel_version_min}" != ""
Provides:	%kernel_modules_pkg >= %{kmod_kernel_version_min}.%{_target_cpu}
%else
Provides:	%kernel_modules_pkg = %{kmod_kernel_version_dep}.%{_target_cpu}
%endif
%description -n  kmod-redhat-atlantic-firmware
atlantic firmware for Driver Update Program


%files -n kmod-redhat-atlantic-firmware
%defattr(644,root,root,755)
%{FIRMWARE_FILES}

%endif

# Development package
%if 0%{kmod_devel_package}
%package -n kmod-redhat-atlantic-devel
Version:	%{kmod_driver_version}
Requires:	kernel >= 4.18.0-240.el8

Requires:	kernel < 4.18.0-241.el8
Summary:	atlantic development files for Driver Update Program

%description -n  kmod-redhat-atlantic-devel
atlantic development files for Driver Update Program


%files -n kmod-redhat-atlantic-devel
%defattr(644,root,root,755)
/lib/modules/%{kmod_rpm_name}-%{kmod_driver_version}/
%endif

%post
modules=( $(find /lib/modules/%{kmod_kernel_version}.%(arch)/%{kmod_install_path} | grep '\.ko$') )
printf '%s\n' "${modules[@]}" | %{sbindir}/weak-modules --add-modules --no-initramfs

mkdir -p "%{kver_state_dir}"
touch "%{kver_state_file}"

exit 0

%posttrans
# We have to re-implement part of weak-modules here because it doesn't allow
# calling initramfs regeneration separately
if [ -f "%{kver_state_file}" ]; then
	kver_base="%{kmod_kernel_version_dep}"
	kvers=$(ls -d "/lib/modules/${kver_base%%.*}"*)

	for k_dir in $kvers; do
		k="${k_dir#/lib/modules/}"

		tmp_initramfs="/boot/initramfs-$k.tmp"
		dst_initramfs="/boot/initramfs-$k.img"

		# The same check as in weak-modules: we assume that the kernel present
		# if the symvers file exists.
		if [ -e "/boot/symvers-$k.gz" ] || [ -e "$k_dir/symvers.gz" ]; then
			/usr/bin/dracut -f "$tmp_initramfs" "$k" || exit 1
			cmp -s "$tmp_initramfs" "$dst_initramfs"
			if [ "$?" = 1 ]; then
				mv "$tmp_initramfs" "$dst_initramfs"
			else
				rm -f "$tmp_initramfs"
			fi
		fi
	done

	rm -f "%{kver_state_file}"
	rmdir "%{kver_state_dir}" 2> /dev/null
fi

rmdir "%{dup_state_dir}" 2> /dev/null

exit 0

%preun
if rpm -q --filetriggers kmod 2> /dev/null| grep -q "Trigger for weak-modules call on kmod removal"; then
	mkdir -p "%{kver_state_dir}"
	touch "%{kver_state_file}"
fi

mkdir -p "%{dup_state_dir}"
rpm -ql kmod-redhat-atlantic-%{kmod_driver_version}-%{kmod_rpm_release}%{?dist}.$(arch) | \
	grep '\.ko$' > "%{dup_module_list}"

%postun
if rpm -q --filetriggers kmod 2> /dev/null| grep -q "Trigger for weak-modules call on kmod removal"; then
	initramfs_opt="--no-initramfs"
else
	initramfs_opt=""
fi

modules=( $(cat "%{dup_module_list}") )
rm -f "%{dup_module_list}"
printf '%s\n' "${modules[@]}" | %{sbindir}/weak-modules --remove-modules $initramfs_opt

rmdir "%{dup_state_dir}" 2> /dev/null

exit 0

%files
%defattr(644,root,root,755)
/lib/modules/%{kmod_kernel_version}.%(arch)
/etc/depmod.d/%{kmod_name}.conf
%doc /usr/share/doc/%{kmod_rpm_name}/greylist.txt



%prep
%setup -n %{kmod_name}-%{kmod_vendor}-%{kmod_driver_version}

%patch0 -p1
%patch1 -p1
%patch2 -p1
%patch3 -p1
%patch4 -p1
%patch5 -p1
%patch6 -p1
%patch7 -p1
%patch8 -p1
%patch9 -p1
%patch10 -p1
%patch11 -p1
%patch12 -p1
%patch13 -p1
%patch14 -p1
%patch15 -p1
%patch16 -p1
%patch17 -p1
%patch18 -p1
%patch19 -p1
%patch20 -p1
%patch21 -p1
%patch22 -p1
%patch23 -p1
%patch24 -p1
%patch25 -p1
%patch26 -p1
%patch27 -p1
%patch28 -p1
%patch29 -p1
%patch30 -p1
%patch31 -p1
%patch32 -p1
%patch33 -p1
%patch34 -p1
%patch35 -p1
%patch36 -p1
%patch37 -p1
%patch38 -p1
%patch39 -p1
%patch40 -p1
%patch41 -p1
%patch42 -p1
%patch43 -p1
%patch44 -p1
%patch45 -p1
%patch46 -p1
%patch47 -p1
%patch48 -p1
%patch49 -p1
%patch50 -p1
%patch51 -p1
%patch52 -p1
%patch53 -p1
%patch54 -p1
%patch55 -p1
%patch56 -p1
%patch57 -p1
%patch58 -p1
%patch59 -p1
%patch60 -p1
%patch61 -p1
%patch62 -p1
%patch63 -p1
%patch64 -p1
%patch65 -p1
%patch66 -p1
%patch67 -p1
%patch68 -p1
%patch69 -p1
%patch70 -p1
%patch71 -p1
%patch72 -p1
%patch73 -p1
%patch74 -p1
%patch75 -p1
%patch76 -p1
%patch77 -p1
%patch78 -p1
%patch79 -p1
%patch80 -p1
%patch81 -p1
%patch82 -p1
%patch83 -p1
%patch84 -p1
%patch85 -p1
%patch86 -p1
%patch87 -p1
%patch88 -p1
%patch89 -p1
%patch90 -p1
%patch91 -p1
%patch92 -p1
%patch93 -p1
%patch94 -p1
%patch95 -p1
%patch96 -p1
%patch97 -p1
%patch98 -p1
%patch99 -p1
%patch100 -p1
%patch101 -p1
%patch102 -p1
%patch103 -p1
%patch104 -p1
%patch105 -p1
%patch106 -p1
%patch107 -p1
%patch108 -p1
%patch109 -p1
%patch110 -p1
%patch111 -p1
%patch112 -p1
%patch113 -p1
%patch114 -p1
%patch115 -p1
%patch116 -p1
%patch117 -p1
%patch118 -p1
%patch119 -p1
%patch120 -p1
%patch121 -p1
%patch122 -p1
%patch123 -p1
%patch124 -p1
%patch125 -p1
%patch126 -p1
%patch127 -p1
%patch128 -p1
%patch129 -p1
%patch130 -p1
%patch131 -p1
%patch132 -p1
%patch133 -p1
%patch134 -p1
%patch135 -p1
%patch136 -p1
%patch137 -p1
%patch138 -p1
%patch139 -p1
set -- *
mkdir source
mv "$@" source/
mkdir obj

%build
rm -rf obj
cp -r source obj

PWD_PATH="$PWD"
%if "%{workaround_no_pwd_rel_path}" != "1"
PWD_PATH=$(realpath --relative-to="%{kernel_source}" . 2>/dev/null || echo "$PWD")
%endif
%{make_build} -C %{kernel_source} V=1 M="$PWD_PATH/obj/%{kmod_kbuild_dir}" \
	NOSTDINC_FLAGS="-I$PWD_PATH/obj/include -I$PWD_PATH/obj/include/uapi %{nil}" \
	EXTRA_CFLAGS="%{nil}" \
	%{nil}
# mark modules executable so that strip-to-file can strip them
find obj/%{kmod_kbuild_dir} -name "*.ko" -type f -exec chmod u+x '{}' +

whitelist="/lib/modules/kabi-current/kabi_whitelist_%{_target_cpu}"
for modules in $( find obj/%{kmod_kbuild_dir} -name "*.ko" -type f -printf "%{findpat}\n" | sed 's|\.ko$||' | sort -u ) ; do
	# update depmod.conf
	module_weak_path=$(echo "$modules" | sed 's/[\/]*[^\/]*$//')
	if [ -z "$module_weak_path" ]; then
		module_weak_path=%{name}
	else
		module_weak_path=%{name}/$module_weak_path
	fi
	echo "override $(echo $modules | sed 's/.*\///')" \
	     "$(echo "%{kmod_kernel_version_dep}" |
	        sed 's/\.[^\.]*$//;
		     s/\([.+?^$\/\\|()\[]\|\]\)/\\\0/g').*" \
		     "weak-updates/$module_weak_path" >> source/depmod.conf

	# update greylist
	nm -u obj/%{kmod_kbuild_dir}/$modules.ko | sed 's/.*U //' |  sed 's/^\.//' | sort -u | while read -r symbol; do
		grep -q "^\s*$symbol\$" $whitelist || echo "$symbol" >> source/greylist
	done
done
sort -u source/greylist | uniq > source/greylist.txt

%install
export INSTALL_MOD_PATH=$RPM_BUILD_ROOT
export INSTALL_MOD_DIR=%{kmod_install_path}
PWD_PATH="$PWD"
%if "%{workaround_no_pwd_rel_path}" != "1"
PWD_PATH=$(realpath --relative-to="%{kernel_source}" . 2>/dev/null || echo "$PWD")
%endif
make -C %{kernel_source} modules_install \
	M=$PWD_PATH/obj/%{kmod_kbuild_dir}
# Cleanup unnecessary kernel-generated module dependency files.
find $INSTALL_MOD_PATH/lib/modules -iname 'modules.*' -exec rm {} \;

install -m 644 -D source/depmod.conf $RPM_BUILD_ROOT/etc/depmod.d/%{kmod_name}.conf
install -m 644 -D source/greylist.txt $RPM_BUILD_ROOT/usr/share/doc/%{kmod_rpm_name}/greylist.txt
%if 0
%{FIRMWARE_FILES_INSTALL}
%endif
%if 0%{kmod_devel_package}
install -m 644 -D $PWD/obj/%{kmod_kbuild_dir}/Module.symvers $RPM_BUILD_ROOT/lib/modules/%{kmod_rpm_name}-%{kmod_driver_version}/build/Module.symvers

if [ -n "%{kmod_devel_src_paths}" ]; then
	for i in %{kmod_devel_src_paths}; do
		mkdir -p "$RPM_BUILD_ROOT/lib/modules/%{kmod_rpm_name}-%{kmod_driver_version}/build/$(dirname "$i")"
		cp -rv "$PWD/source/$i" \
			"$RPM_BUILD_ROOT/lib/modules/%{kmod_rpm_name}-%{kmod_driver_version}/build/$i"
	done
fi
%endif



%clean
rm -rf $RPM_BUILD_ROOT

%changelog
* Thu Apr 01 2021 Eugene Syromiatnikov <esyr@redhat.com> 4.18.0_255.el8_dup8.3-1
- bfcc924fa05e36abe7a039ac5ec2be581e20c288
- atlantic kernel module for Driver Update Program
- Resolves: #bz1944615
