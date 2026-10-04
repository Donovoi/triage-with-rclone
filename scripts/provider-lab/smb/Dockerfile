# Disposable Samba probe only. Never publish this image or export its cache.
# BuildKit heredoc support is required; no mutable external Dockerfile frontend.
FROM docker.io/library/debian@sha256:7792b1f7702a86946cd518db72b6a407302c3e9bc1635634368b878189e8221c
LABEL org.openai.triage.fixture-kind="smb-probe"
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY build-lock.json /opt/synthetic-smb/build-lock.json

RUN <<'BOOTSTRAP'
set -eu
test "$(dpkg --print-architecture)" = amd64
printf '%s  %s\n' '48323966663f34107cc950984bfb0fe2d00306f1a4a20cd0e77cc88c016613d2' /opt/synthetic-smb/build-lock.json | sha256sum -c -
dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' > /tmp/smb-base-packages.tsv
rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*
cat > /etc/apt/sources.list <<'SOURCES'
deb [arch=amd64 signed-by=/usr/share/keyrings/debian-archive-keyring.gpg check-valid-until=no] http://snapshot.debian.org/archive/debian/20261003T000000Z/ trixie main
deb [arch=amd64 signed-by=/usr/share/keyrings/debian-archive-keyring.gpg check-valid-until=no] http://snapshot.debian.org/archive/debian/20261003T000000Z/ trixie-updates main
deb [arch=amd64 signed-by=/usr/share/keyrings/debian-archive-keyring.gpg check-valid-until=no] http://snapshot.debian.org/archive/debian-security/20261003T000000Z/ trixie-security main
SOURCES
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
chmod 0755 /usr/sbin/policy-rc.d
rm -rf /var/lib/apt/lists/*
printf '%s\n' 'SMB_BUILD_PHASE=metadata'
apt-get -o Acquire::Retries=0 -o Acquire::http::Timeout=30 update
test "$(find /var/lib/apt/lists -maxdepth 1 -type f -name '*_InRelease' | wc -l)" -eq 3
release=$(find /var/lib/apt/lists -maxdepth 1 -type f -name '*_dists_trixie_InRelease')
test -n "$release"
printf '%s  %s\n' '0584fba32e13e0ab8285fb16c27adea1ec03a73669c18702821094fd6ca86675' "$release" | sha256sum -c -
release=$(find /var/lib/apt/lists -maxdepth 1 -type f -name '*_dists_trixie-updates_InRelease')
test -n "$release"
printf '%s  %s\n' '203dfe8d2fe5f0cb136a07c755b5111848d4e044008562da9e6274591e32d125' "$release" | sha256sum -c -
release=$(find /var/lib/apt/lists -maxdepth 1 -type f -name '*_dists_trixie-security_InRelease')
test -n "$release"
printf '%s  %s\n' '9f9c5cc05760f1db55fc5e44fede3cb864f995ea98a71ad853ce334e24112430' "$release" | sha256sum -c -
mkdir -m 0700 /tmp/smb-locked-debs
cat > /tmp/smb-artifacts.tsv <<'ARTIFACTS'
base-passwd	3.6.7	cf31c6956ab5f65815d9d9ea1615c4f78ecd2893c31119658248a4756cee83e7	53712	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/b/base-passwd/base-passwd_3.6.7_amd64.deb
debconf	1.5.91	1ddc7e6c5925f748eefb7ca811d98e049f18c158bb21fbc7e122262ce6011e49	121088	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/d/debconf/debconf_1.5.91_all.deb
dpkg	1.22.22	3e800c6d75e8e709007ed1c356e5fa8509a75c1694fb0a1183709abc9cfdc1f3	1537216	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/d/dpkg/dpkg_1.22.22_amd64.deb
gcc-14-base	14.2.0-19	5b6825de4263824b78c4c51f6476414f3b4e89c2ab63e81dc8b9b5501e867cf6	49432	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/g/gcc-14/gcc-14-base_14.2.0-19_amd64.deb
init-system-helpers	1.69~deb13u1	addf78073e1cbc5a5508937e11d2571055e29835e00ee8fab52a66775649378f	39360	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/i/init-system-helpers/init-system-helpers_1.69~deb13u1_all.deb
libacl1	2.3.2-2+b1	08074f01e384bc07c0c2d79a58cf4a6523f71cf75d1808101c79617656c9a39d	32860	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/a/acl/libacl1_2.3.2-2+b1_amd64.deb
libattr1	1:2.5.2-3	606b5ee12ea2786be607a17f40c1fb5e65c76ceaff66665bdf8f8c6c1b71d1fb	22876	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/a/attr/libattr1_2.5.2-3_amd64.deb
libaudit-common	1:4.0.2-2+deb13u1	b9d32e5ff04fd747aacb7d6b3ebbbbf734ddefb2f1695f0b1b2a4b5e51b1052e	12812	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/a/audit/libaudit-common_4.0.2-2+deb13u1_all.deb
libaudit1	1:4.0.2-2+deb13u1	3d1dd3f031a56f01b747e2acc0e14575212580e6fa63d800c44cb0a31f1edfd7	57680	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/a/audit/libaudit1_4.0.2-2+deb13u1_amd64.deb
libavahi-client3	0.8-16	27df3f1c0190d13ec6d014c5515c2ec8e9a49d0983f48fc9e5756ee4e62d7e37	48384	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/a/avahi/libavahi-client3_0.8-16_amd64.deb
libavahi-common-data	0.8-16	a3c0cb1326ed60cbbef133c31af28759f7a922d886d001a138d52bbf0af908d6	112284	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/a/avahi/libavahi-common-data_0.8-16_amd64.deb
libavahi-common3	0.8-16	fb092fc55f1c7f3db0ac64467f30ebae8145543570b8e99f17ce84cf1dd28bb6	44224	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/a/avahi/libavahi-common3_0.8-16_amd64.deb
libbsd0	0.12.2-2	e5a85986fa6bec3307ab1bc860736b478b331882bc45e17675a7bdf88eecb43a	130968	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/libb/libbsd/libbsd0_0.12.2-2_amd64.deb
libbz2-1.0	1.0.8-6	cba4cda04244b5e481bb15524bc3c983a7d1b6f330013b9b381706a2fcb65310	37912	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/b/bzip2/libbz2-1.0_1.0.8-6_amd64.deb
libc6	2.41-12+deb13u4	967aa62605721081c3eb2a17650611a792aa802d76a6511d1840242623d204c9	2846580	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/g/glibc/libc6_2.41-12+deb13u4_amd64.deb
libcap-ng0	0.8.5-4+b1	20a9e4b0619a3eb2566338223bed135dde5a601eaa2f8fdd5f20b94506addcac	17584	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/libc/libcap-ng/libcap-ng0_0.8.5-4+b1_amd64.deb
libcap2	1:2.75-10+deb13u1+b3	89fc4d34fc7a28ad6f0fcd0c561ab253b9dedf6f77f5a000b47c276c8295bf67	28988	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/libc/libcap2/libcap2_2.75-10+deb13u1+b3_amd64.deb
libcom-err2	1.47.2-3+b12	bd43e020b8fed399db3eebf098111f10fba4c436fff99ccad72cc7e27c9764ec	25036	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/e/e2fsprogs/libcom-err2_1.47.2-3+b12_amd64.deb
libcrypt1	1:4.4.38-1	0ebc144d662e3197982d1bf3a7b8b35ca845e54c68811de0328b1f0d7c67585c	90072	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/libx/libxcrypt/libcrypt1_4.4.38-1_amd64.deb
libcups2t64	2.4.10-3+deb13u2	278c57da32afceec1f406869e790b29f40c75b02bb8e512dd903d5a5264df9d2	251548	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/c/cups/libcups2t64_2.4.10-3+deb13u2_amd64.deb
libdb5.3t64	5.3.28+dfsg2-9	18d02510ee78b67e4504ba050176797a200ff24214a7cd318082ab60ad7bf3fc	703676	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/d/db5.3/libdb5.3t64_5.3.28+dfsg2-9_amd64.deb
libdbus-1-3	1.16.2-2	bbcb711daff7e104b5f80f9b05475b6142674bfe65518a36a56e96a91068a3f5	177904	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/d/dbus/libdbus-1-3_1.16.2-2_amd64.deb
libdebconfclient0	0.280	25acadc8b394bc86d05df16e70975e523f8f839a7d8d6d5e22c1cafdcef741aa	10632	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/c/cdebconf/libdebconfclient0_0.280_amd64.deb
libexpat1	2.8.3-1~deb13u1	38abe0e710a07688e9c149d74536e67cfee0364bdb64dd6d644c32a1cfad389f	122672	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/e/expat/libexpat1_2.8.3-1~deb13u1_amd64.deb
libffi8	3.4.8-2	0ebdc340de33333639c3c63874cd4b15ac2e83dfa1ef3053b7eefaf4919f4f68	24144	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/libf/libffi/libffi8_3.4.8-2_amd64.deb
libgcc-s1	14.2.0-19	3c71917b490d1a17aed43196a2787a256ecf060526cdb20216a74bedc061b150	72772	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/g/gcc-14/libgcc-s1_14.2.0-19_amd64.deb
libgmp10	2:6.3.0+dfsg-3	d0d0265eb01770f17afd0f7c8c0622f80479dcfbbe13653a0debeec61464e622	560220	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/g/gmp/libgmp10_6.3.0+dfsg-3_amd64.deb
libgnutls30t64	3.8.9-3+deb13u4	18a8bdfd91c7e3bcb01719d55a2b56849c7160b34f1f52b1c4fdfdd41bf1352b	1469024	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/g/gnutls28/libgnutls30t64_3.8.9-3+deb13u4_amd64.deb
libgssapi-krb5-2	1.21.3-5+deb13u1	30847c1fde4240567d7ed3aeab4f655dd591203758b857e85e824045aae70299	138356	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/k/krb5/libgssapi-krb5-2_1.21.3-5+deb13u1_amd64.deb
libhogweed6t64	3.10.1-1	b059ed155115ac09da295322de48ee1ed58ef5fa45edcc9e12ff0e94636ef25f	335240	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/n/nettle/libhogweed6t64_3.10.1-1_amd64.deb
libicu76	76.1-4	c1bf762996de9ecba9b9d871e4928a8090f023a3e9e7fa3240b3d90f892a01dc	9722072	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/i/icu/libicu76_76.1-4_amd64.deb
libidn2-0	2.3.8-2	90b039bcdc4578f8e1c4935adf8dbb525e36a164deefdbbb8c45bac347d48278	109096	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/libi/libidn2/libidn2-0_2.3.8-2_amd64.deb
libjansson4	2.14-2+b3	60707a62fe6c1228c3389b12a13ca4efd76defc5532473e547a29e99cf7d2a6e	39792	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/j/jansson/libjansson4_2.14-2+b3_amd64.deb
libk5crypto3	1.21.3-5+deb13u1	7da07ee674b47f1f0be7cc89317c25310086a1f1761217d0f72e6ae2c5a69b84	81152	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/k/krb5/libk5crypto3_1.21.3-5+deb13u1_amd64.deb
libkeyutils1	1.6.3-6	0b11ad17be0300b63ad4eeb4c6450fed24d34b7b740f23e5363dcb29ee6d5eba	9456	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/k/keyutils/libkeyutils1_1.6.3-6_amd64.deb
libkrb5-3	1.21.3-5+deb13u1	47d71d6a7f2e59b9bae5f89602397594805113b95889ad18fa703cd53abafc97	326056	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/k/krb5/libkrb5-3_1.21.3-5+deb13u1_amd64.deb
libkrb5support0	1.21.3-5+deb13u1	3a0acd8b37955c0e102c756b52c97df2a31f67b96453c35dab70df218d309117	33124	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/k/krb5/libkrb5support0_1.21.3-5+deb13u1_amd64.deb
libldap2	2.6.10+dfsg-1	60069e4a550ca890113fa89d3001417781b18e146ec5d637d31e368dec9909bd	193576	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/o/openldap/libldap2_2.6.10+dfsg-1_amd64.deb
libldb2	2:2.11.0+samba4.22.11+dfsg-0+deb13u1	8c61310699c84116540e4bff05085e8a4bcf302b4ed58cee1cb4c0c40eaa9670	179964	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/s/samba/libldb2_2.11.0+samba4.22.11+dfsg-0+deb13u1_amd64.deb
liblmdb0	0.9.31-1+b2	97636442b412a6dff51d23ba74f0cdc12ac1edece661a16c43cba294a98cf543	45240	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/l/lmdb/liblmdb0_0.9.31-1+b2_amd64.deb
liblzma5	5.8.1-1+deb13u1	1cfcc6e0dc36f438a79b6e2189facdb9d150b08f57d190a60e01c98075c7f896	309492	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/x/xz-utils/liblzma5_5.8.1-1+deb13u1_amd64.deb
libmd0	1.1.0-2+b1	7244ec3839b61fac0c1884fe08aaa040f26e8f1f35f1f5d3482eacefd30d1b44	36272	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/libm/libmd/libmd0_1.1.0-2+b1_amd64.deb
libncurses6	6.5+20250216-2	e00cbcc8c0826993f881f492c05f33ba8d79b5375dc5a2ab59c82e0c7b9179a9	105036	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/n/ncurses/libncurses6_6.5+20250216-2_amd64.deb
libncursesw6	6.5+20250216-2	47baa2e11579583654583a066b69bd5a5d2f22423081f707ed6c0c3ba6d538b7	135484	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/n/ncurses/libncursesw6_6.5+20250216-2_amd64.deb
libnettle8t64	3.10.1-1	1b03d4a9cd9c8143ba50fe6396f36937e901a317d492d179f4596862c1731cfe	305436	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/n/nettle/libnettle8t64_3.10.1-1_amd64.deb
libp11-kit0	0.25.5-3	784bf2063e166c8bc851a32623b74ebd85c499043a9d57c5bbd64fa63447f45a	425240	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/p/p11-kit/libp11-kit0_0.25.5-3_amd64.deb
libpam-modules	1.7.0-5	9679ade117f8775ac0471f48a92652ab8e8dcda4e2ff06de75158cded9cfd83c	178696	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/p/pam/libpam-modules_1.7.0-5_amd64.deb
libpam-modules-bin	1.7.0-5	cc72066d008444317738e8e931d6131b301466b4e2dd5ef5baa75fb1a45d61a7	49116	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/p/pam/libpam-modules-bin_1.7.0-5_amd64.deb
libpam0g	1.7.0-5	4f5bde27d8df2de6ea8990319b42d9974f56a3ba9907ce7296fd0f8964fc9fb1	69880	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/p/pam/libpam0g_1.7.0-5_amd64.deb
libpcre2-8-0	10.46-1~deb13u3	e226f661d918f04daf38cdbc4806b7ed7d6ef95c7eb0ade692fc350e31970040	299148	http://snapshot.debian.org/archive/debian-security/20261003T000000Z/pool/updates/main/p/pcre2/libpcre2-8-0_10.46-1~deb13u3_amd64.deb
libpopt0	1.19+dfsg-2	07f649b706852af937654295697dcfc7858f3295718ec18681dce1704663e4f2	43844	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/p/popt/libpopt0_1.19+dfsg-2_amd64.deb
libproc2-0	2:4.0.4-9	c9d61caab1b2ddfc3f17edb95be31b9809fcb2daf27d853dff615bc4ebd08b4b	65596	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/p/procps/libproc2-0_4.0.4-9_amd64.deb
libpython3-stdlib	3.13.5-1	7e142ed64a81ccdd39714f213467bd365736ef341adb2be11be981f638b9175f	10180	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/p/python3-defaults/libpython3-stdlib_3.13.5-1_amd64.deb
libpython3.13-minimal	3.13.5-2+deb13u5	a4aa6a9a8c77f87bfe545e1d14ec42c001d189ace90e3aa75deec882b39dee49	863168	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/p/python3.13/libpython3.13-minimal_3.13.5-2+deb13u5_amd64.deb
libpython3.13-stdlib	3.13.5-2+deb13u5	db161322a3481d2c0c3b9a3b9a03c3ab0e2b1718f54b88755fb4a3f939165b84	1958624	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/p/python3.13/libpython3.13-stdlib_3.13.5-2+deb13u5_amd64.deb
libreadline8t64	8.2-6	eeadf2b5e755c9f183883feea2d9b5b28560284275d5f54d3e55d0923b1d0967	168832	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/r/readline/libreadline8t64_8.2-6_amd64.deb
libsasl2-2	2.1.28+dfsg1-9	66e49d7ae026811b49a0050f18b0325960a2625ffd1ff60d91b7844a815fa9d2	57512	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/c/cyrus-sasl2/libsasl2-2_2.1.28+dfsg1-9_amd64.deb
libsasl2-modules-db	2.1.28+dfsg1-9	a5c38659fbd62c33c6d9bfa2be43e75a572d1818531aad32dd74d0a58cc4bd19	19768	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/c/cyrus-sasl2/libsasl2-modules-db_2.1.28+dfsg1-9_amd64.deb
libselinux1	3.8.1-1	68bb8d32bd8d6d7d2f5952a169db03d1484b46ae1e52abccdec42a19dccea5d5	84680	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/libs/libselinux/libselinux1_3.8.1-1_amd64.deb
libsemanage-common	3.8.1-1	65375d886749c236bd1da4d9990b7c2469d2fe66019a28e5614f6814376d3dcb	7812	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/libs/libsemanage/libsemanage-common_3.8.1-1_all.deb
libsemanage2	3.8.1-1	f97da7505d17ad3bdd8fc56302256df7e158e5e0d8b02cb766654199cbc406a9	95284	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/libs/libsemanage/libsemanage2_3.8.1-1_amd64.deb
libsepol2	3.8.1-1	3595d2d3a6d24695e7953f4f00cdfe6974c9242d9a8dfee8998e77fbf7b2ba09	295588	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/libs/libsepol/libsepol2_3.8.1-1_amd64.deb
libsqlite3-0	3.46.1-7+deb13u2	0a459adaffd901109f7811ab65f58e7a957b4907d05539cf3d1184efdcde0468	914584	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/s/sqlite3/libsqlite3-0_3.46.1-7+deb13u2_amd64.deb
libssl3t64	3.5.7-1~deb13u3	ff16bc048bcd7d1b256094450b79c77947d8e76fe2a24bd99b91021d591fa074	2458176	http://snapshot.debian.org/archive/debian-security/20261003T000000Z/pool/updates/main/o/openssl/libssl3t64_3.5.7-1~deb13u3_amd64.deb
libstdc++6	14.2.0-19	ab1fa05837aa7a92aae748fd07a18a35f7d18bb4a71c4724fe2bbf0e32089de0	713628	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/g/gcc-14/libstdc++6_14.2.0-19_amd64.deb
libsystemd0	257.13-1~deb13u1	ab0d4127b5e46e6f8c015a1db15a62ba9ae274cdefa150083adf90ada0600ea1	454648	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/s/systemd/libsystemd0_257.13-1~deb13u1_amd64.deb
libtalloc2	2:2.4.3+samba4.22.11+dfsg-0+deb13u1	b4cc8aa74c8b7c05a64efb6577acc955f522a8e39d8f37fe60b1b3fe6634ce96	63644	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/s/samba/libtalloc2_2.4.3+samba4.22.11+dfsg-0+deb13u1_amd64.deb
libtasn1-6	4.20.0-2+deb13u1	23fec6e06583ce2bad9b2c04c9b485e90440e259b1abf8677cd80d3ce60831ad	50112	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/libt/libtasn1-6/libtasn1-6_4.20.0-2+deb13u1_amd64.deb
libtdb1	2:1.4.13+samba4.22.11+dfsg-0+deb13u1	49f805c2c7e6e29a9f026689241b493bbd2bbf56037f296a66991448954333d7	83444	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/s/samba/libtdb1_1.4.13+samba4.22.11+dfsg-0+deb13u1_amd64.deb
libtevent0t64	2:0.16.2+samba4.22.11+dfsg-0+deb13u1	f558a1c251768eeb8898e8ec8064f665653a10e2584785868ca36d412511d996	78548	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/s/samba/libtevent0t64_0.16.2+samba4.22.11+dfsg-0+deb13u1_amd64.deb
libtext-charwidth-perl	0.04-11+b4	3a1d44df306e0252e8a16df07eba457bc9f2ef736ee890a1c35ffdfd548eafa0	9476	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/libt/libtext-charwidth-perl/libtext-charwidth-perl_0.04-11+b4_amd64.deb
libtext-wrapi18n-perl	0.06-10	17f98c7c09af8ac3bdbfd5a5dad32f3f51c71b02cdfc411366f49092a395de85	8808	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/libt/libtext-wrapi18n-perl/libtext-wrapi18n-perl_0.06-10_all.deb
libtinfo6	6.5+20250216-2	8b9f6a7983e9418564e48a627518de4c03917b56efe68d7f3e93bd8fffa1cc10	348380	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/n/ncurses/libtinfo6_6.5+20250216-2_amd64.deb
libtirpc-common	1.3.6+ds-1	300f582e2c9151a8d329568c705cadc76252c417147312fe331c4560d2c7a6c3	11004	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/libt/libtirpc/libtirpc-common_1.3.6+ds-1_all.deb
libtirpc3t64	1.3.6+ds-1	ef4536c09bf5063554310e22d586ae90990100ba66d2fe7c35660e9e658913b6	83300	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/libt/libtirpc/libtirpc3t64_1.3.6+ds-1_amd64.deb
libunistring5	1.3-2	6dd3490bef06ea1096f32d10766b7e016cf579bfae8451d1b7df15ce05b8aa46	476768	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/libu/libunistring/libunistring5_1.3-2_amd64.deb
liburing2	2.9-1	4b589c00c7a51172aace2cb2fb3d3ff32daf86c644023126dcfcaa840cc941ea	26448	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/libu/liburing/liburing2_2.9-1_amd64.deb
libuuid1	2.41.5-0+deb13u1	c1bf4c4c3ff48c57fabf93307dfb56996b60cfa33927afc4158b5db36fb2721e	37848	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/u/util-linux/libuuid1_2.41.5-0+deb13u1_amd64.deb
libwbclient0	2:4.22.11+dfsg-0+deb13u1	a133ae6f275d737d26f642f9e7d22b0cbef16c8f3ea58f63ec9da8fbbb6bd2f8	72220	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/s/samba/libwbclient0_4.22.11+dfsg-0+deb13u1_amd64.deb
libzstd1	1.5.7+dfsg-1	2f6a2aeacfc925eba8b00ac9139bc4bfccf8cacb09eb93de067074b26948eef9	303836	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/libz/libzstd/libzstd1_1.5.7+dfsg-1_amd64.deb
login.defs	1:4.17.4-2	b4bbb8242cbf5588de7aafeb9d578a3dee1db2891f444ab454fd30bd80ccf2b4	186124	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/s/shadow/login.defs_4.17.4-2_all.deb
media-types	13.0.0	0788e4b0b72db1bcf74a19cb24c3511e7770ad0b341f0f30e361701c3072f53e	29336	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/m/media-types/media-types_13.0.0_all.deb
netbase	6.5	76bafa92947ebd37b0a6f9ec6570412041f56edebc1c66d323731216d318471e	12436	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/n/netbase/netbase_6.5_all.deb
openssl-provider-legacy	3.5.7-1~deb13u3	c12e0266c4780749a4702b8959ac979689f4182e18eed85a8a5eb90ed0e16eab	316452	http://snapshot.debian.org/archive/debian-security/20261003T000000Z/pool/updates/main/o/openssl/openssl-provider-legacy_3.5.7-1~deb13u3_amd64.deb
passwd	1:4.17.4-2	c5eaef41c6947d2888fa3462f787a7e02158b997bd0119154283f425ba57b8b8	1228860	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/s/shadow/passwd_4.17.4-2_amd64.deb
perl-base	5.40.1-6+deb13u1	b795464137a0f4d443fc9284f4b93e883fb83883cb533adf300ac660807a352a	1666320	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/p/perl/perl-base_5.40.1-6+deb13u1_amd64.deb
procps	2:4.0.4-9	4db90bb6776772fc52585d6b1fbfc52ec2a85480e1b4363b743fbb2ffa2a5375	882088	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/p/procps/procps_4.0.4-9_amd64.deb
python3	3.13.5-1	c1388174dc7140e6c19a6dd39f8a0dcb38a835cd66c65644e0dded43d5223cb0	28244	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/p/python3-defaults/python3_3.13.5-1_amd64.deb
python3-minimal	3.13.5-1	a5d2371bebf3689f676e3f3bae800371bcc4392a8a51269e23d528249b399615	27248	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/p/python3-defaults/python3-minimal_3.13.5-1_amd64.deb
python3.13	3.13.5-2+deb13u5	460c1fd72845516ac3ce9d1686916f3ab2e4c86f8a9746e14d26243a47e2b98d	757492	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/p/python3.13/python3.13_3.13.5-2+deb13u5_amd64.deb
python3.13-minimal	3.13.5-2+deb13u5	c1fda9e7b1bf15b2fa75a238d8a8710e142fe14c722fc650c5fc614f078c9073	2224552	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/p/python3.13/python3.13-minimal_3.13.5-2+deb13u5_amd64.deb
readline-common	8.2-6	f77e8aa0bf0de618f11cb0b21658a4ed60f177d63b3cf26d7fc3706b6d0eaaa9	69360	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/r/readline/readline-common_8.2-6_all.deb
samba	2:4.22.11+dfsg-0+deb13u1	97a45a98de720a3e1a2d20627a26d3294f3756b188e711eef42c1afdd3461565	1338156	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/s/samba/samba_4.22.11+dfsg-0+deb13u1_amd64.deb
samba-common	2:4.22.11+dfsg-0+deb13u1	d23f8db2eaa4b5d2f23b16299231b9496f2082f738d7e3555f2f77456688c84d	66256	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/s/samba/samba-common_4.22.11+dfsg-0+deb13u1_all.deb
samba-common-bin	2:4.22.11+dfsg-0+deb13u1	e8605cfa274680d27ab425ab907df6024e1903ccbaa1f22fb4cc9408fad57b16	1334668	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/s/samba/samba-common-bin_4.22.11+dfsg-0+deb13u1_amd64.deb
samba-libs	2:4.22.11+dfsg-0+deb13u1	1b35a51399d31a4cf56ab3340320d790ed28397f17bafad038c535a430de7f03	6048068	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/s/samba/samba-libs_4.22.11+dfsg-0+deb13u1_amd64.deb
sensible-utils	0.0.25	873a9b73c3478cc3148cdbf5cc2084949a0a8e4fa16131d1cbc895d2f1f3470e	24992	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/s/sensible-utils/sensible-utils_0.0.25_all.deb
tar	1.35+dfsg-3.1	214c02e1aa291076a3147b8a4c4cae02fadf4c67df629186e3e313726faef1de	814968	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/t/tar/tar_1.35+dfsg-3.1_amd64.deb
tzdata	2026c-0+deb13u1	813b9bbbe14ccda2b24617b8bade0ade4d745957e75921766c153d249886bd4c	264156	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/t/tzdata/tzdata_2026c-0+deb13u1_all.deb
ucf	3.0052	ab5a6d5a621ad07034ce29d0c2587e6e267ecd2975458b2c8a7d0ada77dcb95b	43296	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/u/ucf/ucf_3.0052_all.deb
zlib1g	1:1.3.dfsg+really1.3.1-1+b1	015be740d6236ad114582dea500c1d907f29e16d6db00566ca32fb68d71ac90d	88892	http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/z/zlib/zlib1g_1.3.dfsg+really1.3.1-1+b1_amd64.deb
ARTIFACTS
printf '%s\n' 'SMB_BUILD_PHASE=deb-download'
while IFS="$(printf '\t')" read -r name version digest size url; do
    target="/tmp/smb-locked-debs/$name.deb"
    /usr/lib/apt/apt-helper -o Acquire::Retries=0 -o Acquire::http::Timeout=30 download-file "$url" "$target" "SHA256:$digest"
    printf '%s  %s\n' "$digest" "$target" | sha256sum -c -
    test "$(wc -c < "$target")" -eq "$size"
    test "$(dpkg-deb -f "$target" Package)" = "$name"
    test "$(dpkg-deb -f "$target" Version)" = "$version"
done < /tmp/smb-artifacts.tsv
# No package may be fetched during dependency solving or installation.
printf '%s\n' 'SMB_BUILD_PHASE=install'
DEBIAN_FRONTEND=noninteractive apt-get --no-download --no-install-recommends --no-remove -y install /tmp/smb-locked-debs/*.deb
apt-get check
python3 - <<'PY'
import hashlib, json, pathlib, subprocess, sys
base = pathlib.Path("/opt/synthetic-smb")
lock = json.loads((base / "build-lock.json").read_text())
expected = {p["name"]: p["version"] for p in lock["packages"]}
rows = [line.split("\t") for line in pathlib.Path("/tmp/smb-artifacts.tsv").read_text().splitlines()]
assert len(rows) == len(expected) and len({r[0] for r in rows}) == len(rows)
repos = {r["suite"]: r["url"] for r in lock["repositories"]}
for row, pkg in zip(rows, lock["packages"]):
    assert row == [pkg["name"], pkg["version"], pkg["sha256"], str(pkg["size"]), repos[pkg["suite"]] + pkg["filename"]]
def installed(text):
    answer = {}
    for line in text.splitlines():
        name, version, status = line.split("\t")
        if status == "ii ":
            name = name.removesuffix(":amd64")
            assert name not in answer
            answer[name] = version
    return answer
before = installed(pathlib.Path("/tmp/smb-base-packages.tsv").read_text())
after = installed(subprocess.check_output(["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${db:Status-Abbrev}\n"], text=True))
assert all(after.get(name) == version for name, version in expected.items())
assert set(before) <= set(after), "package removal forbidden"
assert all(name in expected or before.get(name) == version for name, version in after.items()), "unlocked package change"
assert not ({"winbind", "libpam-winbind", "python3-samba"} & set(after))
assert ".".join(map(str, sys.version_info[:3])) == lock["runtime_expected"]["python_version"]
# Debian performs the actual dependency solver check above; retain source-level
# resolution edges in the lock for independent review.
PY
rm -rf /tmp/smb-locked-debs /var/lib/apt/lists/*
rm -f /tmp/smb-artifacts.tsv /tmp/smb-base-packages.tsv /var/cache/apt/archives/*.deb
BOOTSTRAP

COPY probe_samba.py rclone rclone-version.env /opt/synthetic-smb/

RUN <<'SEED'
set -eu
printf '%s\n' 'SMB_BUILD_PHASE=seed'
groupadd --gid 10001 synthetic-smb
useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin synthetic-smb
python3 - <<'PY'
import hashlib, json, os, pathlib, secrets, shutil, stat, subprocess
base = pathlib.Path("/opt/synthetic-smb")
lock_path = base / "build-lock.json"
lock = json.loads(lock_path.read_text())
expected = lock["runtime_expected"]
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
pins = dict(line.split("=", 1) for line in (base / "rclone-version.env").read_text().splitlines() if line and not line.startswith("#"))
assert pins["RCLONE_VERSION"] == expected["rclone_version"] == "1.75.1"
assert pins["RCLONE_LINUX_EXE_SHA256"] == expected["rclone_sha256"] == digest(base / "rclone")
for name in ("rclone", "probe_samba.py"):
    (base / name).chmod(0o555)
for name in ("build-lock.json", "rclone-version.env"):
    (base / name).chmod(0o444)
result = subprocess.run(["/usr/sbin/smbd", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, check=False)
assert result.returncode == 0 and result.stdout.decode("ascii").strip() == "Version " + expected["samba_version"], "Samba version drift"
os.umask(0o077)
stage = pathlib.Path("/tmp/smb-seed-build")
stage.mkdir(mode=0o700)
for name in ("private", "state", "cache", "lock", "pid", "ncalrpc"):
    (stage / name).mkdir(mode=0o700)
config = stage / "smb.conf"
config.write_text("\n".join([
    "[global]", "server role = standalone server", "security = user",
    "workgroup = SYNTHETIC", "netbios name = SYNTHETIC",
    "passdb backend = tdbsam:" + str(stage / "private/passdb.tdb"),
    "private dir = " + str(stage / "private"),
    "state directory = " + str(stage / "state"),
    "cache directory = " + str(stage / "cache"),
    "lock directory = " + str(stage / "lock"),
    "pid directory = " + str(stage / "pid"),
    "ncalrpc dir = " + str(stage / "ncalrpc"),
    "log file = " + str(stage / "seed.log"), "log level = 0",
    "interfaces = 127.0.0.1", "bind interfaces only = yes",
    "disable netbios = yes", "dns proxy = no",
]) + "\n", encoding="ascii")
password = secrets.token_urlsafe(32)
# Generated secret goes through stdin only; no secret-bearing output is emitted.
try:
    result = subprocess.run(["/usr/bin/smbpasswd", "-c", str(config), "-s", "-a", expected["username"]],
                            input=(password + "\n" + password + "\n").encode("ascii"),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
except subprocess.TimeoutExpired:
    raise SystemExit("synthetic passdb seed timed out") from None
if result.returncode != 0:
    raise SystemExit("synthetic passdb seed failed")
seed = base / "seed"
seed.mkdir(mode=0o700)
for name in ("passdb.tdb", "secrets.tdb"):
    source = stage / "private" / name
    assert source.is_file() and not source.is_symlink() and source.stat().st_size > 0, "missing private seed"
    shutil.copyfile(source, seed / name)
(seed / "credential.json").write_text(json.dumps({"schema_version": 1, "username": expected["username"], "password": password}) + "\n", encoding="ascii")
for path in seed.iterdir():
    assert path.is_file() and not path.is_symlink() and path.stat().st_nlink == 1
    path.chmod(0o600)
    os.chown(path, 10001, 10001)
os.chown(seed, 10001, 10001)
shutil.rmtree(stage)
print("SMB_BUILD_PHASE=manifest", flush=True)
manifest = {
    "schema_version": 1,
    "smbd_sha256": digest(pathlib.Path("/usr/sbin/smbd")),
    "testparm_sha256": digest(pathlib.Path("/usr/bin/testparm")),
    "rclone_sha256": digest(base / "rclone"),
    "probe_sha256": digest(base / "probe_samba.py"),
    "lock_sha256": digest(lock_path),
    "samba_version": expected["samba_version"],
}
(base / "runtime-manifest.json").write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="ascii")
(base / "runtime-manifest.json").chmod(0o444)
PY
SEED

USER 10001:10001
WORKDIR /opt/synthetic-smb
ENTRYPOINT ["python3", "/opt/synthetic-smb/probe_samba.py"]
CMD ["--lock", "/opt/synthetic-smb/build-lock.json"]
