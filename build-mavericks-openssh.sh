#!/bin/bash

set -e

LIBRESSL_VERSION="3.8.2"
OPENSSH_VERSION="9.9p2"
BUILD_DIR="$(pwd)"
LIBRESSL_DIR="$BUILD_DIR/libressl-$LIBRESSL_VERSION"
OPENSSH_DIR="$BUILD_DIR/openssh-$OPENSSH_VERSION"
PREFIX="/usr"
SYSCONFDIR="/etc"

download_file() {
    local url=$1
    local output=$2
    echo "Downloading $output..."
    curl -L -o "$output" "$url" || curl -L -o "$output" "http${url#https}"
}

if [ ! -f "libressl-$LIBRESSL_VERSION.tar.gz" ]
then
    download_file "http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-$LIBRESSL_VERSION.tar.gz" \
                  "libressl-$LIBRESSL_VERSION.tar.gz"
fi

echo ""
echo "Building LibreSSL $LIBRESSL_VERSION..."
rm -rf "$LIBRESSL_DIR"
tar xzf "libressl-$LIBRESSL_VERSION.tar.gz"
cd "$LIBRESSL_DIR"

# Configure LibreSSL without assembly for Mavericks compatibility
./configure --prefix="$BUILD_DIR/libressl-install" \
            --enable-static \
            --disable-shared \
            --disable-asm \
            CFLAGS="-mmacosx-version-min=10.9 -O2"

make -j$(sysctl -n hw.ncpu)
make install
cd "$BUILD_DIR"

echo ""
echo "LibreSSL built successfully"

if [ ! -f "openssh-$OPENSSH_VERSION.tar.gz" ]
then
    download_file "http://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-$OPENSSH_VERSION.tar.gz" \
                  "openssh-$OPENSSH_VERSION.tar.gz"
fi

echo ""
echo "Extracting OpenSSH $OPENSSH_VERSION..."
rm -rf "$OPENSSH_DIR"
tar xzf "openssh-$OPENSSH_VERSION.tar.gz"
cd "$OPENSSH_DIR"

echo "Applying Apple-specific patches..."

if [ -f "$BUILD_DIR/keychain.h" ]
then
    cp "$BUILD_DIR/keychain.h" keychain.h
else
    echo "ERROR: keychain.h not found in $BUILD_DIR"
    exit 1
fi

if [ -f "$BUILD_DIR/keychain.m" ]
then
    cp "$BUILD_DIR/keychain.m" keychain.m
else
    echo "ERROR: keychain.m not found in $BUILD_DIR"
    exit 1
fi

sed -i '' 's/^LIBSSH_OBJS=/&keychain.o /' Makefile.in

if [ -f "$BUILD_DIR/ssh-add-keychain.patch" ]
then
    cp "$BUILD_DIR/ssh-add-keychain.patch" .
else
    echo "ERROR: ssh-add-keychain.patch not found in $BUILD_DIR"
    exit 1
fi
patch -p0 < ssh-add-keychain.patch
if [ $? -ne 0 ]
then
    echo "ERROR: Failed to apply Keychain patch to ssh-add.c"
    exit 1
fi

echo "Patching sshd-session.c for inetd compatibility..."

if [ -f "$BUILD_DIR/sshd-session-inetd-fix.patch" ]
then
    cp "$BUILD_DIR/sshd-session-inetd-fix.patch" .
else
    echo "ERROR: sshd-session-inetd-fix.patch not found in $BUILD_DIR"
    exit 1
fi
patch -p0 < sshd-session-inetd-fix.patch
if [ $? -ne 0 ]
then
    echo "ERROR: Failed to apply inetd fix patch to sshd-session.c"
    exit 1
fi

echo ""
echo "Configuring OpenSSH..."

./configure \
    --prefix="$PREFIX" \
    --sysconfdir="$SYSCONFDIR" \
    --with-ssl-dir="$BUILD_DIR/libressl-install" \
    --with-pam \
    --with-audit=bsm \
    --with-kerberos5=/usr \
    --with-sandbox=darwin \
    --with-privsep-path=/var/empty \
    --with-privsep-user=_sshd \
    --disable-strip \
    CFLAGS="-mmacosx-version-min=10.9 -I$BUILD_DIR/libressl-install/include -D__APPLE_KEYCHAIN__ -D__APPLE_MEMBERSHIP__ -D__APPLE_LAUNCHD__ -D__APPLE_SANDBOX_NAMED_EXTERNAL__" \
    LDFLAGS="-L$BUILD_DIR/libressl-install/lib -framework CoreFoundation -framework Security -framework DirectoryService -lbsm"

echo ""
echo "Building OpenSSH..."
make -j$(sysctl -n hw.ncpu)

echo ""
echo "Updating configuration files..."

sed -i '' \
    -e 's/#UsePAM no/UsePAM yes/' \
    -e 's|^#HostKey /etc/ssh/ssh_host_rsa_key|HostKey /etc/ssh_host_rsa_key|' \
    -e 's|^#HostKey /etc/ssh/ssh_host_ecdsa_key|HostKey /etc/ssh_host_ecdsa_key|' \
    sshd_config
echo "AcceptEnv LANG LC_*" >> sshd_config
# Maintain compatibility with vanilla Mavericks systems
echo "HostKeyAlgorithms +ssh-rsa" >> sshd_config
echo "PubkeyAcceptedAlgorithms +ssh-rsa" >> sshd_config
echo "HostKeyAlgorithms +ssh-rsa" >> ssh_config
echo "PubkeyAcceptedAlgorithms +ssh-rsa" >> ssh_config

echo ""
echo "Creating installation package..."

INSTALL_DIR="$BUILD_DIR/openssh-install"
SCRIPTS_DIR="$BUILD_DIR/pkg-scripts"
rm -rf "$INSTALL_DIR" "$SCRIPTS_DIR"
mkdir -p "$INSTALL_DIR"/{usr/bin,usr/sbin,usr/libexec,etc}
mkdir -p "$SCRIPTS_DIR"

cp ssh scp sftp ssh-add ssh-agent ssh-keygen ssh-keyscan "$INSTALL_DIR/usr/bin/"
cp sshd "$INSTALL_DIR/usr/sbin/"
cp sftp-server ssh-keysign ssh-pkcs11-helper ssh-sk-helper sshd-session "$INSTALL_DIR/usr/libexec/" 2>/dev/null || true

cp ssh_config sshd_config moduli "$INSTALL_DIR/etc/"

chmod 4755 "$INSTALL_DIR/usr/libexec/ssh-keysign"
chmod 600 "$INSTALL_DIR/etc/sshd_config"
chmod 644 "$INSTALL_DIR/etc/ssh_config"
chmod 644 "$INSTALL_DIR/etc/moduli"

cat > "$INSTALL_DIR/usr/libexec/sshd-keygen-wrapper" << 'WRAPPER_EOF'
#!/bin/sh

[ ! -f /etc/ssh_host_key ]     && ssh-keygen -q -t rsa1 -f /etc/ssh_host_key     -N "" -C "" < /dev/null > /dev/null 2> /dev/null
[ ! -f /etc/ssh_host_rsa_key ] && ssh-keygen -q -t rsa  -f /etc/ssh_host_rsa_key -N "" -C "" < /dev/null > /dev/null 2> /dev/null
[ ! -f /etc/ssh_host_dsa_key ] && ssh-keygen -q -t dsa  -f /etc/ssh_host_dsa_key -N "" -C "" < /dev/null > /dev/null 2> /dev/null
[ ! -f /etc/ssh_host_ecdsa_key ] && ssh-keygen -q -t ecdsa -f /etc/ssh_host_ecdsa_key -N "" -C "" < /dev/null > /dev/null 2> /dev/null

exec /usr/sbin/sshd $@
WRAPPER_EOF

chmod +x "$INSTALL_DIR/usr/libexec/sshd-keygen-wrapper"

# Create Distribution file for OS X 10.9.5 requirement
cat > "$BUILD_DIR/Distribution" << 'DIST_EOF'
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="1">
    <title>OpenSSH OPENSSH_VERSION_PLACEHOLDER</title>
    <allowed-os-versions>
        <os-version min="10.9.5" max="10.9.5" />
    </allowed-os-versions>
    <options customize="never" require-scripts="true" rootVolumeOnly="true" />
    <domains enable_anywhere="false" enable_currentUserHome="false" enable_localSystem="true" />
    <installation-check script="pm_install_check();" />
    <script><![CDATA[
    function pm_install_check() {
        if(system.version.ProductVersion) {
            var productVersion = system.version.ProductVersion;
            var majorVersion = parseInt(productVersion.split('.')[0]);
            var minorVersion = parseInt(productVersion.split('.')[1]);
            var patchVersion = parseInt(productVersion.split('.')[2] || 0);

            if (majorVersion == 10 && minorVersion == 9 && patchVersion == 5) {
                return true;
            }
        }
        my.result.type = 'Fatal';
        my.result.title = 'Incompatible OS Version';
        my.result.message = 'This package requires Mac OS X 10.9.5. Your computer is running ' + system.version.ProductVersion + '.';
        return false;
    }
    ]]></script>
    <pkg-ref id="Wowfunhappy.openssh">
        <bundle-version/>
    </pkg-ref>
    <choices-outline>
        <line choice="default">
            <line choice="Wowfunhappy.openssh"/>
        </line>
    </choices-outline>
    <choice id="default"/>
    <choice id="Wowfunhappy.openssh" visible="false">
        <pkg-ref id="Wowfunhappy.openssh"/>
    </choice>
    <pkg-ref id="Wowfunhappy.openssh" version="OPENSSH_VERSION_PLACEHOLDER" onConclusion="none">openssh-component.pkg</pkg-ref>
</installer-gui-script>
DIST_EOF

# Replace version placeholder in Distribution file
sed -i '' "s/OPENSSH_VERSION_PLACEHOLDER/$OPENSSH_VERSION/" "$BUILD_DIR/Distribution"

cat > "$SCRIPTS_DIR/preinstall" << 'PREINSTALL_EOF'
#!/bin/bash
set -e

BACKUP_DIR="/var/backups/vanilla-openssh"

if [ ! -d "$BACKUP_DIR" ]
then
    mkdir -p "$BACKUP_DIR"
    for f in /usr/bin/ssh* /usr/bin/scp /usr/bin/sftp /usr/sbin/sshd /usr/libexec/ssh* /usr/libexec/sftp-server /usr/libexec/sshd-keygen-wrapper
    do
        [ -f "$f" ] && cp -p "$f" "$BACKUP_DIR/" 2>/dev/null || true
    done
    [ -f /etc/ssh_config ] && cp -p /etc/ssh_config "$BACKUP_DIR/"
    [ -f /etc/sshd_config ] && cp -p /etc/sshd_config "$BACKUP_DIR/"
    [ -f /etc/moduli ] && cp -p /etc/moduli "$BACKUP_DIR/"
fi

exit 0
PREINSTALL_EOF

chmod +x "$SCRIPTS_DIR/preinstall"

cd "$BUILD_DIR"

pkgbuild \
    --root "$INSTALL_DIR" \
    --scripts "$SCRIPTS_DIR" \
    --identifier Wowfunhappy.openssh \
    --version "$OPENSSH_VERSION" \
    --install-location / \
    "openssh-component.pkg"

productbuild \
    --distribution "$BUILD_DIR/Distribution" \
    --package-path "$BUILD_DIR" \
    --resources "$BUILD_DIR" \
    "OpenSSH ${OPENSSH_VERSION} for Mavericks.pkg"

rm -f "openssh-component.pkg"

echo ""
echo "Build completed!"

# Cleanup
rm -rf "$LIBRESSL_DIR"
rm -rf "$OPENSSH_DIR"
rm -rf "libressl-install"
rm -rf "$INSTALL_DIR"
rm -rf "$SCRIPTS_DIR"
rm -f "$BUILD_DIR/Distribution"