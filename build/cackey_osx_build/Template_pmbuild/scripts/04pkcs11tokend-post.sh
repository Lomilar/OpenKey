#!/bin/bash
chmod -R go+rX /Library/Security/tokend/PKCS11.tokend
chown -R root:wheel /Library/Security/tokend/PKCS11.tokend

# If on Sierra or newer, disable the pivtoken CryptoTokenKit
if [ "`uname -r | cut -d '.' -f 1`" -ge "16" ]; then
	security smartcards token -d com.apple.CryptoTokenKit.pivtoken
fi
