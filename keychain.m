/*
 * Copyright (c) 2007-2016 Apple Inc. All rights reserved.
 *
 * @APPLE_BSD_LICENSE_HEADER_START@
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 3.  Neither the name of Apple Inc. ("Apple") nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @APPLE_BSD_LICENSE_HEADER_END@
 */

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <sys/stat.h>
#include <stdio.h>

#include "xmalloc.h"
#include "sshkey.h"
#include "ssherr.h"
#include "authfile.h"
#include "openbsd-compat/openbsd-compat.h"
#include "log.h"

/* Mavericks compatibility - we use the older Keychain API */
#define KEYCHAIN_SERVICE "SSH"

char *keychain_read_passphrase(const char *filename)
{
	OSStatus	ret = errSecSuccess;
	UInt32		passphraseLength = 0;
	void		*passphraseData = NULL;
	char		*passphrase = NULL;

	/* Use legacy SecKeychainFindGenericPassword for Mavericks compatibility */
	ret = SecKeychainFindGenericPassword(NULL,
					      strlen(KEYCHAIN_SERVICE), KEYCHAIN_SERVICE,
					      strlen(filename), filename,
					      &passphraseLength, &passphraseData,
					      NULL);

	if (ret == errSecSuccess) {
		passphrase = xmalloc(passphraseLength + 1);
		memcpy(passphrase, passphraseData, passphraseLength);
		passphrase[passphraseLength] = '\0';
		SecKeychainItemFreeContent(NULL, passphraseData);
		debug2("Found passphrase in keychain for: %s", filename);
	} else if (ret != errSecItemNotFound) {
		CFStringRef errorString = SecCopyErrorMessageString(ret, NULL);
		debug2("Keychain error while retrieving passphrase: %s",
		       errorString ? CFStringGetCStringPtr(errorString, kCFStringEncodingUTF8) : "unknown");
		if (errorString) CFRelease(errorString);
	}

	return passphrase;
}

void store_in_keychain(const char *filename, const char *passphrase)
{
	OSStatus		ret = errSecSuccess;
	SecKeychainItemRef	itemRef = NULL;

	/* Try to update existing item first */
	ret = SecKeychainFindGenericPassword(NULL,
					      strlen(KEYCHAIN_SERVICE), KEYCHAIN_SERVICE,
					      strlen(filename), filename,
					      NULL, NULL,
					      &itemRef);

	if (ret == errSecSuccess && itemRef) {
		/* Update existing */
		ret = SecKeychainItemModifyAttributesAndData(itemRef,
							      NULL,
							      strlen(passphrase),
							      passphrase);
		CFRelease(itemRef);
		if (ret == errSecSuccess) {
			fprintf(stderr, "Passphrase updated in keychain: %s\n", filename);
		} else {
			CFStringRef errorString = SecCopyErrorMessageString(ret, NULL);
			fprintf(stderr, "Could not update passphrase in keychain: %s\n",
				errorString ? CFStringGetCStringPtr(errorString, kCFStringEncodingUTF8) : "unknown");
			if (errorString) CFRelease(errorString);
		}
	} else {
		/* Add new item */
		ret = SecKeychainAddGenericPassword(NULL,
						     strlen(KEYCHAIN_SERVICE), KEYCHAIN_SERVICE,
						     strlen(filename), filename,
						     strlen(passphrase), passphrase,
						     NULL);
		if (ret == errSecSuccess) {
			fprintf(stderr, "Passphrase stored in keychain: %s\n", filename);
		} else if (ret == errSecDuplicateItem) {
			fprintf(stderr, "Passphrase already exists in keychain: %s\n", filename);
		} else {
			CFStringRef errorString = SecCopyErrorMessageString(ret, NULL);
			fprintf(stderr, "Could not store passphrase in keychain: %s\n",
				errorString ? CFStringGetCStringPtr(errorString, kCFStringEncodingUTF8) : "unknown");
			if (errorString) CFRelease(errorString);
		}
	}
}

void remove_from_keychain(const char *filename)
{
	OSStatus		ret = errSecSuccess;
	SecKeychainItemRef	itemRef = NULL;

	ret = SecKeychainFindGenericPassword(NULL,
					      strlen(KEYCHAIN_SERVICE), KEYCHAIN_SERVICE,
					      strlen(filename), filename,
					      NULL, NULL,
					      &itemRef);

	if (ret == errSecSuccess && itemRef) {
		ret = SecKeychainItemDelete(itemRef);
		CFRelease(itemRef);
		if (ret == errSecSuccess) {
			fprintf(stderr, "Passphrase removed from keychain: %s\n", filename);
		} else {
			CFStringRef errorString = SecCopyErrorMessageString(ret, NULL);
			fprintf(stderr, "Could not remove passphrase from keychain: %s\n",
				errorString ? CFStringGetCStringPtr(errorString, kCFStringEncodingUTF8) : "unknown");
			if (errorString) CFRelease(errorString);
		}
	}
}

int load_identities_from_keychain(int (^add_identity)(const char *identity))
{
	OSStatus		ret = errSecSuccess;
	SecKeychainSearchRef	search = NULL;
	SecKeychainItemRef	item = NULL;
	int			loaded_count = 0;

	/* Create a search for all SSH passwords */
	SecKeychainAttribute attr = {
		.tag = kSecServiceItemAttr,
		.length = strlen(KEYCHAIN_SERVICE),
		.data = (void *)KEYCHAIN_SERVICE
	};
	SecKeychainAttributeList attrList = {
		.count = 1,
		.attr = &attr
	};

	ret = SecKeychainSearchCreateFromAttributes(NULL,
						      kSecGenericPasswordItemClass,
						      &attrList,
						      &search);

	if (ret != errSecSuccess) {
		CFStringRef errorString = SecCopyErrorMessageString(ret, NULL);
		fprintf(stderr, "Could not search keychain: %s\n",
			errorString ? CFStringGetCStringPtr(errorString, kCFStringEncodingUTF8) : "unknown");
		if (errorString) CFRelease(errorString);
		return -1;
	}

	/* Iterate through all found items */
	while ((ret = SecKeychainSearchCopyNext(search, &item)) == errSecSuccess) {
		SecKeychainAttributeList *attrs = NULL;
		UInt32 passwordLength = 0;
		void *passwordData = NULL;

		/* Get the attributes (including account name which is the filename) */
		ret = SecKeychainItemCopyAttributesAndData(item,
							    NULL,
							    NULL,
							    &attrs,
							    &passwordLength,
							    &passwordData);

		if (ret == errSecSuccess && attrs != NULL) {
			/* Find the account attribute (filename) */
			for (UInt32 i = 0; i < attrs->count; i++) {
				if (attrs->attr[i].tag == kSecAccountItemAttr) {
					char *filename = xmalloc(attrs->attr[i].length + 1);
					memcpy(filename, attrs->attr[i].data, attrs->attr[i].length);
					filename[attrs->attr[i].length] = '\0';

					/* Try to add this identity */
					struct stat st;
					if (stat(filename, &st) == 0) {
						fprintf(stderr, "Adding key from keychain: %s\n", filename);
						if (add_identity(filename) == 0) {
							loaded_count++;
						}
					} else {
						debug2("Keychain has entry for missing file: %s", filename);
					}

					free(filename);
					break;
				}
			}

			SecKeychainItemFreeAttributesAndData(attrs, passwordData);
		}

		CFRelease(item);
	}

	if (search) {
		CFRelease(search);
	}

	if (loaded_count == 0) {
		fprintf(stderr, "No SSH identities found in keychain.\n");
	} else {
		fprintf(stderr, "Loaded %d SSH identit%s from keychain.\n",
			loaded_count, loaded_count == 1 ? "y" : "ies");
	}

	return (loaded_count > 0) ? 0 : -1;
}