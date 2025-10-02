void	store_in_keychain(const char *filename, const char *passphrase);
void	remove_from_keychain(const char *filename);
char	*keychain_read_passphrase(const char *filename);

#ifdef __BLOCKS__
/* Block-based API for loading all identities from keychain */
int	load_identities_from_keychain(int (^add_identity)(const char *identity));
#endif