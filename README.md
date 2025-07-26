# age x25519 identity implementation for yubikey

Create an [age](https://github.com/FiloSottile/age) X25519 identity using a YubiKey via the PIV interface.

This project uses [github.com/go-piv/piv-go](https://github.com/go-piv/piv-go) to access the YubiKey and derive an age-compatible identity from piv slot.

## Attribution

- [age](https://github.com/FiloSottile/age) – simple, modern, and secure file encryption
- [piv-go](https://github.com/go-piv/piv-go) – Go library for interacting with PIV tokens like YubiKey
