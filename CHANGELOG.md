# Changelog

## Unreleased

No changes.

## 0.3.0 - 2019-08-06

### Breaking changes

* The update of ring to 0.16.0 was reverted, bringing us back to 0.14.6. This
  was done to improve compatibility with the rest of the ecosystem, which still
  partially relies on 0.14 (most notable rustls).

## 0.2.0 - 2019-07-24

### Breaking changes

* `AppImage::sign`, `Gbl::sign` and `Gbl::verify_signature` now take P-256 keys
  in a different format (`P256KeyPair` and `P256PublicKey`).

### New Features

* Added proper types for P-256 public keys and key pairs. They can now be loaded
  from DER-encoded binary data instead of just PEM.
  
### Other Changes

* Drop dependency on `rand`, instead using `ring` to generate the random nonce.

## 0.1.3 - 2019-03-06

* Add support for upcasting from concrete encryption/signature type states to
  `MaybeEncrypted`/`MaybeSigned`.

## 0.1.2 - 2019-03-06

* Fix handling of `AppProperties` versions by accepting minor version bumps.

## 0.1.1 - 2019-01-21

* Update dependencies.

## 0.1.0 - 2018-12-20

* Initial release.
