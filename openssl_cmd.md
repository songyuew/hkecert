# OpenSSL Commands

## Install OpenSSL

Check if OpenSSL is already installed

```
openssl version
```

If not installed, try this command

```
sudo apt-get update && sudo apt-get install openssl
```

## Extract Certificates and Private Key from `.p12` into `.pem` File (Signer Side)

```
openssl pkcs12 -in <P12_FILENAME>.p12 -out <TARGET_FILENAME>.pem -legacy
```

- The passphase for the `.p12` file is required.
- The `.pem` file output will be protected by a passphase.

## Create Signature

```
openssl dgst -sha256 -sign <PRIVATE_KEY>.pem -out <SIGNATURE_FILENAME>.sig <FILE_TO_SIGN>
```

- If the `.pem` file is passphase protected, you will be prompted to type it here.

## Convert Certificate to Public Key (Verifier Side)

```
openssl x509 -inform der -in <CERTIFICATE_FILENAME>.cer  -pubkey -noout > <PUBLIC_KEY_FILENAME>.pem
```

## Verify Signature

```
openssl dgst -sha256 -verify <PUBLIC_KEY_FILENAME>.pem -signature <SIGNATURE_FILENAME>.sig <MSG_FILENAME>
```

## Encrypt

```
openssl pkeyutl -encrypt -inkey <RECIPIENT_PUBLIC_KEY>.cer.pem -pubin -in <PLAINTEXT_FILE> -out <TARGET_CIPHER_FILE>.enc
```

## Decrypt

```
openssl pkeyutl -decrypt -inkey <PRIVATE_KEY>.pem -in <CIPHER_FILE>.enc > <TARGET_PLAIN_FILE>
```

- If the `.pem` file is passphase protected, you will be prompted to type it here.

## View Certificate Information

```
openssl x509 -in <CERTIFICATE>.cer -noout -text
```