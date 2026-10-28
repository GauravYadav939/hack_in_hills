"""
Generate cryptographic keys for Glasshouse Broker.

This script generates NaCl signing keys for:
1. Capability tokens (token_signing_key)
2. Audit log signatures (audit_signing_key)

The keys are printed in base64 format for easy inclusion in .env files.
"""

import nacl.signing
import nacl.encoding
import sys


def generate_signing_key():
    """Generate a NaCl signing key pair and return the private key."""
    signing_key = nacl.signing.SigningKey.generate()
    # Return the private key in base64 format
    return signing_key.encode(encoder=nacl.encoding.Base64Encoder).decode('ascii')


def main():
    print("=" * 70)
    print("Glasshouse Cryptographic Key Generator")
    print("=" * 70)
    print()
    print("Generating secure signing keys...")
    print()

    # Generate token signing key
    token_key = generate_signing_key()
    print("TOKEN_SIGNING_KEY (for capability tokens):")
    print(f"  {token_key}")
    print()

    # Generate audit signing key
    audit_key = generate_signing_key()
    print("AUDIT_SIGNING_KEY (for audit log):")
    print(f"  {audit_key}")
    print()

    print("=" * 70)
    print("IMPORTANT SECURITY NOTES:")
    print("=" * 70)
    print("1. Copy these keys to your .env file")
    print("2. NEVER commit these keys to version control")
    print("3. Keep .env in .gitignore")
    print("4. Generate NEW keys for production deployments")
    print("5. Store production keys in a secure secret manager")
    print()
    print("Add these lines to your .env file:")
    print()
    print(f"TOKEN_SIGNING_KEY={token_key}")
    print(f"AUDIT_SIGNING_KEY={audit_key}")
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nKey generation cancelled.")
        sys.exit(1)
    except Exception as e:
        print(f"\nError generating keys: {e}", file=sys.stderr)
        sys.exit(1)
