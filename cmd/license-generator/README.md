# License Generator Tool

This tool provides two ways to generate license tokens for your application:

1. **Interactive Mode** - Guided dialog with user input
2. **Direct Mode** - Command-line arguments for automation

## Usage

### Interactive Mode (Recommended for first-time use)

```bash
go run cmd/license-generator/main.go --interactive
```

This will guide you through:
- Private key file path
- Hash key for machine encryption
- License name
- Validity period (in days)
- Access scopes
- Option to save to file

### Direct Mode (For automation/scripts)

```bash
go run cmd/license-generator/main.go <private_key_file> <hash_key> <license_name> <days_valid> <scopes>
```

**Example:**
```bash
go run cmd/license-generator/main.go private.pem myhashkey123 "Production License" 365 read,write,admin
```

## Parameters

- `private_key_file` - Path to your RSA private key file
- `hash_key` - 32-byte key for encrypting machine hash (AES-CBC)
- `license_name` - Descriptive name for the license
- `days_valid` - Number of days the license should be valid
- `scopes` - Comma-separated list of access scopes (e.g., `read,write,admin`)

## Available Scopes

- `read` - Read data access
- `write` - Write data access
- `admin` - Full system access

## Example Private Key

Create a private key file (e.g., `private.pem`):

```bash
# Generate RSA private key
openssl genrsa -out private.pem 2048

# Extract public key
openssl rsa -in private.pem -pubout -out public.pem
```

## Hash Key Requirements

The hash key must be exactly 32 bytes for AES-256 encryption. You can generate one:

```bash
# Generate random 32-byte key (hex encoded)
openssl rand -hex 32
```

## Output

The tool generates a JWT token that contains:
- Encrypted machine hardware hash
- License metadata (name, scopes)
- Validity period
- RSA signature

## Validation

Use the generated license token with the `license.Validate()` function in your application, providing the corresponding public key and hash key.

## Security Notes

- Keep private keys secure and never commit them to version control
- Use strong, random hash keys