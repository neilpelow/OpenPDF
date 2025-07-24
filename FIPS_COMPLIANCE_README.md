# OpenPDF FIPS Compliance Architecture

## Overview

OpenPDF now supports FIPS (Federal Information Processing Standards) compliance through a modular cryptographic architecture that allows switching between standard and FIPS-compliant Bouncy Castle implementations at runtime.

## Architecture

The FIPS compliance feature is implemented using a modular architecture with the following components:

### Core Components

1. **`ICryptoService` Interface** (`openpdf-core-modern/src/main/java/org/openpdf/text/pdf/crypto/ICryptoService.java`)
   - Defines all cryptographic operations needed by OpenPDF
   - Abstract interface that allows different implementations

2. **`CryptoServiceProvider`** (`openpdf-core-modern/src/main/java/org/openpdf/text/pdf/crypto/CryptoServiceProvider.java`)
   - Singleton utility class that uses Java's `ServiceLoader` to dynamically load the appropriate `ICryptoService` implementation
   - Provides a single point of access to cryptographic operations

3. **Refactored Core Classes**
   - All core OpenPDF classes now use `ICryptoService` instead of direct Bouncy Castle calls
   - Key classes: `PdfPKCS7`, `OcspClientBouncyCastle`, `PdfPublicKeySecurityHandler`, etc.

### Adapter Modules

1. **`openpdf-bc-adapter`** - Standard Bouncy Castle Implementation
   - Uses standard (non-FIPS) Bouncy Castle libraries
   - Provides full cryptographic functionality
   - Suitable for general use cases

2. **`openpdf-fips-adapter`** - FIPS-Compliant Implementation
   - Uses FIPS-certified Bouncy Castle libraries
   - Enforces FIPS-approved algorithms only
   - Suitable for government and regulated environments

## Usage

### Basic Usage

The architecture is designed to be transparent to existing code. Simply include the appropriate adapter module in your classpath:

```java
// Your existing OpenPDF code continues to work unchanged
Document document = new Document();
PdfWriter writer = PdfWriter.getInstance(document, new FileOutputStream("output.pdf"));

// Cryptographic operations automatically use the loaded adapter
writer.setEncryption(userPassword.getBytes(), ownerPassword.getBytes(), 
                    PdfWriter.ALLOW_PRINTING, PdfWriter.ENCRYPTION_AES_128);
```

### Choosing an Adapter

#### For Standard Use (Non-FIPS)
Include the standard Bouncy Castle adapter in your dependencies:

```xml
<dependency>
    <groupId>org.librepdf</groupId>
    <artifactId>openpdf-bc-adapter</artifactId>
    <version>${openpdf.version}</version>
</dependency>
```

#### For FIPS Compliance
Include the FIPS-compliant adapter instead:

```xml
<dependency>
    <groupId>org.librepdf</groupId>
    <artifactId>openpdf-fips-adapter</artifactId>
    <version>${openpdf.version}</version>
</dependency>
```

**Important**: Only include ONE adapter module. Including both will cause conflicts.

### Runtime Detection

The system automatically detects which adapter is available and uses it:

```java
ICryptoService cryptoService = CryptoServiceProvider.get();
System.out.println("Using: " + cryptoService.getClass().getSimpleName());
```

## FIPS Compliance Features

### FIPS-Approved Algorithms

The FIPS adapter enforces the use of FIPS-approved algorithms only:

- **Hash Functions**: SHA-1, SHA-256, SHA-384, SHA-512
- **Symmetric Encryption**: AES-128, AES-192, AES-256
- **Asymmetric Encryption**: RSA, DSA, ECDSA
- **Key Derivation**: PBKDF2

### Non-FIPS Algorithms

The following algorithms are **NOT** available in FIPS mode:
- MD5 (deprecated)
- RC4 (deprecated)
- DES (deprecated)
- Any other non-FIPS algorithms

### Error Handling

When using the FIPS adapter, attempting to use non-FIPS algorithms will throw `GeneralSecurityException`:

```java
try {
    // This will fail in FIPS mode
    cryptoService.digest(data, "MD5");
} catch (GeneralSecurityException e) {
    System.out.println("MD5 not allowed in FIPS mode: " + e.getMessage());
}
```

## Migration Guide

### From Previous OpenPDF Versions

1. **Update Dependencies**
   - Remove any direct Bouncy Castle dependencies from your project
   - Add the appropriate adapter module

2. **No Code Changes Required**
   - Existing OpenPDF code continues to work unchanged
   - The ServiceLoader mechanism handles adapter selection automatically

3. **Testing**
   - Test your application with both adapters to ensure compatibility
   - Verify FIPS compliance requirements are met when using the FIPS adapter

### Dependency Management

#### Maven
```xml
<dependencies>
    <!-- Core OpenPDF -->
    <dependency>
        <groupId>org.librepdf</groupId>
        <artifactId>openpdf-core-modern</artifactId>
        <version>${openpdf.version}</version>
    </dependency>
    
    <!-- Choose ONE adapter -->
    <dependency>
        <groupId>org.librepdf</groupId>
        <artifactId>openpdf-bc-adapter</artifactId>
        <version>${openpdf.version}</version>
    </dependency>
    <!-- OR -->
    <dependency>
        <groupId>org.librepdf</groupId>
        <artifactId>openpdf-fips-adapter</artifactId>
        <version>${openpdf.version}</version>
    </dependency>
</dependencies>
```

#### Gradle
```gradle
dependencies {
    implementation 'org.librepdf:openpdf-core-modern:${openpdf.version}'
    
    // Choose ONE adapter
    implementation 'org.librepdf:openpdf-bc-adapter:${openpdf.version}'
    // OR
    implementation 'org.librepdf:openpdf-fips-adapter:${openpdf.version}'
}
```

## Testing

### Running Tests

```bash
# Test with standard adapter
mvn test -Dcrypto.adapter=bc

# Test with FIPS adapter
mvn test -Dcrypto.adapter=fips
```

### Verification

The `CryptoServiceProviderTest` class verifies:
- ServiceLoader correctly loads the adapter
- Basic cryptographic operations work
- Algorithm mappings are correct
- ASN.1 operations function properly

## Troubleshooting

### Common Issues

1. **No ICryptoService Implementation Found**
   - Ensure you have included one of the adapter modules
   - Check that the ServiceLoader registration file exists in the adapter JAR

2. **FIPS Algorithm Errors**
   - Verify you're using FIPS-approved algorithms
   - Check the algorithm name mappings

3. **Class Loading Issues**
   - Ensure only one adapter is included
   - Check for conflicting Bouncy Castle versions

### Debug Mode

Enable debug logging to see which adapter is loaded:

```java
// Add to your application startup
System.setProperty("org.openpdf.crypto.debug", "true");
ICryptoService service = CryptoServiceProvider.get();
```

## Security Considerations

1. **FIPS Validation**
   - The FIPS adapter uses Bouncy Castle FIPS libraries
   - Verify the specific FIPS module version meets your requirements

2. **Algorithm Selection**
   - FIPS mode enforces approved algorithms only
   - Plan for algorithm migration if using deprecated algorithms

3. **Key Management**
   - Follow FIPS key management guidelines
   - Use appropriate key sizes and algorithms

## Support

For issues related to:
- **FIPS Compliance**: Check Bouncy Castle FIPS documentation
- **OpenPDF Integration**: Check OpenPDF documentation and issues
- **Algorithm Support**: Verify algorithm is FIPS-approved

## Version Compatibility

- **OpenPDF Core**: 1.3.30+
- **Bouncy Castle Standard**: 1.70+
- **Bouncy Castle FIPS**: 1.0.2+

## License

This FIPS compliance feature is subject to the same license as OpenPDF (LGPL/MPL). 