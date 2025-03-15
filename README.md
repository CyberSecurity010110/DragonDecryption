# DragonDecryptor.py is a comprehensive file security analysis and decryption tool that performs the following main functions:

    File Scanning and Analysis:
        Scans specified directories for files
        Analyzes files for encryption indicators and high entropy
        Calculates file entropy and checksums
        Performs content analysis and heuristic checks

    Decryption Capabilities:
        Attempts to decrypt files using multiple methods:
            OpenSSL with various ciphers and keys
            GPG decryption
        Handles read-only files during decryption process

    Security Analysis Features:
        YARA scanning for malware patterns
        Binwalk analysis for embedded files
        Signature validation for executables
        Suspicious string detection
        File metadata reporting

    Configuration and Logging:
        Configurable through JSON configuration file
        Comprehensive logging of all operations
        Customizable parameters for:
            Decryption keys and ciphers
            Entropy thresholds
            File size limits
            Suspicious patterns

    Post-Analysis Operations:
        Makes files executable if necessary
        Verifies file checksums
        Reports detailed metadata about processed files

The tool is designed to be highly configurable and can be customized through a config.json file, with sensible defaults if no configuration is provided. It provides detailed logging of all operations for audit purposes.
