# CoreGuard

A secure smart contract for managing personal data on the Stacks blockchain. CoreGuard allows users to:

- Store encrypted personal data securely on-chain
- Control access to their data through permissions
- Revoke access when needed
- Track all data access attempts

## Features
- Encrypted data storage
- Granular permission controls
- Access logging
- Permission revocation
- Data ownership verification
- Time-based access expiration
- Batch permission management

## Security
All data stored through CoreGuard is encrypted before being stored on-chain. Only authorized users with proper permissions can access the decrypted data.

## New Features

### Time-based Access Expiration
- Grant temporary access to data with automatic expiration
- Set custom expiration timestamps for each permission grant
- Permissions automatically expire after the specified time
- Optional expiration allows for permanent access when needed

### Batch Permission Management
- Grant access to multiple users in a single transaction
- Manage permissions for groups of users efficiently
- Revoke access for entire batches at once
- Track batch permissions with unique batch IDs
- Support for up to 50 users per batch
