# MFA Setup User Guide

## Quick Start

If your system administrator has enabled MFA, you need to set up two-factor authentication for sudo access. This guide walks you through the process.

## What You'll Need

1. **A smartphone** with an authenticator app:
   - Google Authenticator (recommended)
   - Microsoft Authenticator
   - Authy
   - 1Password
   - Any TOTP-compatible app

2. **Access to your server** via SSH or console

3. **Your sudo password**

## Step 1: Run Setup Command

```bash
sudo setup-mfa
```

You'll see:
```
 MFA Setup for [your-username]
════════════════════════════════════════════════

This setup will:
  • Generate a unique secret for your account
  • Display a QR code for your mobile authenticator app
  • Create emergency backup codes
  • Test the configuration

Proceed? (Y/n): Y
```

## Step 2: Scan QR Code

```
 Setting up Google Authenticator
════════════════════════════════════════════════

Scan this QR code with your authenticator app:

[QR CODE DISPLAYED HERE]

Can't scan? Enter this key manually:
Secret key: ABCD EFGH IJKL MNOP QRST UVWX YZ23 4567

Press ENTER after adding to your app...
```

### In Your Authenticator App:
1. Open your authenticator app
2. Tap "Add" or "+" button
3. Select "Scan QR Code" or "Scan Barcode"
4. Point camera at the QR code on screen
5. Your server will appear in the app

### Manual Entry Option:
1. Select "Enter manually" in your app
2. Account name: `yourserver.com (username)`
3. Key: Enter the secret key shown
4. Type: Time-based
5. Digits: 6

## Step 3: Save Backup Codes

```
Emergency Backup Codes
════════════════════════════════════════════════

IMPORTANT: Save these codes in a secure location!
Each code can only be used once.

12345678
23456789
34567890
45678901
56789012

These codes can be used if you lose your phone.
Store them in a password manager or secure location.

Press ENTER to continue...
```

**CRITICAL**: Save these codes immediately! Options:
- Password manager (recommended)
- Printed and stored securely
- Encrypted file backup
- NOT in plain text on your computer

## Step 4: Test Your Setup

```
 Testing MFA Configuration
════════════════════════════════════════════════

Enter the 6-digit code from your authenticator app: 123456

 MFA test successful! Your configuration is working correctly.
```

If the test fails:
- Check your phone's time is correct
- Wait for the next code (changes every 30 seconds)
- Verify you scanned the correct QR code

## Step 5: Confirmation

```
 MFA Setup Complete!
════════════════════════════════════════════════

Your account is now protected with MFA.
You'll need your authenticator app for all sudo commands.

Next sudo command will require:
1. Your password (as usual)
2. 6-digit code from your app

Try it now: sudo whoami
```

## Using MFA Daily

### Normal Usage
```bash
$ sudo apt update
[sudo] password for john: [enter password]
Verification code: [enter 6-digit code]
```

### Multiple Commands
```bash
# MFA is cached for a few minutes (same as password)
$ sudo apt update
Verification code: 123456
$ sudo apt upgrade  # No MFA needed if within timeout
```

### Scripts and Automation
If you have scripts using sudo with NOPASSWD:
- They continue working without MFA
- System automatically detects and bypasses MFA
- No changes needed to your scripts

## Troubleshooting

### "Verification code" Not Appearing
```bash
# Check your MFA status
sudo mfa-status

# If not configured, run setup again
sudo setup-mfa
```

### Wrong Code Error
1. **Check time sync on phone**
   - iPhone: Settings → General → Date & Time → Set Automatically
   - Android: Settings → System → Date & time → Automatic date & time

2. **Wait for next code**
   - Codes change every 30 seconds
   - Try the next code when it appears

3. **Re-sync in app**
   - Google Authenticator: Settings → Time correction → Sync now

### Lost Phone / Can't Access App

#### Option 1: Use Backup Code
```bash
$ sudo apt update
[sudo] password for john: [password]
Verification code: 12345678  # Enter backup code instead
```

#### Option 2: Emergency Bypass (Temporary)
```bash
# If you have console access
$ sudo emergency-mfa-bypass enable
# Gives you 60 minutes to fix MFA setup
```

#### Option 3: Contact Admin
Your system administrator can:
- Add you to emergency bypass group
- Reset your MFA configuration
- Provide recovery assistance

### Locked Out Completely

If you cannot sudo at all:

1. **Try console access** (if enabled without MFA)
2. **Use emergency admin account** (ask your admin)
3. **Boot to recovery mode** (physical access required)
4. **Contact your system administrator**

## Best Practices

### DO:
 Keep authenticator app updated
 Enable cloud backup in your authenticator app
 Store backup codes securely
 Set up MFA on multiple devices (tablet as backup)
 Test MFA works before logging out

### DON'T:
 Share your MFA codes with anyone
 Store backup codes in plain text
 Disable phone lock screen
 Use SMS for MFA (not supported here)
 Ignore time sync warnings

## Managing Multiple Servers

### Naming Convention
In your authenticator app, use clear names:
```
prod-web01 (john)
prod-db01 (john)
dev-server (john)
```

### Organization
Most authenticator apps support:
- Folders or groups
- Search functionality  
- Icons and colors
- Export/import for backup

## Advanced Setup

### Multiple Devices
You can set up MFA on multiple devices:
```bash
# During setup, scan QR code with multiple devices
# Or add manually using the same secret key
# All devices will generate the same codes
```

### Backup Authenticator
1. Install authenticator on second device
2. Use same secret key from initial setup
3. Both devices now generate identical codes
4. Keep second device secure as backup

### Export/Import
Many authenticator apps support backup:
- **Google Authenticator**: Export accounts → Transfer accounts
- **Authy**: Automatic encrypted backup
- **1Password**: Syncs across devices
- **Microsoft Authenticator**: Cloud backup

## Frequently Asked Questions

### Q: How often do I need to enter MFA codes?
A: Same as your sudo password timeout (typically 5-15 minutes)

### Q: Can I disable MFA for my account?
A: No, only system administrators can modify MFA settings

### Q: What if my phone dies/breaks?
A: Use backup codes or emergency bypass procedures

### Q: Do I need internet for MFA?
A: No, TOTP codes work offline once set up

### Q: Can I use hardware tokens?
A: Currently only TOTP apps are supported

### Q: Why do codes change every 30 seconds?
A: Time-based security - prevents replay attacks

### Q: Can I extend the code validity window?
A: No, 30-second windows are standard for security

### Q: Will this affect my SSH key access?
A: No, SSH authentication is separate from sudo MFA

## Getting Help

### Check Status
```bash
sudo mfa-status
```

### View Help
```bash
setup-mfa --help
emergency-mfa-bypass help
```

### Documentation
```bash
man google-authenticator
cat /usr/local/share/eos/mfa-recovery.md
```

### Support Contacts
- System Administrator: [configured by your org]
- Emergency Contact: [configured by your org]
- Documentation: `/usr/local/share/eos/`

## Summary Checklist

- [ ] Authenticator app installed on phone
- [ ] QR code scanned successfully  
- [ ] Backup codes saved securely
- [ ] Test passed successfully
- [ ] Can sudo with password + MFA code
- [ ] Backup plan understood (codes/emergency)
- [ ] Second device configured (optional)
- [ ] Authenticator app backed up (optional)

Remember: MFA significantly improves security. The minor inconvenience of entering a code protects against password compromise, phishing, and unauthorized access.