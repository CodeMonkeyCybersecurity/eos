"""
EOS Random String Generator Module for Salt
Provides secure random string generation when Vault is not available
"""

import string
import secrets
import hashlib
import base64
import os
from datetime import datetime

__virtualname__ = 'eos_random'

def __virtual__():
    """
    Only load if we're in the right environment
    """
    return __virtualname__

def get_str(length=32, chars=None, prefix=''):
    """
    Generate a cryptographically secure random string
    
    Args:
        length (int): Length of the random string to generate
        chars (str): Characters to use for generation (default: alphanumeric)
        prefix (str): Optional prefix to add to the string
        
    Returns:
        str: Random string of specified length
        
    Example:
        salt['eos_random.get_str'](32)
        salt['eos_random.get_str'](16, chars='abcdef0123456789', prefix='hex_')
    """
    if chars is None:
        chars = string.ascii_letters + string.digits
    
    # Use secrets module for cryptographically strong randomness
    result = ''.join(secrets.choice(chars) for _ in range(length))
    
    return prefix + result

def hex_str(length=64):
    """
    Generate a random hexadecimal string
    
    Args:
        length (int): Length of the hex string to generate
        
    Returns:
        str: Random hexadecimal string
    """
    return get_str(length, chars='abcdef0123456789')

def password(length=16, include_special=True):
    """
    Generate a secure password
    
    Args:
        length (int): Length of password
        include_special (bool): Include special characters
        
    Returns:
        str: Secure password
    """
    chars = string.ascii_letters + string.digits
    if include_special:
        chars += "!@#$%^&*"
    
    # Ensure at least one of each character type
    password_chars = []
    password_chars.append(secrets.choice(string.ascii_lowercase))
    password_chars.append(secrets.choice(string.ascii_uppercase))
    password_chars.append(secrets.choice(string.digits))
    if include_special:
        password_chars.append(secrets.choice("!@#$%^&*"))
    
    # Fill the rest
    for _ in range(length - len(password_chars)):
        password_chars.append(secrets.choice(chars))
    
    # Shuffle
    secrets.SystemRandom().shuffle(password_chars)
    
    return ''.join(password_chars)

def api_key(prefix='eos_'):
    """
    Generate an API key
    
    Args:
        prefix (str): Prefix for the API key
        
    Returns:
        str: API key in format prefix_randomstring
    """
    # Generate 32 bytes of random data and base64 encode it
    random_bytes = secrets.token_bytes(32)
    key = base64.urlsafe_b64encode(random_bytes).decode('utf-8').rstrip('=')
    
    return f"{prefix}{key}"

def uuid():
    """
    Generate a random UUID
    
    Returns:
        str: Random UUID
    """
    import uuid as uuid_module
    return str(uuid_module.uuid4())

def deterministic(seed, length=32, chars=None):
    """
    Generate a deterministic "random" string based on a seed
    Useful for generating the same password across runs
    
    Args:
        seed (str): Seed string for generation
        length (int): Length of output
        chars (str): Characters to use
        
    Returns:
        str: Deterministic pseudo-random string
    """
    if chars is None:
        chars = string.ascii_letters + string.digits
    
    # Create a hash of the seed
    hash_obj = hashlib.sha256(seed.encode())
    hash_bytes = hash_obj.digest()
    
    # Use the hash to select characters
    result = []
    for i in range(length):
        # Get a byte from the hash (cycling if needed)
        byte_index = i % len(hash_bytes)
        char_index = hash_bytes[byte_index] % len(chars)
        result.append(chars[char_index])
    
    return ''.join(result)

def get_or_create(key, length=32, chars=None, storage_path='/etc/eos/salt_secrets.json'):
    """
    Get an existing random value by key or create a new one
    Provides persistence across Salt runs
    
    Args:
        key (str): Unique key for this secret
        length (int): Length if creating new
        chars (str): Characters to use if creating new
        storage_path (str): Where to store persistent secrets
        
    Returns:
        str: The random string (existing or newly created)
    """
    import json
    
    # Ensure storage directory exists
    storage_dir = os.path.dirname(storage_path)
    if not os.path.exists(storage_dir):
        os.makedirs(storage_dir, mode=0o700)
    
    # Load existing secrets
    secrets_data = {}
    if os.path.exists(storage_path):
        try:
            with open(storage_path, 'r') as f:
                secrets_data = json.load(f)
        except:
            secrets_data = {}
    
    # Return existing or create new
    if key in secrets_data:
        return secrets_data[key]
    else:
        new_secret = get_str(length, chars)
        secrets_data[key] = new_secret
        
        # Save back to file
        with open(storage_path, 'w') as f:
            json.dump(secrets_data, f, indent=2)
        
        # Secure the file
        os.chmod(storage_path, 0o600)
        
        return new_secret