import math
import string

def estimate_crack_time(password: str) -> str:
    """
    Rough estimate for cracking time in seconds based on charset and length.
    """
    length = len(password)
    charset_size = 0
    if any(c.islower() for c in password):
        charset_size += 26
    if any(c.isupper() for c in password):
        charset_size += 26
    if any(c.isdigit() for c in password):
        charset_size += 10
    if any(c in string.punctuation for c in password):
        charset_size += len(string.punctuation)

    if charset_size == 0 or length == 0:
        return "Instantly cracked"

    combinations = pow(charset_size, length)
    guesses_per_second = 1e9  # Assume 1 billion guesses/sec attacker speed

    seconds = combinations / guesses_per_second

    units = [('seconds', 1),
             ('minutes', 60),
             ('hours', 3600),
             ('days', 86400),
             ('years', 3.154e7),
             ('centuries', 3.154e9)]

    for name, sec in units:
        if seconds < sec * 1000:
            val = seconds / sec
            return f"{val:.2f} {name}"
    return "Centuries"

def caesar_rotator(text: str, shift: int=3) -> str:
    # Returns Caesar ciphered text for educational purpose
    result = []
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base + shift) % 26 + base))
        else:
            result.append(c)
    return ''.join(result)


from PIL import Image

def decrypt_steg_password(steg_image, user):
    """
    Extract hidden ASCII message from LSB of image pixels in steg_image.
    """
    # steg_image is a StegImage model instance
    # user param is not used here, but you can extend to decrypt with user key if needed

    img_path = steg_image.image.path  # Full system path to file
    try:
        img = Image.open(img_path)
        pixels = img.load()

        width, height = img.size
        bits = []

        for y in range(height):
            for x in range(width):
                r, g, b = pixels[x, y][:3]  # Ignore alpha channel if exists
                # Extract LSB from each color channel
                bits.append(r & 1)
                bits.append(g & 1)
                bits.append(b & 1)

        # Group bits into bytes (8 bits)
        bytes_data = []
        for i in range(0, len(bits), 8):
            byte = 0
            for bit_i in range(8):
                if i + bit_i < len(bits):
                    byte = (byte << 1) | bits[i + bit_i]
            bytes_data.append(byte)

        # Convert bytes to string until null terminator or max length
        message_bytes = []
        for b in bytes_data:
            if b == 0:
                break
            message_bytes.append(b)

        hidden_message = bytes(message_bytes).decode('ascii', errors='ignore')
        return hidden_message

    except Exception as e:
        # You can log error e if needed
        return ''