from email.header import Header
from constants import EMOJI_PATTERN

def emoji_to_rfc2047(match):
    """Convert the matched emoji to RFC 2047 encoding."""
    emoji = match.group(0)
    return Header(emoji, "utf-8").encode()

def replace_emojis_with_rfc2047(text):
    """Replace all emojis in a text with RFC 2047 encoded forms."""
    return EMOJI_PATTERN.sub(emoji_to_rfc2047, text)