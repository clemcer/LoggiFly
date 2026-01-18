---
title: Extracting Fields with Regex
---

# Extracting Fields with Regex

For plain text logs that aren't in JSON format, you can use regex patterns with **named capturing groups** to extract specific information and make it available as template fields.

## How Named Capturing Groups Work

The syntax for a named capturing group is `(?P<field_name>...)`:
- `P<field_name>` assigns the name `field_name` to the captured value
- The part inside the parentheses `(...)` is the pattern to match
- The captured value becomes available as `{field_name}` in both `message_template` and `title_template`

Example Log Line from audiobookshelf:

```txt
[2025-05-03 10:16:53.154] INFO: [SocketAuthority] Socket VKrcSNa--FjwAqmSAAAU disconnected from client "example user" after 11696ms (Reason: transport close)
```

## Example

```yaml
containers:
  audiobookshelf:
    keywords:
      - regex: '(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}.\d{3}).*Socket.*disconnected from client "(?P<user>[A-Za-z\s]+)"'
        title_template: "User activity detected for {user}"
        message_template: |
          🔎 The user {user} was seen!
          🕐 {timestamp}
```
<!-- 
**Result:**

Normal notification vs notification with custom templates:

![Template Comparison](/template_comparison.png)
 -->
