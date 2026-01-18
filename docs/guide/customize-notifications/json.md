---
title: Extracting JSON Fields
---

# Extracting JSON Fields

When your logs are in JSON format, all JSON keys automatically become available as template fields in both `message_template` and `title_template`.

## How It Works

LoggiFly automatically parses JSON logs and makes all keys accessible in your templates. This works for both keyword and regex patterns.

Here is an example where you want to catch this long json log entry from Authelia: 

```json
{
  "level": "error",
  "method": "POST",
  "msg": "Unsuccessful 1FA authentication attempt by user 'example_user' and they are banned until 12:23:00PM on May 1 2025 (+02:00)",
  "path": "/api/firstfactor",
  "remote_ip": "192.168.178.191",
  "stack": [
    {
      "File": "github.com/authelia/authelia/v4/internal/handlers/response.go",
      "Line": 274,
      "Name": "doMarkAuthenticationAttemptWithRequest"
    },
    {
      "File": "runtime/asm_amd64.s",
      "Line": 1700,
      "Name": "goexit"
    }
  ],
  "time": "2025-05-01T14:19:29+02:00"
}
```

You can use `message_template` to extract fields from the json log entry:

```yaml
containers:
  authelia:
    keywords:
      - keyword: Unsuccessful 1FA authentication
        title_template: "Failed login from {remote_ip}"
        message_template: |
          🚨 Failed Login Attempt:
          {msg}
          🔎 IP: {remote_ip}
          🕐 {time}
```


## Nested JSON Structures

You can also extract data from nested json structures, including dictionaries and lists:

- {key} for top-level fields
- {dict[key]} for nested fields
- {list[index][key]} for list access (with indices starting at 0)

Example json log entry:

```json
{
  "event": "login",
  "user": {
    "name": "admin",
    "roles": [
      {"name": "superuser"},
      {"name": "editor"}
    ]
  },
  "location": {
    "city": "Berlin",
    "country": "Germany"
  }
}

```

Example template:

```yaml
containers:
  myapp:
    keywords:
      - keyword: "login"
        message_template: |
          User {user[name]} logged in from {location[city]}
          Role: {user[roles][0][name]}
```

Output:

```
User admin logged in from Berlin
Role: superuser
```

