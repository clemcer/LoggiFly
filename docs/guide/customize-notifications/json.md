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
  rules:
    - container_name: authelia
      keywords:
        - keyword: Unsuccessful 1FA authentication
          title_template: "Failed login from {{ remote_ip }}"
          message_template: |
            🚨 Failed Login Attempt:
            {{ msg }}
            🔎 IP: {{ remote_ip }}
            🕐 {{ time }}
```


## Nested JSON Structures

You can also extract data from nested JSON structures, including dictionaries and lists:

- <code v-pre>{{ key }}</code> or <code v-pre>{{ json["key"] }}</code> or <code v-pre>{{ json.key }}</code> for top-level fields (access via `json.key` is the same as <code v-pre>{{ key }}</code> and needed for edge cases that are described below)
- <code v-pre>{{ some['nested']['field'] }}</code> or <code v-pre>{{ some.nested.field }}</code>for nested fields
- <code v-pre>{{ list[0]['key'] }}</code> for list access (indices starting at 0)

::: info
Top level fields only work with <code v-pre>{{ key }}</code> when they are valid python identifiers, so alphanumeric and underscores only. For keys with hyphens, spaces, dots, or other special characters use <code v-pre>{{ json["key-with-hyphen"] }}</code> since <code v-pre>{{ key-with-hyphen }}</code> would not work.

The same thing applies to dot notation (<code v-pre>{{ dict.key }}</code>) only works for keys that are valid Python identifiers. For everything else use bracket notation.<br>
For example, use <code v-pre>{{ dict['key-with-hyphen'] }}</code> as <code v-pre>{{ dict.key-with-hyphen }}</code> would not work.
:::

Example JSON log entry:

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
  rules:
    - container_name: myapp
      keywords:
        - keyword: "login"
          message_template: |
            User {{ user['name'] }} logged in from {{ location['city'] }}
            Role: {{ user['roles'][0]['name'] }}
```

Output:

```
User admin logged in from Berlin
Role: superuser
```
