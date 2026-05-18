# LoggiFly Config Migration: v1 → v2

Converts a LoggiFly v1.8.0 `config.yaml` to the v2 format.

## Usage

### Docker (recommended)

Mount the directory containing your config and run:

```bash
docker run --rm \
  -v /path/to/your/config/dir:/config \
  ghcr.io/clemcer/loggifly-migrate:v1-to-v2
```

By default the script reads `/config/config.yaml` and writes `/config/configv2.yaml`.

To specify custom paths inside the container:

```bash
docker run --rm \
  -v /path/to/your/config/dir:/config \
  ghcr.io/clemcer/loggifly-migrate:v1-to-v2 \
  -i /config/my_config.yaml -o /config/my_configv2.yaml
```

### Running directly

Requires Python 3.11+ and the project dependencies installed (`pip install -r requirements.txt`).

Run from the **project root**:

```bash
python scripts/v2_migration/convert.py -i /path/to/config.yaml -o /path/to/output.yaml
```

**Options:**

| Flag | Default | Description |
|------|---------|-------------|
| `-i`, `--input` | `/config/config.yaml` | Path to the v1 config file |
| `-o`, `--output` | `/config/configv2.yaml` | Path to write the converted v2 config |

## What the script does

1. Validates the input against the v1.8.0 model which also performs all legacy migrations up until v1.8
2. Renames deprecated fields (`action` → `container_action`, `hide_regex_in_title` → `hide_full_regex`, `excluded_keywords` → `ignore_keywords`)
3. Moves modular settings from `settings:` to a new `defaults:` section
4. Converts `containers` and `swarm_services` entries to the v2 rules format
5. Converts `hosts` entries to scoped rules
6. Validates the result against the v2 model
7. Writes the converted config

The original file is never modified.

## After conversion

Review the output file before using it. Check the logs printed during conversion. Warnings indicate fields that could not be migrated automatically and may require manual adjustment.
