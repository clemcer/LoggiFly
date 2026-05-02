import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent / "app"))

from config.models.root import RootConfig # type: ignore

import json
schema = RootConfig.model_json_schema(mode="validation")
out = Path(__file__).resolve().parent.parent / "docs/guide/schema/v2_schema.json"
with open(out, "w") as f:
    json.dump(schema, f, indent=2)
