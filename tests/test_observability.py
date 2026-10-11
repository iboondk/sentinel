"""Structure tests for the observability stack and the STRIDE threat model.

These parse the compose, Filebeat, Wazuh and threat-model files. They do not
start docker, Elasticsearch or Wazuh. `docker compose config` and `up` are not
run by this suite (docker is not installed on the dev machine).
"""

import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
OBS = ROOT / "observability"
COMPOSE = OBS / "docker-compose.yml"
DOCKERFILE = ROOT / "apps" / "fixed" / "Dockerfile"
FILEBEAT = OBS / "filebeat" / "filebeat.yml"
RULES = OBS / "wazuh" / "local_rules.xml"
LOCALFILE = OBS / "wazuh" / "ossec-localfile.conf"
KIBANA_QUERIES = OBS / "kibana" / "README-queries.md"
THREAT_MODEL = ROOT / "docs" / "threat-model.md"
ENV_EXAMPLE = ROOT / ".env.example"

STRIDE_CATEGORIES = [
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information disclosure",
    "Denial of service",
    "Elevation of privilege",
]
RULE_ID_MIN, RULE_ID_MAX = 100100, 100199


@pytest.fixture(scope="module")
def compose():
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def services(compose):
    return compose["services"]


@pytest.fixture(scope="module")
def filebeat_cfg():
    return yaml.safe_load(FILEBEAT.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def rules_root():
    # local_rules.xml is a single <group> element, so it parses as-is. Wrap it
    # in a root anyway so the parser also copes with several top-level elements.
    text = RULES.read_text(encoding="utf-8")
    return ET.fromstring(f"<root>{text}</root>")


# --- docker-compose.yml -----------------------------------------------------


def test_compose_has_no_version_key(compose):
    assert "version" not in compose


def test_compose_services_exist(services):
    expected = {"elasticsearch", "kibana", "filebeat", "app-fixed", "wazuh-manager"}
    assert expected <= set(services)


def test_every_published_port_is_bound_to_loopback(services):
    checked = 0
    for name, svc in services.items():
        for port in svc.get("ports", []) or []:
            checked += 1
            assert str(port).startswith("127.0.0.1:"), f"{name} publishes {port!r}"
    assert checked >= 3


def test_elasticsearch_is_single_node_without_security(services):
    es = services["elasticsearch"]
    env = es["environment"]
    assert env["discovery.type"] == "single-node"
    assert str(env["xpack.security.enabled"]).lower() == "false"
    assert env["ES_JAVA_OPTS"].startswith("${ES_JAVA_OPTS:-")


def test_elastic_images_are_pinned_to_8_15(services):
    for name in ("elasticsearch", "kibana", "filebeat"):
        image = services[name]["image"]
        assert re.search(r":\$\{ELASTIC_VERSION:-8\.15\.\d+\}$", image), image


def test_wazuh_manager_is_in_wazuh_profile_only(services):
    wazuh = services["wazuh-manager"]
    assert wazuh["profiles"] == ["wazuh"]
    assert re.search(r"wazuh/wazuh-manager:\$\{WAZUH_VERSION:-4\.9\.\d+\}$", wazuh["image"])
    for name, svc in services.items():
        if name != "wazuh-manager":
            assert "profiles" not in svc, f"{name} must start without a profile"


def test_wazuh_mounts_rules_read_only_and_logs_volume(services):
    volumes = services["wazuh-manager"]["volumes"]
    assert any(
        v.startswith("./wazuh/local_rules.xml:") and v.endswith(":ro") for v in volumes
    ), volumes
    assert "sentinel-logs:/var/log/sentinel:ro" in volumes, volumes


def test_filebeat_mounts_config_read_only_and_logs_volume(services):
    volumes = services["filebeat"]["volumes"]
    assert any(
        v == "./filebeat/filebeat.yml:/usr/share/filebeat/filebeat.yml:ro" for v in volumes
    ), volumes
    assert "sentinel-logs:/var/log/sentinel:ro" in volumes, volumes


def test_app_fixed_logs_volume_is_read_write(services):
    # The app must be able to write its logs; only the readers mount them :ro.
    volumes = services["app-fixed"]["volumes"]
    assert "sentinel-logs:/var/log/sentinel" in volumes, volumes


def test_dockerfile_creates_and_chowns_compose_log_dir(services):
    # Regression: the named volume is seeded with the image directory's owner.
    # If the directory is missing or root-owned, the non-root app cannot write logs.
    log_dir = services["app-fixed"]["environment"]["SENTINEL_LOG_DIR"]
    text = DOCKERFILE.read_text(encoding="utf-8")
    assert re.search(rf"SENTINEL_LOG_DIR={re.escape(log_dir)}(\s|\\|$)", text, re.M), log_dir
    assert re.search(
        rf"RUN mkdir -p {re.escape(log_dir)} && chown sentinel:sentinel {re.escape(log_dir)}\s*$",
        text,
        re.M,
    ), log_dir
    assert re.search(r"^USER sentinel\s*$", text, re.M)


def test_app_fixed_builds_from_fixed_app_and_sets_log_dir(services, compose):
    app = services["app-fixed"]
    assert (OBS / app["build"]["context"]).resolve() == (ROOT / "apps" / "fixed").resolve()
    assert app["environment"]["SENTINEL_LOG_DIR"] == "/var/log/sentinel"
    assert any(v.startswith("sentinel-logs:/var/log/sentinel") for v in app["volumes"])
    assert "sentinel-logs" in compose["volumes"]


def test_secret_key_comes_from_env_without_default_value(services):
    value = services["app-fixed"]["environment"]["SENTINEL_SECRET_KEY"]
    assert value == "${SENTINEL_SECRET_KEY:-}"


def test_elasticsearch_health_check_exists(services):
    assert "healthcheck" in services["elasticsearch"]


def test_compose_has_no_password_text():
    assert "password" not in COMPOSE.read_text(encoding="utf-8").lower()


# --- filebeat.yml -----------------------------------------------------------


def test_filebeat_filestream_reads_sentinel_logs_as_ndjson(filebeat_cfg):
    (inp,) = filebeat_cfg["filebeat.inputs"]
    assert inp["type"] == "filestream"
    assert inp["paths"] == ["/var/log/sentinel/*.log"]
    ndjson = next(p["ndjson"] for p in inp["parsers"] if "ndjson" in p)
    assert ndjson["target"] == ""


def test_filebeat_output_and_index_pattern(filebeat_cfg):
    es = filebeat_cfg["output.elasticsearch"]
    assert es["hosts"] == ["elasticsearch:9200"]
    assert es["index"] == "sentinel-logs-%{+yyyy.MM.dd}"


def test_filebeat_template_name_and_pattern_match_index(filebeat_cfg):
    assert filebeat_cfg["setup.template.name"] == "sentinel-logs"
    assert filebeat_cfg["setup.template.pattern"] == "sentinel-logs-*"
    assert filebeat_cfg["setup.ilm.enabled"] is False


# --- Wazuh rules and localfile ----------------------------------------------


def test_wazuh_rules_group_is_sentinel(rules_root):
    groups = rules_root.findall("group")
    assert [g.get("name") for g in groups] == ["sentinel,"]


def test_wazuh_has_at_least_three_rules_in_range(rules_root):
    ids = [int(r.get("id")) for r in rules_root.iter("rule")]
    in_range = [i for i in ids if RULE_ID_MIN <= i <= RULE_ID_MAX]
    assert len(in_range) >= 3
    assert len(in_range) == len(ids), "every rule id must be in 100100-100199"


def _rule(rules_root, rule_id):
    for r in rules_root.iter("rule"):
        if r.get("id") == str(rule_id):
            return r
    raise AssertionError(f"rule {rule_id} missing")


def test_blocked_input_rule_is_level_6_on_event_field(rules_root):
    rule = _rule(rules_root, 100100)
    assert rule.get("level") == "6"
    field = rule.find("field[@name='event']")
    assert field is not None and field.text == "^blocked_input$"


def test_5xx_rule_is_level_5_on_status_field(rules_root):
    rule = _rule(rules_root, 100101)
    assert rule.get("level") == "5"
    field = rule.find("field[@name='status']")
    assert field is not None and field.text == r"^5\d\d$"


def test_frequency_rule_fires_at_10_per_remote_addr_in_60s(rules_root):
    rule = _rule(rules_root, 100102)
    assert rule.get("level") == "10"
    # Wazuh fires at the frequency-th matching event within the timeframe.
    assert rule.get("frequency") == "10"
    assert rule.get("timeframe") == "60"
    assert rule.find("if_matched_sid").text == "100100"
    assert rule.find("same_field").text == "remote_addr"


def test_localfile_block_collects_sentinel_json_logs():
    root = ET.parse(LOCALFILE).getroot()
    assert root.tag == "ossec_config"
    blocks = root.findall("localfile")
    assert len(blocks) == 1
    assert blocks[0].findtext("log_format") == "json"
    assert blocks[0].findtext("location") == "/var/log/sentinel/*.log"


# --- Kibana queries ---------------------------------------------------------


def test_kibana_queries_cover_required_views():
    text = KIBANA_QUERIES.read_text(encoding="utf-8")
    assert 'event : "blocked_input"' in text
    assert "remote_addr" in text
    assert "status >= 500" in text
    assert "path" in text


# --- .env.example -----------------------------------------------------------


def _env_map():
    out = {}
    for line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        out[key.strip()] = value.strip()
    return out


def test_env_example_has_required_keys_with_fake_values():
    env = _env_map()
    for key in ("ES_JAVA_OPTS", "KIBANA_PORT", "ES_PORT"):
        assert key in env
    assert env["SENTINEL_SECRET_KEY"] == "change-me-local-only"


# --- threat model -----------------------------------------------------------


def test_threat_model_contains_all_six_stride_categories():
    text = THREAT_MODEL.read_text(encoding="utf-8")
    for category in STRIDE_CATEGORIES:
        assert category in text, category


def test_threat_model_has_two_threats_per_category():
    text = THREAT_MODEL.read_text(encoding="utf-8")
    for prefix in ("S", "T", "R", "I", "D", "E"):
        ids = re.findall(rf"^\| {prefix}-\d+ \|", text, flags=re.MULTILINE)
        assert len(ids) >= 2, f"category {prefix} has {len(ids)} threats"


def test_threat_model_has_scope_assumptions_and_out_of_scope():
    text = THREAT_MODEL.read_text(encoding="utf-8")
    for heading in ("## 1. Scope", "## 4. Assumptions", "## 6. Out of scope"):
        assert heading in text, heading
