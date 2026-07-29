# Wazuh single-node deployment

The guardrail does not need Wazuh to work. This is for central pattern
management and alerting; without it the daemon runs on bundled patterns and
every enforcement point behaves identically.

## Prerequisites

```bash
# The indexer will not start without this. It does not survive a reboot.
sudo sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-wazuh.conf
```

Ports used: `1514`, `1515`, `55000`, `9200`, `443`. Verify they are free —
on this host the existing llm-proxy stack holds `3000`, `8000`, `8080`, `5433`,
which do not collide.

## Deploy

```bash
git clone https://github.com/wazuh/wazuh-docker.git -b v4.9.0
cd wazuh-docker/single-node
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d
```

First start takes several minutes. The API answers on `https://localhost:55000`
with a self-signed certificate.

## Publish the pattern file

The API endpoint for group files is **GET-only** — there is no PUT or POST.
Publishing means writing the file on the manager. This was accepted
deliberately so Wazuh stays the single management plane.

```bash
MANAGER=single-node-wazuh.manager-1     # docker ps to confirm

docker exec "$MANAGER" mkdir -p /var/ossec/etc/shared/guardrail
docker cp ../../wazuh/patterns.json "$MANAGER":/var/ossec/etc/shared/guardrail/patterns.json
docker exec "$MANAGER" chown wazuh:wazuh /var/ossec/etc/shared/guardrail/patterns.json
```

Confirm the fetch path — **`raw=true` is mandatory**; without it the response
falls through to `_rcl2json()` and comes back mangled:

```bash
TOKEN=$(curl -sk -u wazuh:<password> -X POST \
  'https://localhost:55000/security/user/authenticate' | python3 -c 'import sys,json;print(json.load(sys.stdin)["data"]["token"])')

curl -sk -H "Authorization: Bearer $TOKEN" \
  'https://localhost:55000/groups/guardrail/files/patterns.json?raw=true' \
  | python3 -m json.tool | head
```

## Install the rules

```bash
docker cp ../../wazuh/local_rules.xml "$MANAGER":/var/ossec/etc/rules/local_rules.xml
docker exec "$MANAGER" /var/ossec/bin/wazuh-control restart
```

Then set the expected pattern SHA in rule `100220` so drift detection has a
baseline (`guardrailctl patterns` prints it).

## Verify the decoder

The single most important check: guardrail fields must decode as **scalars**.

```bash
docker exec -i "$MANAGER" /var/ossec/bin/wazuh-logtest
# paste one line from ~/.local/state/wazuh-guards/guardrail.json
```

Expect `guardrail.action`, `guardrail.has_high`, `guardrail.max_severity`.
If you instead see `findings.0.rule`, the event shape is wrong — Wazuh's JSON
decoder flattens arrays, and a rule matching `findings.0.severity` would miss a
high-severity finding at index 1.

## Point the daemon at it

```bash
cat > ~/.config/wazuh-guards/wazuh.env <<'EOF'
WAZUH_API_URL=https://127.0.0.1:55000
WAZUH_API_USER=wazuh
WAZUH_API_PASSWORD=<password>
WAZUH_API_VERIFY_TLS=false
EOF
chmod 600 ~/.config/wazuh-guards/wazuh.env

guardrailctl restart
guardrailctl patterns          # source should now read "wazuh"
```

`WAZUH_API_VERIFY_TLS=false` is for the default self-signed cert. Replacing the
certificate and leaving verification on is the better end state.

## Confirm Wazuh is not in the enforcement path

```bash
docker compose stop
guardrailctl test "my key is AKIAIOSFODNN7EXAMPLE"   # must still block
docker compose start
```

Patterns are fetched at daemon startup and cached. A scan never touches the
network, so a stopped manager changes nothing about enforcement.
