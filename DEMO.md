# Demo script: recording a GIF or Loom

This script shows the Sentinel stack in about 90 seconds. Record it once with the fixed app and the local Elastic stack. Use a Loom or Kap recording for the full run, and export a short GIF from the Kibana and gate sections for the README.

## Before you record

1. Use a clean terminal with a large font (16 pt or more) and a dark theme.
2. Use fake data only. The seeded users `alice/wonderland` and `bob/builder` are demo accounts. Never show a real `.env`.
3. Make sure Docker Desktop is running and nothing else uses ports 5002, 5601 or 9200.
4. Close other browser tabs. Set the browser zoom to 110%.
5. Clear old logs so the demo starts clean:

   ```bash
   cd observability && docker compose down -v && cd ..
   ```

## Scene 1: the stack starts (about 15 seconds)

Say: "One command brings up the fixed app, Elasticsearch, Kibana and Filebeat."

```bash
make up
cd observability
docker compose ps
```

Show the four services as `running` or `healthy`. Pause for two seconds on the output.

## Scene 2: the app answers (about 15 seconds)

Say: "The fixed app keeps the same API as the demo app. Here is the health route."

```bash
curl -s http://127.0.0.1:5002/health
curl -s "http://127.0.0.1:5002/search?q=ali"
curl -s -X POST http://127.0.0.1:5002/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"wonderland"}'
```

Expected: the health route returns `{"status":"ok","variant":"fixed"}`. The search returns `alice` in the result list. The login returns `"status":"ok"`.

## Scene 3: an attack is blocked and logged (about 20 seconds)

Say: "Now a classic injection attempt on the ping route. The fixed app validates the host and returns 400."

```bash
curl -s -i "http://127.0.0.1:5002/ping?host=8.8.8.8;id"
```

Then show the log line:

```bash
docker compose exec app-fixed tail -n 3 /var/log/sentinel/fixed.log
```

Point out the `"event":"blocked_input"` field. Say: "Every request is one JSON line, so Filebeat can ship it without a parser change."

## Scene 4: the logs reach Kibana (about 20 seconds)

Open `http://127.0.0.1:5601` in the browser. Go to Discover, pick the `sentinel-logs-*` data view, and search `event : blocked_input`. Show the matching document. Then open [`observability/kibana/README-queries.md`](observability/kibana/README-queries.md) and show one saved query.

If Kibana has no data view yet, create one for `sentinel-logs-*` with `@timestamp` as the time field. Do this before recording so the take stays smooth.

## Scene 5: the gate (about 15 seconds)

Say: "In CI the same scanners run on every pull request. The gate maps every finding to one severity scale and fails the job at high or worse."

Show `pipeline/gate.py` (the docstring at the top), then show the output of a real run:

```bash
python3 pipeline/gate.py --target fixed \
  --semgrep semgrep.json --trivy trivy.json \
  --gitleaks gitleaks.json --zap zap.json \
  --fail-on high --summary-out reports/after/summary.json
echo "exit status: $?"
```

Only record this scene when you have real scanner output from a CI run or a local run with the scanners installed. Do not record it with the fixture files in `tests/fixtures/`, and do not type numbers into the recording.

## Scene 6: the report (about 10 seconds)

Open `reports/before-after.md` from a real CI run artifact. Point at the severity table. Say: "The numbers come from the scanner output, not from hand-typed values."

If there is no real run yet, skip this scene and say so in the voice-over.

## Stop and clean up

```bash
cd observability && docker compose down
```

## Turning the recording into a GIF

1. Export the Loom or screen recording at 1280 px width, 12 to 15 frames per second.
2. Trim to scenes 2 and 3. These show the most in the least time.
3. Convert with ffmpeg, writing the output into the project folder:

   ```bash
   ffmpeg -i demo.mov -vf "fps=12,scale=1280:-1:flags=lanczos,split[a][b];[a]palettegen[p];[b][p]paletteuse" docs/demo.gif
   ```

4. Keep the GIF under 10 MB. Add it to the README under the title with `![demo](docs/demo.gif)`.

## Checklist before publishing

- [ ] No real credentials on screen. Only the fake `.env.example` values.
- [ ] Every number shown comes from a real run, and the run is named in the voice-over.
- [ ] The recording says which parts were not run locally (for example, the scanners and Docker if you recorded on a machine without them).
- [ ] The video title and description carry no AI attribution.
