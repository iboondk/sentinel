# Kibana queries for Sentinel logs

Index pattern: `sentinel-logs-*` (time field `@timestamp`, set by the Filebeat
`timestamp` processor from the app's `ts` field). Create it once in
Stack Management > Data Views.

The app writes one JSON object per request with these fields: `ts`, `variant`,
`method`, `path`, `query`, `status`, `remote_addr`, `event`
(`request`, `blocked_input` or `error`).

## Blocked inputs by remote_addr

KQL filter in Discover:

```kql
event : "blocked_input"
```

Count per source in a Lens bar chart: break down by `remote_addr`, metric
`Count of records`.

## 5xx rate

Lens formula for the share of responses that are server errors, over time:

```
count(kql='status >= 500 and status <= 599') / count()
```

Discover filter to list the 5xx responses themselves:

```kql
status >= 500 and status <= 599
```

## Top paths

Most requested paths, for all events:

```kql
event : *
```

Then break down a Lens table by `path`, metric `Count of records`, sorted
descending. To see only paths that triggered blocks, use:

```kql
event : "blocked_input"
```

and break down by `path`.

## Notes

- Results are local demo data only. Do not treat the counts as production
  traffic metrics.
- The `status` field is numeric in the index. Range queries work; do not quote
  the values.
