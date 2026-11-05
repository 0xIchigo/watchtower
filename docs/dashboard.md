# The dashboard

`pnpm dev serve` starts the dashboard at [http://127.0.0.1:4545](http://127.0.0.1:4545). If that port is taken, `serve` uses the next free one and prints the URL; choose your own with `--port`. Your API key is only ever read from `.env`, never typed into the browser. If you add it while the dashboard is running, click **Recheck**.

## Setting up a program

The **Setup** tab asks for a program ID.

**Discover** reads the program's upgrade authority, finds its Squads multisig and pulls its IDL, with likely admin-only instructions pre-ticked. You can also add mints, treasuries with outflow thresholds, extra keys to protect, and alert channels.

**Save** writes `watchtower.yaml` and starts monitoring immediately. Alert-channel secrets such as webhook URLs go into `.env`, not the YAML.

| Tab      | Shows                                                                                                                                                                                                                     |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Overview | Posture grade per program, multisig and mint; findings by severity; Parsed Streams health (subscriptions, notifications received, current slot); scan coverage and credits; **Open report** for the shareable HTML report |
| Activity | Every finding, live as it happens, filterable by severity, subject and text, with details and Orb links; plus the monitor log                                                                                             |
| Setup    | Everything above, editable; **Send test alert** checks your channels                                                                                                                                                      |

The dashboard runs the same monitor as `watch`, so you don't need both.

## Stopping and starting

- **Stop monitoring** in the header closes the stream and stops all alerts. The dashboard stays up, so you can still browse findings and the report.
- **Start monitoring** reconnects and catches up with Parsed Events on everything that happened while stopped. Those events alert as usual, so stopping never loses them.
- To shut down entirely, press Ctrl+C in the terminal running `serve` (or `watch`). The next start also catches up from where it stopped. The [CLI](cli.md) does the same things without a browser.

## Several monitors

- Each tab along the top is a monitor with its own programs, alert channels, history and stream connection. They run side by side, and stopping one leaves the others running.
- **+ New Monitor** adds one and opens its Setup. Name it there, or it takes its first program's name.
- **Delete Monitor** removes a monitor's config and finding history; alert-channel secrets stay in `.env`. Stop a monitor before deleting it. When your only monitor has nothing saved yet, there is nothing to delete and the button is hidden.
- Your first monitor is `watchtower.yaml`. Each new one is saved as `monitors/<name>.yaml` with its own state file, so the CLI can run it too: `pnpm dev watch -c monitors/kamino-lend.yaml`.
- Each monitor opens its own Parsed Streams connection and runs its own scans, so credits add up per monitor.

## Host your own dashboard

`serve` binds to `127.0.0.1` by default, where only your machine can reach it. To put it on a server, it needs one of two protections; it refuses to start on a public interface without one:

| Mode               | Set                        | Use                                                                                                                                             |
| ------------------ | -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| Private            | `WATCHTOWER_PASSWORD=…`    | Your team's monitor. Every page and API call needs the password (HTTP basic auth, any username).                                                |
| Public status page | `WATCHTOWER_READONLY=true` | Show the posture grade and live activity to anyone. Setup, discovery and every write are disabled, and the config is never sent to the browser. |

```sh
docker build -t watchtower .
docker run -d --name watchtower --restart unless-stopped \
  -p 4545:4545 -v "$PWD:/data" \
  -e WATCHTOWER_PASSWORD='choose-a-long-password' \
  watchtower
```

The image runs `serve` on `0.0.0.0:4545` and honours `PORT`, so it deploys as-is to Fly.io, Render, Railway or any container host. Serverless platforms such as Vercel do not fit: Watchtower keeps a stream connection, timers and a state file running between requests. Mount a volume at `/data` to keep `watchtower.yaml`, `.env` and `.watchtower/` across restarts. For a read-only public page, configure it privately first (or commit a `watchtower.yaml` without secrets), then redeploy with `WATCHTOWER_READONLY=true`. Put it behind HTTPS; most hosts do this for you.

**Forking:** the dashboard is plain HTML, CSS and JavaScript in [`ui/`](../ui), with no build step, so you can restyle it directly. The JSON API it uses is listed in [`AGENTS.md`](../AGENTS.md).
