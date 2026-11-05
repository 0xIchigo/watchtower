# Watchtower

Security monitoring for Solana programs. Point it at a program ID and it will:

- **Grade its security posture**: who can upgrade it and who holds admin, whether each is a single key or a multisig, the threshold and time lock, and whether admin instructions are watched.
- **Scan its history** for deployments, authority changes, multisig proposals and membership changes, new listings and risk changes, mint authority changes, and vault outflows.
- **Alert in real time** to the terminal, Discord, Slack, Telegram, or any webhook, including one critical alert when several stages of a takeover line up.
- **Replay the past**: run every detector over an earlier window, for example to see what an exploit would have triggered.

It runs on your machine with your own Helius API key, as a CLI or as a web dashboard (`watchtower serve`). There's no database or account to set up, and you can host the dashboard yourself.

Watchtower is built on two Helius APIs:

- **Parsed Events** decodes every instruction in a transaction, inner instructions included, into named args and accounts. Watchtower uses its `scan` endpoint to search an address's history server-side by program, instruction name and discriminator.
- **Parsed Streams** delivers the same decoded transactions over a WebSocket as they confirm, filtered by program, instruction name and account.

Every call goes through the [Helius TypeScript SDK](https://github.com/helius-labs/helius-sdk) (`helius-sdk`): Parsed Events, Parsed Streams, DAS, `getProgramAccountsV2` and standard Solana RPC. If you fork Watchtower, `src/helius/` shows how to use each one.

## Quickstart: the dashboard

```sh
git clone https://github.com/0xIchigo/watchtower
cd watchtower
pnpm install && pnpm build
cp .env.example .env      # then set HELIUS_API_KEY in .env
pnpm dev serve
```

Open [http://127.0.0.1:4545](http://127.0.0.1:4545). If that port is taken, `serve` uses the next free one and prints the URL; choose your own with `--port`. Your API key is only ever read from `.env`, never typed into the browser. If you add it while the dashboard is running, click **Recheck**.

The **Setup** tab asks for a program ID.

**Discover** reads the program's upgrade authority, finds its Squads multisig and pulls its IDL, with likely admin-only instructions pre-ticked. You can also add mints, treasuries with outflow thresholds, extra keys to protect, and alert channels.

**Save** writes `watchtower.yaml` and starts monitoring immediately. Alert-channel secrets such as webhook URLs go into `.env`, not the YAML.

| Tab      | Shows                                                                                                                                                                                                                     |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Overview | Posture grade per program, multisig and mint; findings by severity; Parsed Streams health (subscriptions, notifications received, current slot); scan coverage and credits; **Open report** for the shareable HTML report |
| Activity | Every finding, live as it happens, filterable by severity, subject and text, with details and Orb links; plus the monitor log                                                                                             |
| Setup    | Everything above, editable; **Send test alert** checks your channels                                                                                                                                                      |

The dashboard runs the same monitor as `watch`, so you don't need both.

**Stopping and starting:**

- **Stop monitoring** in the header closes the stream and stops all alerts. The dashboard stays up, so you can still browse findings and the report.
- **Start monitoring** reconnects and catches up with Parsed Events on everything that happened while stopped. Those events alert as usual, so stopping never loses them.
- To shut down entirely, press Ctrl+C in the terminal running `serve` (or `watch`). The next start also catches up from where it stopped. The CLI steps below do the same things without a browser.

**Several monitors:**

- Each tab along the top is a monitor with its own programs, alert channels, history and stream connection. They run side by side, and stopping one leaves the others running.
- **+ New Monitor** adds one and opens its Setup. Name it there, or it takes its first program's name.
- **Delete Monitor** appears once a monitor is stopped or not configured yet. It removes the monitor's config and finding history; alert-channel secrets stay in `.env`.
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

The image runs `serve` on `0.0.0.0:4545` and honours `PORT`, so it deploys as-is to Fly.io, Render, Railway or any container host. Mount a volume at `/data` to keep `watchtower.yaml`, `.env` and `.watchtower/` across restarts. For a read-only public page, configure it privately first (or commit a `watchtower.yaml` without secrets), then redeploy with `WATCHTOWER_READONLY=true`. Put it behind HTTPS; most hosts do this for you.

**Forking:** the dashboard is plain HTML, CSS and JavaScript in [`ui/`](ui), with no build step, so you can restyle it directly. The JSON API it uses is listed in [`AGENTS.md`](AGENTS.md).

## Run it end to end from the CLI

Follow these steps in order.

### 1. Prerequisites

- Node.js 22 or later, and pnpm (`corepack enable`)
- A Helius API key from [dashboard.helius.dev](https://dashboard.helius.dev), with access to Parsed Events and Parsed Streams

### 2. Install, build and test

```sh
git clone https://github.com/0xIchigo/watchtower
cd watchtower
pnpm install
pnpm check   # format, lint, typecheck, tests, build
```

The tests run offline and never spend API credits. It includes Squads v3 and v4 decoding against real mainnet accounts (Jupiter's and Kamino's upgrade multisigs).

### 3. Set up a program

```sh
cp .env.example .env      # then set HELIUS_API_KEY in .env
pnpm dev init
```

`init` reads your key from `.env` and asks for:

| Prompt                  | Example                                                                  |
| ----------------------- | ------------------------------------------------------------------------ |
| Program ID              | `KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD` (Kamino Lend)              |
| Admin-only instructions | pre-selected from the program's IDL; press enter to accept               |
| Mints to watch          | `J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn` (JitoSOL, used in step 7) |
| Alert channels          | optional: Discord, Slack, Telegram, webhook                              |

Watchtower then reads the program's ProgramData account and finds the upgrade authority. If the authority is a Squads vault, it finds the multisig through the vault's Parsed Events history and confirms it by re-deriving the vault address:

```
◇  Discovered
│  Program data   9uSbGW1y9H5Av6H5TKxQ1wnFApSq2t3oEpfF2YfjDQGA
│  Authority      Squads v4 vault GzFgdRJXmawPhGeBsyRCDLx4jAKPsvbUqoqitzppkzkW
│  Multisig       6hhBGCtmg7tPWUSgp3LG6X2rsmYWAc4tNsA6G4CnfQbM
│  Threshold      5 of 10, time lock 86400s
```

This writes `watchtower.yaml` (see [`watchtower.example.yaml`](watchtower.example.yaml)). Any alert-channel secrets are added to `.env`, which stays mode 600 and git-ignored.

### 4. Check alert delivery

```sh
pnpm dev test-alert
```

This sends one sample critical alert to every configured channel. Fix any `Alert delivery failed` line before continuing.

### 5. Generate the posture report

```sh
pnpm dev report
open reports/watchtower-*.html
```

The first run scans 90 days of history for each watched address and records it without alerting. The terminal output and HTML report show:

- **Posture grade:** one per subject (program, multisig, mint), with the overall grade taken from the weakest subject
- **Activity:** every finding in the window
- **Coverage:** transactions scanned, matches and credits used, per scan

Each scan stops at `backfill.maxScannedTransactions`. A first scan reads newest-first, so on a busy address it covers only the most recent part of the lookback window and is marked **Recent only**; the older history is not scanned later. A later catch-up scan that stops at the budget is marked **Behind** and continues from the same place on the next run. Live monitoring sees every new transaction either way.

### 6. Start live monitoring

```sh
pnpm dev watch
```

Expected output:

```
14:02:11 Watchtower watching 1 program(s), 1 multisig(s), 1 mint(s)
14:02:11   Stream deployments: BPF loader, 1 account
14:02:12 Connected to Parsed Streams
14:02:12 Backfilling up to slot 464,612,034 with Parsed Events…
14:02:14   Kamino Lend deployments: 3 scanned, 0 new finding(s), up to date
```

On each connect, `watch` does four things:

1. Subscribes to Parsed Streams.
2. Delivers any alerts that `report` queued or that previously failed to send.
3. Scans from each saved cursor to the current slot, so nothing that happened while it was stopped is missed.
4. Moves the cursors forward as notifications arrive, once each one is processed.
5. Every 5 minutes, logs a heartbeat with the notifications received per subscription, so a quiet stream can be told apart from a broken one.

### 7. See a live alert

Program upgrades and multisig changes are rare. To see the pipeline fire within minutes, watch a high-traffic mint at `info` severity. JitoSOL mints new tokens on every stake deposit.

In `watchtower.yaml`, set the console sink to show everything:

```yaml
alerts:
  minSeverity: low
  sinks:
    - type: console
      minSeverity: info
```

Restart `pnpm dev watch`. Within a few minutes you should see:

```
 INFO  Tokens minted · JitoSOL · slot 464612301
  1.92 JitoSOL minted (0.00% of supply at discovery).
  https://orbmarkets.io/tx/…
```

### 8. Confirm gap-fill

Stop `watch` with Ctrl+C, wait two minutes, and start it again. The backfill lines report the transactions it missed while stopped, and their findings print as alerts.

### 9. Run it unattended

```sh
docker build -t watchtower .
docker run -d --name watchtower --restart unless-stopped -v "$PWD:/data" watchtower watch
docker logs -f watchtower
```

The container reads `watchtower.yaml` and `.env` from the mounted directory and keeps its state in `.watchtower/` there. Without `watch`, the image runs the dashboard instead (see above).

To start over from scratch, delete `.watchtower/state.json`.

### 10. Replay an exploit

`replay` runs every detector over a past window with Parsed Events and prints a timeline. It never sends alerts or touches your state file. With `--program`, no config is needed: admin instructions come from the IDL that was live when the window starts.

```sh
pnpm dev replay --program dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH:Drift \
  --from 2026-03-20 --to 2026-04-02 --no-program-scans
```

`--no-program-scans` skips scanning the program's whole transaction stream, which for a busy program runs to millions of transactions a day. Admin calls are still found through each admin key's own, much shorter history. `--budget` caps each scan, and `--json` saves the findings.

Discovery uses on-chain state as it is today: current multisig members, authorities and vault balances. Vault drains can't be replayed once a vault is empty.

## What it detects

| Detector                 | Signals                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `program-deployment`     | Upgrade, upgrade-authority transfer, program made immutable, program closed, loader-v4 migration, ProgramData resize. Each alert says whether it ran through a Squads multisig, by CPI, or by direct signature.                                                                                                                                                                                                                                                                                                                                                                                                     |
| `upgrade-proposal`       | Early warning: an upgrade, authority change, close or migration of a watched program **proposed** in its Squads multisig, before it can execute. Each alert states the approvals and time lock still standing in the way, and later approvals of that proposal alert too.                                                                                                                                                                                                                                                                                                                                           |
| `multisig-proposal`      | Every other proposal on a watched multisig, decoded into what it would do: "transfer 5,000 SOL to …", "call `update_admin` on Drift (admin-only)". **Critical** when an approval or execution is signed against a durable nonce, the pattern reported in the Drift takeover. High for a proposal from a member who has not proposed before, and escalated when a proposal executes within an hour of being created.                                                                                                                                                                                                 |
| `multisig-change`        | **Squads v4:** config proposals and executions (members, threshold, time lock, spending limits, rent collector), changes made by a config authority without a vote, spending-limit use. **Squads v3:** member and threshold changes. A threshold of 1 or a time lock of 0 is critical, and an execution inherits the severity of its proposal.                                                                                                                                                                                                                                                                      |
| `mint-authority`         | Mint, freeze and Token-2022 authority changes and revocations; mints of at least 1% of supply; transfer hook, fee, pause, default account state, UI multiplier and interest rate changes.                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `privileged-instruction` | Every call to an instruction in `privilegedInstructions`, classified by what it changes: **admin control** (`set_admin`, `transfer_authority`: high), **new markets or assets** (`initialize_spot_market`, `init_reserve`: high), **oracles** (high) and **risk settings** such as limits and weights (medium). A newly listed token is vetted: one created less than 30 days before the listing, or whose top 10 holders own 90% of supply, makes the alert critical. A signer not seen before is high, and a failed attempt by an unknown signer is high, since it often means someone is probing access control. |
| `treasury-outflow`       | Net SOL and token outflows from `treasuries` and from discovered program vaults. One outflow at its threshold is high; 3× the threshold within the window is critical. Three or more assets leaving within the window is a critical **sweep**. With `allowedDestinations` set, any outflow elsewhere is high.                                                                                                                                                                                                                                                                                                       |
| `key-authority`          | Control handed off in a transaction signed by a treasury or watched key: stake staker or withdrawer authority (withdrawer is critical), stake lockup, token account owner (critical) or close authority, token delegate approvals, and System `assign` of the account to a program (critical). Lists the other instructions in the same transaction, since the SwissBorg/Kiln exploit reportedly hid authority changes inside an unstake.                                                                                                                                                                           |
| `nonce-authority`        | A durable nonce account created for, or reassigned to, a privileged key: an upgrade authority, admin key, multisig member, config authority, mint or freeze authority, known admin signer, or anything in `watchedKeys`. Anyone can do this for any key, and a transaction that key signs against the nonce never expires.                                                                                                                                                                                                                                                                                          |
| `idl-change`             | A newly published IDL for a watched program, listing instructions added and removed. High when a new instruction looks admin-only. `watch` checks every `idlPollMinutes`.                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `config-change`          | A changed field in a program's config accounts, such as Drift's `State` or Kamino's `GlobalConfig`, read through the IDL layout and compared every `configPollSeconds` (default 60) and right after any admin call. An admin key change is **critical** however it happened: a renamed instruction, a CPI, or one the classifier misses. Changed public keys, status and pause flags are high; limits, fees and collateral settings are medium. Counters and timestamps are ignored.                                                                                                                                |
| `build-verification`     | An upgrade whose bytecode still does not match a verified build 30 minutes later: critical when the program has registered source for verification, high when it has none. Every upgrade alert also says whether its bytecode is a verified build.                                                                                                                                                                                                                                                                                                                                                                  |
| `attack-chain`           | One critical alert when a protocol shows two stages of a takeover within 24 hours: **control** (admin, authority or multisig changes, nonce-signed approvals, new admin signers), **risk** (listings, oracle or limit changes) and **drain** (large, sustained or swept outflows). Control plus risk alerts before any funds move, which is the window between a new admin's first calls and a drain: in the Drift exploit, the new admin listed a three-week-old token and raised withdrawal limits in its first transaction. It alerts again when a further stage appears.                                        |

| Escalation    | Rule                                                                                                                                             |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| Durable nonce | Any medium-or-higher finding goes up one level when its transaction used a durable nonce, since it could have been signed long before it landed. |

### Found automatically

- **Admin keys:** read from the program's config accounts through its IDL layout, such as Drift's `State.admin` or Kamino's `LendingMarket.lendingMarketOwner`, and from the signers of its recent admin calls in an admin role, so a permissionless crank does not count. A Squads multisig behind an admin key is watched like the upgrade multisig, and the posture grade covers it. Each admin key's history is scanned for admin calls, which is far cheaper than scanning a busy program.
- **Config accounts:** the accounts that store an admin key, found in order of cost:
  - **Fixed address:** read directly when the IDL derives the account from constant seeds, such as Pump AMM's `GlobalConfig`.
  - **Listed:** listed from the program when there are only a handful, such as Drift's `State` or Kamino's `GlobalConfig`.
  - **Sampled:** otherwise taken from a sample of the program's recent transactions, keeping only the one or two accounts most of them use. That covers types with many instances, such as Kamino's 242 permissionless lending markets or Orca's Whirlpool configs, and programs too large to list. The sample counts accounts passed directly, and accounts named in another account's field, such as each pool's `whirlpools_config`.

  Types the IDL derives per mint or per user are skipped. An account is kept only when its admin field holds a real admin, so integration configs that store another program's authority are skipped. When a config type cannot be found, or a program with admin instructions has no admin key, the dashboard log says so.

- **Following control changes:** when an authority, admin key or multisig membership changes while monitoring, Watchtower discovers again within 10 seconds, starts watching the new admin or multisig, re-grades posture, and resubscribes the stream if its filters changed. No restart needed.
- **Verified builds:** each program's deployed bytecode is hashed the way `solana-verify` does and checked against the OtterSec verification service (`verify.osec.io`, overridable with `WATCHTOWER_VERIFY_URL`).
- **Token-2022 controls:** risky mint extensions are read from the mint account: a permanent delegate, transfer hook program or non-transferable flag (critical), pausable or frozen-by-default accounts (high), and transfer fees, close authority, interest or UI multipliers (medium). They count in a watched mint's posture and make a listing of such a token critical.
- **New admin wallets:** an admin call signed by a wallet that first appeared on-chain less than 7 days earlier is critical. The admin wallet used in the Drift exploit was funded 25 hours before its first admin call.
- **Vaults:** the program-derived addresses that pay out tokens in the program's recent transactions, kept when they hold at least $100,000, priced with the Helius DAS API. Each holding worth $10,000 or more gets a threshold of 20% of its balance, so 60% leaving within an hour is critical. Turn it on per program with `watchVaults: true` (or the Setup checkbox). It suits programs that hold user funds, such as lending and perps; an aggregator like Jupiter routes funds through its PDAs on every swap, which floods the stream and looks like outflows. A vault starts monitoring from the present rather than scanning its history, since that history is mostly user deposits and withdrawals.

### How the posture grade works

Each program, multisig and mint is graded on its own and starts at 100 points. Every check passes, warns, fails or is just a note:

| Result       | Points |
| ------------ | ------ |
| Fail         | −25    |
| Warning      | −10    |
| Pass or note | 0      |

The overall score is the lowest subject score, because one weak link is enough for an attacker. Grades: **A** 90+, **B** 75–89, **C** 60–74, **D** 40–59, **F** below 40. The dashboard and the HTML report show each check's cost and how to fix it.

| Check                                                                                                     | Result       | How to improve                                                             |
| --------------------------------------------------------------------------------------------------------- | ------------ | -------------------------------------------------------------------------- |
| Upgrade authority is a single wallet                                                                      | Fail         | Move it to a Squads vault with a time lock, or make the program immutable  |
| Multisig needs only 1 signature                                                                           | Fail         | Raise the threshold to at least half of the voting members                 |
| Threshold below half of the voting members                                                                | Warning      | Same                                                                       |
| No time lock                                                                                              | Warning      | Set one (24 hours is common); Squads v3 needs a migration to v4            |
| Controlled multisig: a config authority can change members without a vote                                 | Warning      | Remove the config authority                                                |
| Upgrade authority is an unrecognized PDA (governance or custom)                                           | Warning      | Confirm who controls it                                                    |
| Admin key is a single wallet                                                                              | Fail         | Move admin control to a Squads multisig with a time lock                   |
| Admin multisig: threshold, time lock and config authority, graded like the upgrade multisig               | As above     | As above                                                                   |
| Admin instructions in the IDL that are not monitored                                                      | Warning      | Pick them in Setup → Programs, or list them under `privilegedInstructions` |
| Active mint or freeze authority                                                                           | Warning each | Revoke it, or move it to a multisig                                        |
| Token-2022 permanent delegate, transfer hook or non-transferable                                          | Fail each    | Remove the extension, or put its authority behind a time-locked multisig   |
| Other Token-2022 controls: pausable, frozen by default, transfer fee, close authority, interest, UI scale | Warning each | Same                                                                       |
| No verified build, or deployed bytecode that is not the registered build                                  | Warning      | Publish a verified build with `solana-verify`                              |
| A privileged key controls durable nonce accounts (found through the key's history and confirmed on-chain) | Warning      | Close accounts that are no longer needed                                   |
| Last deployment, missing IDL                                                                              | Note         | —                                                                          |

## How alerts stay complete

- **Cursors:** each watched address has one, stored in `.watchtower/state.json`. A cursor only moves past slots that have been scanned.
- **Live stream:** cursors advance to the latest notification's slot once every notification before it is processed. They stop the moment the connection drops, and while any subscription is rejected, so the next gap-fill covers the gap.
- **First scan:** each scan plan's first scan records history without alerting. After that, every new finding it scans alerts, including when another plan for the same program is new.
- **`report`:** findings from `report` are queued, and `watch` delivers them.
- **Failed deliveries:** they stay queued and are retried on the next start. Discord and Slack rate limits are retried automatically.
- **Duplicates:** findings are keyed by detector, signature and instruction position, so a transaction that arrives from both backfill and the stream alerts once.
- **Live-only signals:** nonce setup for a privileged key has no history to backfill, because the key is only an instruction argument, not an account. `watch` subscribes to nonce instructions chain-wide and filters them locally, and `report` lists existing nonce accounts instead.

## Configuration

See [`watchtower.example.yaml`](watchtower.example.yaml). Any string can reference `${ENV_VAR}`, and `.env` is loaded automatically. Configs saved from the dashboard may only keep the references already in alert channel secrets, so the browser cannot read other variables.

| Variable                    | Default                                             |
| --------------------------- | --------------------------------------------------- |
| `HELIUS_API_KEY`            | required                                            |
| `HELIUS_RPC_URL`            | the Helius SDK's (`https://mainnet.helius-rpc.com`) |
| `HELIUS_PARSED_STREAMS_URL` | the Helius SDK's (`wss://beta.helius-rpc.com`)      |

Parsed Events uses the SDK's endpoint, `https://mainnet.helius-rpc.com/v1/parsed-events`. Requests carry an `X-Helius-Client: helius-watchtower/<version>` header.

### Credits

A Parsed Events scan costs 10 credits plus 1 for each 1,000 transactions scanned. Matched transactions returned in full also cost credits: in testing, a busy exchange wallet with 14,156 matches cost about 1,560 credits.

- **Which addresses are scanned:** the program's ProgramData, each multisig, each mint, each treasury, and the program itself when admin instructions are configured. `report` also scans each privileged key's history for nonce accounts.
- **How long the histories are:** ProgramData and multisig histories are short and cost about 11 credits a run. Busy programs, mints and treasuries are long.
- **Capping a run:** `backfill.maxScannedTransactions` caps each scan, and the report lists the credits each one used.
- **First scans:** a first scan reads newest-first, so it covers the most recent history within the cap and then starts monitoring from the present.
- **Very busy programs:** admin-instruction gap-fills on programs like Jupiter scan the program's whole transaction stream. A long downtime can exceed the cap, and the scan continues on the next run. The live stream is unaffected.

## Writing a detector

A detector is a pure function from a decoded transaction to findings:

```ts
import { account, nameOf } from '../model.js';
import { findingFor, type Detector } from './types.js';

export const oracleChange: Detector = {
  id: 'oracle-change',
  description: 'Oracle account swapped on a watched market',
  detect(tx, ctx) {
    return tx.instructions
      .filter((ix) => ctx.targets.programs.has(ix.programId) && nameOf(ix) === 'updateoracle')
      .map((ix) =>
        findingFor('oracle-change', tx, ix, {
          severity: 'high',
          title: 'Oracle changed',
          description: `Oracle set to ${account(ix, 'new_oracle')?.pubkey}`,
          subject: ix.programId,
          subjectLabel: ctx.targets.programs.get(ix.programId)!.label,
          details: {},
        }),
      );
  },
};
```

1. Register it in [`src/detectors/index.ts`](src/detectors/index.ts).
2. Add tests in [`test/detectors.test.ts`](test/detectors.test.ts) using the helpers in [`test/helpers.ts`](test/helpers.ts).

[`AGENTS.md`](AGENTS.md) covers the code layout, the conventions and the API limits, and [`CONTRIBUTING.md`](CONTRIBUTING.md) the pull request checklist.

## Limitations

- **Mainnet only.**
- **Upgrade authorities:** Squads v3 and v4 are recognized. SPL Governance, Realms and other PDAs are reported as unrecognized.
- **Admin instructions:** a program's own instructions are decoded only when Parsed Events has its IDL (Anchor or Program Metadata).
- **Live alert times:** Parsed Streams does not carry `blockTime`, so live alerts show the slot.
- **Proposals:** Squads v4 proposals staged through a transaction buffer (`vaultTransactionCreateFromBuffer`) are not decoded yet. Approvals are linked to a v4 proposal only when `proposalCreate` ran in the same transaction as `vaultTransactionCreate`, as the Squads app does.
- **Treasury thresholds:** these are raw token amounts, not USD values.
- **Config accounts:** fields are read only up to the first one whose offset differs between Borsh and zero-copy layouts, and replay cannot diff them, since past account states are not stored.

## Disclaimer

Watchtower is a monitoring aid, not an audit or a guarantee. It can miss events: a detector may not recognize a new attack pattern, a program without a published IDL cannot be fully decoded, and Parsed Events and Parsed Streams are in beta. Alerts point you at activity to review; they do not prove an attack or rule one out. Keep your own incident response in place.

## Contributing

Found a bug or a gap in a detector? Open an issue or a pull request; [`CONTRIBUTING.md`](CONTRIBUTING.md) has the setup and checklist.

## License

MIT
