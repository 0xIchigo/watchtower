# Contributing

Thanks for helping make Solana programs safer to depend on.

## Setup

You need Node.js 22 or later, pnpm, and a [Helius API key](https://dashboard.helius.dev) for anything that talks to mainnet.

```sh
pnpm install
cp .env.example .env   # then set HELIUS_API_KEY
pnpm check             # format, lint, typecheck, tests, build
```

The tests run offline and never spend API credits.

## Before you open a pull request

- Run `pnpm check`. CI runs the same steps.
- `pnpm format` fixes formatting; `pnpm lint` runs oxlint.
- Read [`AGENTS.md`](AGENTS.md). It covers the layout, the conventions (naming, comments, how detectors read decoded instructions) and the invariants that keep alerts complete, such as when a cursor may move.
- Add tests for new behavior. Detectors are tested with the helpers in [`test/helpers.ts`](test/helpers.ts), which build transactions in the Parsed Streams wire shape. When you change an account decoder, add a fixture from a real mainnet account.
- Keep changes focused. A new detector, a bug fix and a refactor are easier to review as separate pull requests.

## Adding a detector

[`README.md`](README.md#writing-a-detector) walks through it. If a detector targets a real exploit, a `watchtower replay` of the exploit window is the most convincing test.

## Reporting bugs

Open an issue with what you ran, what you expected and what happened, plus the relevant log lines with your API key removed.
