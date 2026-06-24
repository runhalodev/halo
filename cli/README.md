# @runhalodev/cli

`halo` — operator + payer CLI for [Halo](https://www.npmjs.com/org/runhalodev). Run and pay for x402-gated services from the terminal.

## Usage

No install required:

```bash
npx @runhalodev/cli --help
```

Or install globally to get the `halo` command:

```bash
npm install -g @runhalodev/cli
halo --help
```

Requires Node.js >= 20.

## Commands

| Command | Purpose |
| --- | --- |
| `halo setup`   | Initialize config / wallet |
| `halo doctor`  | Check environment and configuration |
| `halo serve`   | Run an x402-gated service (operator side) |
| `halo service` | Manage services |
| `halo pay`     | Pay an x402-gated endpoint |
| `halo consume` | Consume / call a paid resource |
| `halo vault`   | Manage the vault |
| `halo link`    | Link accounts / services |
| `halo status`  | Show status |

Run `halo <command> --help` for details on any command.

## License

Apache-2.0
