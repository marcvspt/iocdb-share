# IoCDB Share

## Setup

You need to configure an `.env` file with your own values. This an example with the environment variables needed for the APIs:

```env
# VirusTotal
VIRUSTOTAL_API_KEY=abcde12345

# PolySwarm
POLYSWARM_API_KEY=abcde12345

# AlienVault OTX
OTX_API_KEY=abcde12345

# AbuseIPDB
ABUSEIPDB_API_KEY=abcde12345
```

## Commands

All commands are run from the root of the project, from a terminal:

| Command                 | Action                                           |
| :---------------------- | :----------------------------------------------- |
| `pnpm install`          | Installs dependencies                            |
| `pnpm run dev`          | Starts local dev server at `localhost:4321`      |
| `pnpm run build`        | Build your production site (this is a server app)|
| `pnpm run astro ...`    | Run CLI commands like `astro add`, `astro check` |
| `pnpm run astro --help` | Get help using the Astro CLI                     |
