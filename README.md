# VultrPilot — Qwen Browser Agent

VultrPilot is a FastAPI web app for the Vultr Agent Rush Challenge 1. It uses
Qwen through Vultr Serverless Inference to plan tasks, verifies annotated
screenshots with a multimodal Qwen model, and performs public-page browsing in
an isolated Playwright container. Generated Python projects can run in a
separate disposable executor with no network access.

## Architecture

```text
Browser chat → FastAPI API on a Vultr VM → Qwen text model (planning)
                                      ↘ Qwen vision model (screenshot verification)
                                      ↘ isolated Playwright runner (HTTPS only)
                                      ↘ disposable Python executor (network disabled)
```

The browser action flow defaults to confirmation before each action. The UI
also exposes quick-approve and autopilot modes; use those only in a controlled
environment. Credentials, login flows, payment actions, and irreversible
actions are not supported by the agent policy.

## Local setup

1. Copy `.env.example` to `.env` and set
   `VULTR_SERVERLESS_INFERENCE_API_KEY`.
2. Start all services:

   ```powershell
   docker compose up --build
   ```

3. Open `http://localhost:8000/` and submit a public HTTPS browsing request,
   for example: `Find the title of the Python homepage and return the page
   title and URL.`

The compose stack starts three services:

- `api`: FastAPI chat UI, Qwen integration, approval flow, uploads, and ZIP
  artifact creation.
- `runner`: isolated headless Chromium browser for public HTTPS pages.
- `executor`: disposable Python worker with `network_mode: none` and resource
  limits.

Uploaded files and generated ZIP artifacts are stored under `/tmp` in the API
container and are cleaned up after one hour when cleanup runs. Executor jobs
are stored in the named `executor_jobs` volume for diagnostics; remove that
volume when its contents are no longer needed. Do not use these locations for
durable application data.

## Configuration

`.env.example` contains the publishable configuration template. Set the real
API key only in a local or VM `.env` file; `.env` is intentionally ignored.

- `VULTR_SERVERLESS_INFERENCE_API_KEY`: Vultr Serverless Inference key.
- `QWEN_MODEL`: planning model; defaults to `Qwen/Qwen3-8B`.
- `QWEN_VISION_MODEL`: screenshot verification model; defaults to
  `qwen3.8-27b`.
- `QWEN_BASE_URL`: Qwen-compatible endpoint; defaults to
  `https://api.vultrinference.com/v1`.
- `RUNNER_URL`: internal runner URL; defaults to `http://runner:8001`.
- `FRONTEND_ORIGIN`: comma-separated allowed browser origins.

## Vultr deployment

- Deploy the `api`, `runner`, and `executor` services on a Vultr Cloud Compute
  VM, or adapt the compose file to place the runner and executor on separate
  disposable instances.
- Keep all API keys on the VM and place the public service behind TLS and an
  appropriate access control layer before using it beyond a demo.
- The public demo used during development was `http://45.76.144.49:8000/`.

## Repository layout

```text
api/                 FastAPI service and built-in web frontend
executor/            No-network disposable Python worker
runner/              Isolated Playwright browser service
docker-compose.yml   Local/deployment service definition
.env.example         Safe configuration template
.gitignore           Secret, cache, runtime, and sensitive-capture rules
```

## Safety notes

The runner accepts only valid HTTPS URLs and runs Chromium with a restricted
container configuration. Browser clicks require a user approval event unless
the selected UI mode explicitly permits them. The executor has no network
interface and applies CPU, memory, file-size, process-count, and wall-clock
limits, but it should still be deployed as an untrusted-code boundary rather
than treated as a complete security guarantee.
