# Readiness checker

The rules behind the free checks at [horodylova-ltd.co.uk/tools](https://horodylova-ltd.co.uk/tools). Published so that anyone can read exactly what a check does with their input before running it.

Every finding comes from a deterministic rule in this folder. Nothing here calls a language model.

## What is in here

| Folder | Check | Input | What it does |
| --- | --- | --- | --- |
| `url/` | App Exposure Check | The public address of an app | Loads the page and the scripts served from the same site, looks for secret keys, connection strings, exposed `.env` and `.git`, public source maps. Detects the stack (Supabase, Firebase, Stripe, the builder). Never follows a redirect to a private network, never reads a row of data. |
| `stripe/` | Stripe Integration Check | Output of two Stripe CLI commands the user runs in their own terminal, and optionally the handler code | Step 1 reads the webhook endpoint list (no secrets in that output) and checks status, address, subscribed events and API version. Step 2 reads the response of a `curl` the user sends to their own endpoint with an invalid signature and an unknown event type. Step 3 reads pasted handler and Checkout code for signature verification, idempotency, handled events and prices set by the client. A paste containing a live key is refused and not analysed. |
| `types.ts` | | | The finding and report shapes shared by all checks. |

## Running the tests

    npm install
    npm test

Fixtures live next to each check. Keys in fixtures are made up.

## Principles

- Facts come from code, not from a model. A rule either fires or it does not, and the test suite shows when.
- Input is analysed in memory. The site keeps no copy of what is pasted.
- Nothing is sent to a third party on the user's behalf. Where a request has to reach the user's own server, the user runs the command.
- Each rule names the object, the consequence in plain words and the remedy. Remedies are written as instructions, not as scripts to run blindly.

## Reporting a wrong finding

Open an issue with the rule code (for example `CODE-06`) and a minimal input that reproduces it. Real keys, addresses and customer data must not be included.

## License

MIT. See `LICENSE`.
