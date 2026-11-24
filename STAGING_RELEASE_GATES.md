# Live staging release gates

The `verisigil-staging-runtime-gates` workflow is bound to the isolated Railway Passport staging branch. It runs the complete Python unit suite and read-only live HTTP checks against the staging service.

Live checks require: `/health` HTTP 200, `/openapi.json` HTTP 200, all critical Passport and runtime-authority routes present, Supabase bearer security documented, and unauthenticated tenant/agent reads denied with HTTP 401.

This workflow deliberately does not create users, issue API keys, register agents, consume authority, or touch customer actuators. Those stateful end-to-end checks require a dedicated synthetic Supabase Auth test identity and an isolated actuator test fixture; they must never be simulated against production customer data.