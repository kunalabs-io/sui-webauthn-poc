# Sui WebAuthn POC

### Warning: This is a proof of concept, not production ready code! It may be unsafe!

---

This is POC accompanying the WebAuthn SIP. It's a simple web app that demonstrates the use of WebAuthn to sign, encode and verify Sui transactions. Also demonstrates public key recovery both from signature and using the `largeBlob` extension

Steps to run:
- `pnpm install`
- `pnpm run`
- visit `http://localhost:5173`


Tip: You can use the WebAuthn tab in Chrome DevTools for testing.