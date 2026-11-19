# Hyperledger Fabric deployment guide

This guide connects the application to an existing Fabric 2.4+ network. It intentionally does not place a complete Fabric network inside the development Compose file: consortium identities, endorsement policy, CAs, and channel membership are deployment-specific security decisions.

Record the actual Fabric peer and Fabric CA versions for each deployment. The version defaults in the bundled samples installer are documented in [`reproducibility.md`](reproducibility.md) and are not a substitute for checking the running network.

## 1. Establish the network

Create a channel for the participating issuers/verifiers and define an endorsement policy that reflects the trust model. For a two-organization academic consortium, an `AND('UniversityMSP.peer','AccreditorMSP.peer')` policy is a sensible starting point; for a single institutional registrar, require that organization’s peer endorsement and document the governance limitation.

Every participating peer must have the document chaincode installed, then the approved definition must be committed to the chosen channel. Fabric’s chaincode lifecycle is the correct point for organizations to agree on that operating policy.

Example with the Fabric samples test network (adapt the organization names and paths):

```bash
cd fabric-samples/test-network
./network.sh up createChannel -ca -c verifynet

peer lifecycle chaincode package document.tar.gz \
  --path /absolute/path/to/quantum-document-verifier/fabric/chaincode/document \
  --lang golang --label document_1

# Install on each endorsing organization, obtain package ID, approve, then commit
# using the Fabric lifecycle commands and your channel endorsement policy.
```

Use Fabric’s documented lifecycle process for the install, approve, and commit commands. Do not copy a test-network identity into production.

## 2. Enroll a least-privilege gateway identity

Enroll an application identity with access limited to the channel and this chaincode. Provide these files read-only to the bridge container:

```text
fabric/gateway/crypto/
├── peer-tls-ca.pem
├── client-cert.pem
└── client-key.pem
```

Copy [`fabric/gateway/.env.example`](../fabric/gateway/.env.example) to `fabric/gateway/.env` and fill in the MSP, channel, chaincode name, TLS peer endpoint, hostname override, and a long random `GATEWAY_TOKEN`. The bridge uses mTLS to the Fabric Gateway and a separate bearer token solely to protect the internal FastAPI-to-bridge hop.

## 3. Start the bridge on the Fabric network

The bridge must join the Docker network that can reach the peer Gateway service:

```bash
docker network create fabric_test  # only if the Fabric deployment has not created it
docker compose -f fabric/docker-compose.fabric-gateway.yml up --build -d
```

The provided bridge follows Fabric Gateway’s explicit proposal → endorse → submit → commit-status flow. A successful HTTP `201` therefore means that the service observed a successful commit status, not merely that it sent a proposal.

## 4. Switch the application to Fabric

Update the application `.env` and restart the API/web services with the Fabric network overlay:

```dotenv
LEDGER_BACKEND=fabric
FABRIC_GATEWAY_URL=http://fabric-gateway:3000
FABRIC_GATEWAY_TOKEN=<same value as fabric/gateway/.env>
```

```bash
docker compose -f docker-compose.yml -f docker-compose.fabric.yml up --build -d
```

The base Compose file intentionally does not require the external `fabric_test` network, so the development-ledger setup works without starting Fabric.

Check `GET /health`; it must report `"ledger_backend": "hyperledger-fabric"`. The UI’s development-ledger label is intentionally visible as a guardrail.

## Operational checklist

- Use TLS for public API access and keep the bridge on a private network.
- Require issuer authentication/authorization in front of `POST /register`.
- Enable Fabric state-database history only where operationally required; the contract’s `GetDocumentHistory` relies on the peer’s history database.
- Monitor rejected/invalid transactions, gateway certificate expiry, peer reachability, and chaincode events.
- Back up enrollment material and rotate application identities. Do not place enrollment private keys in source control or image layers.
- Test the endorsement policy with more than one organization before describing the ledger as decentralized.
