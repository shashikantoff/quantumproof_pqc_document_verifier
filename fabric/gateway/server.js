import { readFileSync } from 'node:fs';
import crypto from 'node:crypto';
import express from 'express';
import grpc from '@grpc/grpc-js';
import { connect, hash, signers } from '@hyperledger/fabric-gateway';

const required = [
  'GATEWAY_TOKEN', 'FABRIC_MSP_ID', 'FABRIC_CHANNEL', 'FABRIC_CHAINCODE', 'PEER_ENDPOINT',
  'PEER_HOST_ALIAS', 'PEER_TLS_CERT_PATH', 'CLIENT_CERT_PATH', 'CLIENT_KEY_PATH',
];
for (const name of required) {
  if (!process.env[name]) throw new Error(`${name} is required`);
}

function newGrpcConnection() {
  const tlsRootCert = readFileSync(process.env.PEER_TLS_CERT_PATH);
  return new grpc.Client(
    process.env.PEER_ENDPOINT,
    grpc.credentials.createSsl(tlsRootCert),
    { 'grpc.ssl_target_name_override': process.env.PEER_HOST_ALIAS },
  );
}

const client = newGrpcConnection();
const identity = {
  mspId: process.env.FABRIC_MSP_ID,
  credentials: readFileSync(process.env.CLIENT_CERT_PATH),
};
const privateKey = crypto.createPrivateKey(readFileSync(process.env.CLIENT_KEY_PATH));
const gateway = connect({ client, identity, signer: signers.newPrivateKeySigner(privateKey), hash: hash.sha256 });
const contract = gateway.getNetwork(process.env.FABRIC_CHANNEL).getContract(process.env.FABRIC_CHAINCODE);

function constantTimeTokenMatch(value) {
  const expected = Buffer.from(`Bearer ${process.env.GATEWAY_TOKEN}`);
  const received = Buffer.from(value || '');
  return expected.length === received.length && crypto.timingSafeEqual(expected, received);
}

async function submit(name, args) {
  const proposal = contract.newProposal(name, { arguments: args });
  const transaction = await proposal.endorse();
  const commit = await transaction.submit();
  const status = await commit.getStatus();
  if (!status.successful) throw new Error(`Fabric commit failed with status ${status.code}`);
  return { transactionId: proposal.getTransactionId(), blockNumber: Number(status.blockNumber) || null };
}

const app = express();
app.use(express.json({ limit: '64kb' }));
app.use((req, res, next) => constantTimeTokenMatch(req.get('authorization')) ? next() : res.status(401).json({ detail: 'unauthorized' }));

app.post('/records', async (req, res, next) => {
  try {
    const payload = req.body;
    if (!payload.documentId) return res.status(422).json({ detail: 'documentId is required' });
    res.status(201).json(await submit('CreateDocument', [payload.documentId, JSON.stringify(payload)]));
  } catch (error) { next(error); }
});

app.post('/records/:id/revoke', async (req, res, next) => {
  try {
    const reason = String(req.body?.reason || '').trim();
    if (!reason) return res.status(422).json({ detail: 'reason is required' });
    if (reason.length > 500) return res.status(422).json({ detail: 'reason is too long' });
    res.status(201).json(await submit('RevokeDocument', [req.params.id, reason]));
  } catch (error) { next(error); }
});

app.get('/records/:id', async (req, res, next) => {
  try {
    const bytes = await contract.evaluateTransaction('ReadDocument', req.params.id);
    res.json(JSON.parse(Buffer.from(bytes).toString('utf8')));
  } catch (error) {
    if (String(error).includes('does not exist')) return res.status(404).json({ detail: 'not found' });
    next(error);
  }
});

app.get('/records/:id/history', async (req, res, next) => {
  try {
    const bytes = await contract.evaluateTransaction('GetDocumentHistory', req.params.id);
    res.json(JSON.parse(Buffer.from(bytes).toString('utf8')));
  } catch (error) { next(error); }
});

app.use((error, _req, res, _next) => {
  console.error(error);
  res.status(502).json({ detail: 'Fabric gateway operation failed' });
});

const server = app.listen(process.env.PORT || 3000, () => console.log('Fabric gateway bridge listening'));
function close() { server.close(); gateway.close(); client.close(); }
process.on('SIGINT', close); process.on('SIGTERM', close);
