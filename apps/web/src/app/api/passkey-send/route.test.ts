// @vitest-environment node
/**
 * Tests for the /api/passkey-send route handler (issue #172).
 *
 * Three suites:
 *   - "input validation": malformed XDR, invalid auth, wrong envelope types return 400
 *   - "relayer error mapping": PluginTransportError → 502/504, PluginExecutionError → 422
 *   - "happy paths": successful contract call + deploy with mocked ChannelsClient
 */
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest';
import { Keypair, xdr, Transaction, hash as sha256 } from '@stellar/stellar-sdk';
import { ChannelsClient } from '@openzeppelin/relayer-plugin-channels';

const PASSPHRASE = 'Test SDF Network ; September 2015';

type Post = (req: Request) => Promise<Response>;
let POST: Post;
let submitSorobanTxMock: Mock;
let submitTxMock: Mock;

/** Build a minimal Soroban v1 tx envelope (for deploy tests) */
function buildDeployEnvelope(fee: number): string {
  const source = Keypair.fromRawEd25519Seed(sha256(Buffer.from('kalepail')));
  const account = new xdr.MuxedAccount.keyTypeEd25519(source.rawPublicKey());
  const op = xdr.Operation.invokeHostFunction(
    new xdr.InvokeHostFunctionOp({
      hostFunction: xdr.HostFunction.hostFunctionTypeCreateContract(
        new xdr.CreateContractArgs({
          contractIdPreimage: xdr.ContractIdPreimage.contractIdPreimageFromAddress(
            new xdr.ContractIdPreimageFromAddress({
              address: xdr.ScAddress.scAddressTypeContract(Buffer.alloc(32)),
              salt: xdr.Uint256(Buffer.alloc(32)),
            }),
          ),
          executable: xdr.ContractExecutable.contractExecutableWasm(xdr.Hash(Buffer.alloc(32))),
        }),
      ),
      auth: [],
    }),
  );
  const tx = new xdr.Transaction({
    sourceAccount: account,
    fee: xdr.Uint32(fee),
    seqNum: xdr.SequenceNumber.fromString('1'),
    cond: xdr.Preconditions.precondNone(),
    memo: xdr.Memo.memoNone(),
    operations: [op],
    ext: new xdr.TransactionExt(1, new xdr.SorobanTransactionData({
      ext: new xdr.ExtensionPoint(0),
      resources: new xdr.SorobanResources({
        footprint: new xdr.LedgerFootprint({ readOnly: [], readWrite: [] }),
        instructions: xdr.Uint32(0),
        readBytes: xdr.Uint32(0),
        writeBytes: xdr.Uint32(0),
      }),
      resourceFee: xdr.Int64.fromString(String(fee - 100)),
    })),
  });
  const envelope = new xdr.TransactionEnvelope.envelopeTypeTx(new xdr.TransactionV1Envelope({ tx, signatures: [] }));
  const txObj = new Transaction(envelope.toXDR('base64'), PASSPHRASE);
  txObj.sign(source);
  return txObj.toXDR();
}

/** Valid base64-encoded SorobanAuthorizedFunction (invoke contract) */
function validFunc(): string {
  const addr = xdr.ScAddress.scAddressTypeContract(Buffer.alloc(32, 1));
  const func = xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
    new xdr.InvokeContractArgs({
      contractAddress: addr,
      functionName: xdr.ScSymbol.fromString('test'),
      args: [],
    }),
  );
  return func.toXDR('base64');
}

/** Valid base64-encoded SorobanAuthorizationEntry */
function validAuth(): string {
  const entry = new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsSourceAccount(),
    rootInvocation: new xdr.SorobanAuthorizedInvocation({
      function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
        new xdr.InvokeContractArgs({
          contractAddress: xdr.ScAddress.scAddressTypeContract(Buffer.alloc(32, 1)),
          functionName: xdr.ScSymbol.fromString('test'),
          args: [],
        }),
      ),
      subInvocations: [],
    }),
  });
  return entry.toXDR('base64');
}

/** Typed relayer errors (matching @openzeppelin/relayer-plugin-channels) */
class PluginTransportError extends Error {
  errorDetails: { statusCode: number; message?: string };
  constructor(statusCode: number, message = 'transport error') {
    super(message);
    this.name = 'PluginTransportError';
    this.errorDetails = { statusCode, message };
  }
}

class PluginExecutionError extends Error {
  errorDetails: { message?: string };
  constructor(message = 'execution error') {
    super(message);
    this.name = 'PluginExecutionError';
    this.errorDetails = { message };
  }
}

class PluginUnexpectedError extends Error {
  errorDetails: Record<string, unknown>;
  constructor(message = 'unexpected error') {
    super(message);
    this.name = 'PluginUnexpectedError';
    this.errorDetails = {};
  }
}

function passkeySend(body: Record<string, unknown>): Promise<Response> {
  return POST(
    new Request('http://localhost/api/passkey-send', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }),
  );
}

beforeEach(async () => {
  vi.resetModules();
  vi.stubEnv('PASSKEY_RELAYER_URL', 'https://relayer.example.com');
  vi.stubEnv('PASSKEY_RELAYER_API_KEY', 'test-api-key');
  vi.stubEnv('NEXT_PUBLIC_NETWORK_PASSPHRASE', PASSPHRASE);

  // Mock ChannelsClient methods
  submitSorobanTxMock = vi.fn(async () => ({ hash: 'mockhash123' }));
  submitTxMock = vi.fn(async () => ({ hash: 'mockhash456' }));

  vi.spyOn(ChannelsClient.prototype, 'submitSorobanTransaction').mockImplementation(submitSorobanTxMock);
  vi.spyOn(ChannelsClient.prototype, 'submitTransaction').mockImplementation(submitTxMock);

  // Mock console methods to suppress logs during tests
  vi.spyOn(console, 'log').mockImplementation(() => {});
  vi.spyOn(console, 'error').mockImplementation(() => {});

  ({ POST } = (await import('./route')) as { POST: Post });
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

// ══════════════════════════════════════════════════════════════════════════
// Suite — input validation (issue #172: client errors → 400)
// ══════════════════════════════════════════════════════════════════════════

describe('POST /api/passkey-send — input validation', () => {
  it('400 when body is not valid JSON', async () => {
    const res = await POST(
      new Request('http://localhost/api/passkey-send', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: '{not valid json',
      }),
    );
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toMatch(/json/i);
    expect(submitSorobanTxMock).not.toHaveBeenCalled();
    expect(submitTxMock).not.toHaveBeenCalled();
  });

  it('400 when body is neither { func, auth } nor { xdr }', async () => {
    const res = await passkeySend({ something: 'else' });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toMatch(/must be/i);
    expect(submitSorobanTxMock).not.toHaveBeenCalled();
    expect(submitTxMock).not.toHaveBeenCalled();
  });

  it('400 when func is provided but auth is not an array', async () => {
    const res = await passkeySend({ func: validFunc(), auth: 'notanarray' });
    expect(res.status).toBe(400);
    expect(submitSorobanTxMock).not.toHaveBeenCalled();
  });

  it('400 when auth array contains non-string elements', async () => {
    const res = await passkeySend({ func: validFunc(), auth: [validAuth(), 123, validAuth()] });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toMatch(/auth must be an array/i);
    expect(submitSorobanTxMock).not.toHaveBeenCalled();
  });

  it('400 when func is malformed base64', async () => {
    const res = await passkeySend({ func: 'not-valid-base64!!!', auth: [] });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toMatch(/func must be valid/i);
    expect(submitSorobanTxMock).not.toHaveBeenCalled();
  });

  it('400 when func is valid base64 but not valid SorobanAuthorizedFunction XDR', async () => {
    const res = await passkeySend({ func: Buffer.from('random bytes').toString('base64'), auth: [] });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toMatch(/func must be valid/i);
    expect(submitSorobanTxMock).not.toHaveBeenCalled();
  });

  it('400 when auth entry is malformed XDR', async () => {
    const res = await passkeySend({ func: validFunc(), auth: ['not-valid-xdr!!!'] });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toMatch(/auth\[0\] must be valid/i);
    expect(submitSorobanTxMock).not.toHaveBeenCalled();
  });

  it('400 when xdr is malformed base64', async () => {
    const res = await passkeySend({ xdr: 'not-valid-base64!!!' });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toMatch(/xdr must be valid/i);
    expect(submitTxMock).not.toHaveBeenCalled();
  });

  it('400 when xdr is valid base64 but not a TransactionEnvelope', async () => {
    const res = await passkeySend({ xdr: Buffer.from('random bytes').toString('base64') });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toMatch(/xdr must be valid/i);
    expect(submitTxMock).not.toHaveBeenCalled();
  });

  it('400 when xdr is not a v1 envelope', async () => {
    // Build a v0 envelope (no ext, no Soroban data)
    const source = Keypair.random();
    const account = new xdr.MuxedAccount.keyTypeEd25519(source.rawPublicKey());
    const tx = new xdr.Transaction({
      sourceAccount: account,
      fee: xdr.Uint32(100),
      seqNum: xdr.SequenceNumber.fromString('1'),
      cond: xdr.Preconditions.precondNone(),
      memo: xdr.Memo.memoNone(),
      operations: [],
      ext: new xdr.TransactionExt(0), // v0, no Soroban data
    });
    const envelope = new xdr.TransactionEnvelope.envelopeTypeTx(new xdr.TransactionV1Envelope({ tx, signatures: [] }));
    const xdrStr = envelope.toXDR('base64');

    const res = await passkeySend({ xdr: xdrStr });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toMatch(/must be a Soroban transaction/i);
    expect(submitTxMock).not.toHaveBeenCalled();
  });

  it('400 when xdr is a fee-bump envelope', async () => {
    // Build a fee-bump envelope (different envelope type)
    const source = Keypair.random();
    const account = new xdr.MuxedAccount.keyTypeEd25519(source.rawPublicKey());
    const innerTx = new xdr.Transaction({
      sourceAccount: account,
      fee: xdr.Uint32(100),
      seqNum: xdr.SequenceNumber.fromString('1'),
      cond: xdr.Preconditions.precondNone(),
      memo: xdr.Memo.memoNone(),
      operations: [],
      ext: new xdr.TransactionExt(0),
    });
    const innerEnv = new xdr.TransactionEnvelope.envelopeTypeTx(
      new xdr.TransactionV1Envelope({ tx: innerTx, signatures: [] }),
    );
    const feeBumpTx = new xdr.FeeBumpTransaction({
      feeSource: account,
      fee: xdr.Int64.fromString('200'),
      innerTx: xdr.FeeBumpTransactionInnerTx.envelopeTypeTx(innerEnv.v1()!),
      ext: new xdr.FeeBumpTransactionExt(0),
    });
    const feeBumpEnv = new xdr.TransactionEnvelope.envelopeTypeFeeBump(
      new xdr.FeeBumpTransactionEnvelope({ tx: feeBumpTx, signatures: [] }),
    );
    const xdrStr = feeBumpEnv.toXDR('base64');

    const res = await passkeySend({ xdr: xdrStr });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toMatch(/must be a v1 transaction/i);
    expect(submitTxMock).not.toHaveBeenCalled();
  });
});

// ══════════════════════════════════════════════════════════════════════════
// Suite — relayer error mapping (issue #172: typed errors → 422/502/504)
// ══════════════════════════════════════════════════════════════════════════

describe('POST /api/passkey-send — relayer error mapping', () => {
  it('422 when PluginExecutionError is thrown (relayer rejection)', async () => {
    submitSorobanTxMock.mockRejectedValueOnce(new PluginExecutionError('simulation failed: contract panic'));
    const res = await passkeySend({ func: validFunc(), auth: [validAuth()] });
    expect(res.status).toBe(422);
    const body = (await res.json()) as { error: string; code: string };
    expect(body.error).toMatch(/simulation failed/i);
    expect(body.code).toBe('RELAYER_EXECUTION_ERROR');
  });

  it('422 includes errorDetails.message when present', async () => {
    const err = new PluginExecutionError('outer message');
    err.errorDetails.message = 'inner detail message';
    submitSorobanTxMock.mockRejectedValueOnce(err);
    const res = await passkeySend({ func: validFunc(), auth: [validAuth()] });
    expect(res.status).toBe(422);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe('inner detail message');
  });

  it('502 when PluginTransportError with 5xx statusCode', async () => {
    submitTxMock.mockRejectedValueOnce(new PluginTransportError(503, 'upstream service unavailable'));
    const res = await passkeySend({ xdr: buildDeployEnvelope(1000) });
    expect(res.status).toBe(502);
    const body = (await res.json()) as { error: string; code: string };
    expect(body.error).toMatch(/unreachable.*503/i);
    expect(body.code).toBe('RELAYER_TRANSPORT_ERROR');
  });

  it('504 when PluginTransportError with timeout-like statusCode', async () => {
    submitTxMock.mockRejectedValueOnce(new PluginTransportError(408, 'request timeout'));
    const res = await passkeySend({ xdr: buildDeployEnvelope(1000) });
    expect(res.status).toBe(504);
    const body = (await res.json()) as { error: string; code: string };
    expect(body.error).toMatch(/unreachable.*408/i);
    expect(body.code).toBe('RELAYER_TRANSPORT_ERROR');
  });

  it('502 when PluginUnexpectedError (malformed relayer response)', async () => {
    submitSorobanTxMock.mockRejectedValueOnce(new PluginUnexpectedError('response not json'));
    const res = await passkeySend({ func: validFunc(), auth: [validAuth()] });
    expect(res.status).toBe(502);
    const body = (await res.json()) as { error: string; code: string };
    expect(body.error).toMatch(/malformed response/i);
    expect(body.code).toBe('RELAYER_UNEXPECTED_ERROR');
  });

  it('502 when unknown error is thrown (not a typed relayer error)', async () => {
    submitSorobanTxMock.mockRejectedValueOnce(new Error('something completely unexpected'));
    const res = await passkeySend({ func: validFunc(), auth: [validAuth()] });
    expect(res.status).toBe(502);
    const body = (await res.json()) as { error: string; code: string };
    expect(body.error).toBe('something completely unexpected');
    expect(body.code).toBe('UNKNOWN_ERROR');
  });

  it('502 when relayer returns no hash', async () => {
    submitSorobanTxMock.mockResolvedValueOnce({ hash: null });
    const res = await passkeySend({ func: validFunc(), auth: [validAuth()] });
    expect(res.status).toBe(502);
    const body = (await res.json()) as { error: string };
    expect(body.error).toMatch(/no tx hash/i);
  });

  it('502 when relayer returns empty object', async () => {
    submitSorobanTxMock.mockResolvedValueOnce({});
    const res = await passkeySend({ func: validFunc(), auth: [validAuth()] });
    expect(res.status).toBe(502);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// Suite — happy paths (issue #172 acceptance criteria)
// ══════════════════════════════════════════════════════════════════════════

describe('POST /api/passkey-send — happy paths', () => {
  it('200 with { func, auth } — calls submitSorobanTransaction', async () => {
    submitSorobanTxMock.mockResolvedValueOnce({ hash: 'abcd1234' });
    const res = await passkeySend({ func: validFunc(), auth: [validAuth(), validAuth()] });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { hash: string };
    expect(body.hash).toBe('abcd1234');
    expect(submitSorobanTxMock).toHaveBeenCalledTimes(1);
    expect(submitSorobanTxMock).toHaveBeenCalledWith({
      func: validFunc(),
      auth: [validAuth(), validAuth()],
    });
    expect(submitTxMock).not.toHaveBeenCalled();
  });

  it('200 with { xdr } — calls submitTransaction after refee', async () => {
    submitTxMock.mockResolvedValueOnce({ hash: 'deploy5678' });
    const deployXdr = buildDeployEnvelope(1000);
    const res = await passkeySend({ xdr: deployXdr });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { hash: string };
    expect(body.hash).toBe('deploy5678');
    expect(submitTxMock).toHaveBeenCalledTimes(1);
    expect(submitSorobanTxMock).not.toHaveBeenCalled();

    // Verify that refeeDeploy was called by checking the XDR was modified
    const submittedXdr = submitTxMock.mock.calls[0][0].xdr as string;
    expect(submittedXdr).not.toBe(deployXdr);

    // The refee'd tx should have fee === resourceFee
    const env = xdr.TransactionEnvelope.fromXDR(submittedXdr, 'base64');
    const tx = env.v1()?.tx();
    const resourceFee = Number(tx?.ext().sorobanData()?.resourceFee().toString());
    const actualFee = Number(tx?.fee().toString());
    expect(actualFee).toBe(resourceFee);
  });

  it('503 when PASSKEY_RELAYER_URL is not configured', async () => {
    vi.resetModules();
    vi.stubEnv('PASSKEY_RELAYER_URL', '');
    vi.stubEnv('PASSKEY_RELAYER_API_KEY', 'test-key');
    ({ POST } = (await import('./route')) as { POST: Post });
    const res = await passkeySend({ func: validFunc(), auth: [] });
    expect(res.status).toBe(503);
    const body = (await res.json()) as { error: string };
    expect(body.error).toMatch(/not configured/i);
  });

  it('503 when PASSKEY_RELAYER_API_KEY is not configured', async () => {
    vi.resetModules();
    vi.stubEnv('PASSKEY_RELAYER_URL', 'https://relayer.example.com');
    vi.stubEnv('PASSKEY_RELAYER_API_KEY', '');
    ({ POST } = (await import('./route')) as { POST: Post });
    const res = await passkeySend({ func: validFunc(), auth: [] });
    expect(res.status).toBe(503);
  });

  it('logs successful submission with hash', async () => {
    submitSorobanTxMock.mockResolvedValueOnce({ hash: 'logged-hash' });
    await passkeySend({ func: validFunc(), auth: [validAuth()] });
    expect(console.log).toHaveBeenCalledWith('[passkey-send] Success:', { hash: 'logged-hash' });
  });

  it('logs error details on PluginExecutionError', async () => {
    const err = new PluginExecutionError('test error');
    submitSorobanTxMock.mockRejectedValueOnce(err);
    await passkeySend({ func: validFunc(), auth: [validAuth()] });
    expect(console.error).toHaveBeenCalledWith(
      '[passkey-send] Relayer error:',
      expect.objectContaining({
        name: 'PluginExecutionError',
        message: 'test error',
      }),
    );
  });

  it('logs error on malformed input XDR', async () => {
    await passkeySend({ func: 'bad-xdr', auth: [] });
    expect(console.error).toHaveBeenCalledWith(
      '[passkey-send] Invalid func XDR:',
      expect.any(String),
    );
  });
});
