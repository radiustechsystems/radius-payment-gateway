// `node --test pages/assets/pay.test.mjs`: the pure helpers of pay.js. Not part of `cargo test`.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
require('./pay.js');
const pay = globalThis.radiusPay;

const sbc = '0x33ad9e4BD16B69B5BFdED37D8B5D9fF9aba014Fb';
const payTo = '0x4373dD700774F8C3f649AC58B7EDCC112785Fe6e';
const offer = (method) => ({
  scheme: 'exact', network: 'eip155:72344', amount: '10000', asset: sbc, payTo, maxTimeoutSeconds: 60,
  extra: { assetTransferMethod: method, name: 'Stable Coin', version: '1' }
});

test('pick takes the first EIP-3009 offer on an EVM network', () => {
  assert.equal(pay.pick([offer('permit2'), offer('eip3009')]).extra.assetTransferMethod, 'eip3009');
  assert.equal(pay.pick([offer('permit2')]), null);
  const bare = offer('eip3009'); delete bare.extra.assetTransferMethod;
  assert.equal(pay.pick([bare]), bare);
  assert.equal(pay.pick([{ ...offer('eip3009'), network: 'solana:x' }]), null);
});

test('buildTypedData signs TransferWithAuthorization on the token domain', () => {
  const from = '0x857b06519E91e3A54538791bDbb0E22373e36b66';
  const nonce = '0x' + '11'.repeat(32);
  const { typedData, authorization } = pay.buildTypedData(offer('eip3009'), from, 1_760_000_000, nonce);
  assert.equal(typedData.primaryType, 'TransferWithAuthorization');
  assert.deepEqual(typedData.domain, { name: 'Stable Coin', version: '1', chainId: 72344, verifyingContract: sbc });
  assert.deepEqual(typedData.types.TransferWithAuthorization.map((f) => f.name + ':' + f.type),
    ['from:address', 'to:address', 'value:uint256', 'validAfter:uint256', 'validBefore:uint256', 'nonce:bytes32']);
  assert.deepEqual(authorization, { from, to: payTo, value: '10000', validAfter: String(1_760_000_000 - 600), validBefore: String(1_760_000_060), nonce });
  assert.equal(typedData.message, authorization);
});

test('encodePayload round-trips through the header encoding', () => {
  const challenge = { resource: { url: 'https://api.example.com/paid/x', description: 'd' } };
  const { authorization } = pay.buildTypedData(offer('eip3009'), payTo, 1, '0x' + '00'.repeat(32));
  const encoded = pay.encodePayload(challenge, offer('eip3009'), authorization, '0xsig');
  const decoded = pay.decodeHeader(encoded);
  assert.equal(decoded.x402Version, 2);
  assert.deepEqual(decoded.resource, challenge.resource);
  assert.deepEqual(decoded.accepted, offer('eip3009'));
  assert.equal(decoded.payload.signature, '0xsig');
  assert.equal(decoded.payload.authorization.nonce, '0x' + '00'.repeat(32));
  assert.equal(pay.decodeHeader('not base64!'), null);
});

const chain = { chainName: 'Radius Testnet', blockExplorerUrls: ['https://testnet.radiustech.xyz'], faucet: 'https://testnet.radiustech.xyz/wallet' };
const option = (index, payable, amountUnits) => ({ index, amount: '0.01', amountUnits, symbol: 'SBC', decimals: 6, payable, chain });

test('errorMessage explains refusals, unknown settlements and outages', () => {
  const o = option(0, true, '10000');
  assert.match(pay.errorMessage(402, { error: 'insufficient_funds' }, null, o, chain).link, /wallet/);
  assert.match(pay.errorMessage(402, { error: 'settlement failed: x' }, null, o, chain).text, /Payment refused: settlement failed: x/);
  const unknown = pay.errorMessage(503, { code: 'settlement_unknown' }, { transaction: '0xabc' }, o, chain);
  assert.match(unknown.text, /Do not pay again/);
  assert.equal(unknown.link, 'https://testnet.radiustech.xyz/tx/0xabc');
  assert.match(pay.errorMessage(502, null, null, o, null).text, /Nothing was charged/);
});

test('balances are read with balanceOf and shown in units', () => {
  assert.equal(pay.balanceOfData('0x4373dD700774F8C3f649AC58B7EDCC112785Fe6e'),
    '0x70a082310000000000000000000000004373dd700774f8c3f649ac58b7edcc112785fe6e');
  assert.equal(pay.parseUint('0x' + '0'.repeat(63) + 'a'), 10n);
  assert.equal(pay.parseUint('0x'), 0n);
  assert.equal(pay.parseUint(undefined), null);
  assert.equal(pay.formatUnits(10000n, 6), '0.01');
  assert.equal(pay.formatUnits(520000n, 6), '0.52');
  assert.equal(pay.formatUnits(1234567890n, 6), '1234.56789');
  assert.equal(pay.formatUnits(0n, 6), '0');
  assert.equal(pay.formatUnits(5n, 0), '5');
});

test('chooseOption keeps a covered selection and otherwise takes the first covered option', () => {
  const options = [option(0, true, '10000'), option(1, false, '10000'), option(2, true, '10000')];
  assert.equal(pay.chooseOption(options, { 0: 5000n, 1: 10n ** 9n, 2: 20000n }, 0), 2, 'moves off an uncovered option');
  assert.equal(pay.chooseOption(options, { 0: 20000n, 2: 20000n }, 2), 2, 'keeps a covered one');
  assert.equal(pay.chooseOption(options, { 0: 0n, 2: null }, 0), 0, 'stays when nothing covers');
});

test('shorten keeps the ends of an address', () => {
  assert.equal(pay.shorten(payTo), '0x4373…Fe6e');
  assert.equal(pay.shorten('not an address'), 'not an address');
});
