// The payment page's script: reads the x402 challenge embedded in the page, pays it from an
// injected wallet (EIP-1193: MetaMask and the like) by signing an EIP-3009
// TransferWithAuthorization, sends the payment to this same URL, and reloads once the gateway
// has settled it, so the purchase is delivered as a normal page load.
//
// Pure helpers are exposed on `radiusPay` for tests; everything that touches the page or the
// wallet lives in `run`.
(function (root) {
  'use strict';

  var CHAINS = {
    72344: {
      chainName: 'Radius Testnet',
      rpcUrls: ['https://rpc.testnet.radiustech.xyz'],
      blockExplorerUrls: ['https://testnet.radiustech.xyz'],
      nativeCurrency: { name: 'RUSD', symbol: 'RUSD', decimals: 18 },
      faucet: 'https://testnet.radiustech.xyz/wallet'
    },
    723487: {
      chainName: 'Radius',
      rpcUrls: ['https://rpc.radiustech.xyz'],
      blockExplorerUrls: ['https://network.radiustech.xyz'],
      nativeCurrency: { name: 'RUSD', symbol: 'RUSD', decimals: 18 }
    }
  };

  var METAMASK = 'https://metamask.io/download/';
  var SKEW_SECONDS = 600; // validAfter is set this far in the past, as the reference client does.

  /** The chain id of a CAIP-2 `eip155:<id>` network, or null. */
  function chainIdOf(network) {
    var match = /^eip155:(\d+)$/.exec(network || '');
    return match ? Number(match[1]) : null;
  }

  /**
   * The first offer this page can pay: `exact` on an EVM network through EIP-3009 (the default
   * transfer method). Permit2 offers need an allowance and a second signature, which this page
   * doesn't do yet.
   */
  function pick(accepts) {
    for (var i = 0; i < (accepts || []).length; i++) {
      var offer = accepts[i];
      var method = (offer.extra && offer.extra.assetTransferMethod) || 'eip3009';
      if (offer.scheme === 'exact' && chainIdOf(offer.network) !== null && method === 'eip3009') {
        return offer;
      }
    }
    return null;
  }

  function hex(bytes) {
    var out = '0x';
    for (var i = 0; i < bytes.length; i++) {
      out += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    }
    return out;
  }

  function randomNonce() {
    var bytes = new Uint8Array(32);
    (root.crypto || root.msCrypto).getRandomValues(bytes);
    return hex(bytes);
  }

  /** The EIP-712 typed data of an EIP-3009 authorization for `offer`, and the authorization. */
  function buildTypedData(offer, from, now, nonce) {
    var authorization = {
      from: from,
      to: offer.payTo,
      value: String(offer.amount),
      validAfter: String(Math.max(0, now - SKEW_SECONDS)),
      validBefore: String(now + (offer.maxTimeoutSeconds || 60)),
      nonce: nonce
    };
    var typedData = {
      types: {
        EIP712Domain: [
          { name: 'name', type: 'string' },
          { name: 'version', type: 'string' },
          { name: 'chainId', type: 'uint256' },
          { name: 'verifyingContract', type: 'address' }
        ],
        TransferWithAuthorization: [
          { name: 'from', type: 'address' },
          { name: 'to', type: 'address' },
          { name: 'value', type: 'uint256' },
          { name: 'validAfter', type: 'uint256' },
          { name: 'validBefore', type: 'uint256' },
          { name: 'nonce', type: 'bytes32' }
        ]
      },
      primaryType: 'TransferWithAuthorization',
      domain: {
        name: offer.extra && offer.extra.name,
        version: offer.extra && offer.extra.version,
        chainId: chainIdOf(offer.network),
        verifyingContract: offer.asset
      },
      message: authorization
    };
    return { typedData: typedData, authorization: authorization };
  }

  /** The x402 v2 PaymentPayload for the signed authorization, base64 for PAYMENT-SIGNATURE. */
  function encodePayload(challenge, offer, authorization, signature) {
    var payload = {
      x402Version: 2,
      resource: challenge.resource,
      accepted: offer,
      payload: { signature: signature, authorization: authorization }
    };
    var bytes = new TextEncoder().encode(JSON.stringify(payload));
    var binary = '';
    for (var i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }

  function decodeHeader(text) {
    try {
      var binary = atob(text);
      var bytes = new Uint8Array(binary.length);
      for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      return JSON.parse(new TextDecoder().decode(bytes));
    } catch (e) {
      return null;
    }
  }

  /**
   * What to tell the buyer about a gateway answer that wasn't a success: `{text, link}`.
   * `body` is the parsed JSON body (or null), `settlement` the decoded PAYMENT-RESPONSE (or null).
   */
  function errorMessage(status, body, settlement, offer) {
    var chain = CHAINS[chainIdOf(offer && offer.network)] || {};
    var reason = (body && (body.error || body.message)) || '';
    if (status === 402) {
      if (/insufficient|balance|funds/i.test(reason)) {
        return chain.faucet
          ? { text: 'Not enough ' + (offer.extra && offer.extra.name || 'tokens') + '. Get testnet funds from the faucet.', link: chain.faucet }
          : { text: 'Not enough funds in this wallet.' };
      }
      return { text: 'Payment refused: ' + (reason || 'the payment was not accepted') + '.' };
    }
    if (status === 503 && body && body.code === 'settlement_unknown') {
      var tx = settlement && settlement.transaction;
      var explorer = chain.blockExplorerUrls && chain.blockExplorerUrls[0];
      return {
        text: 'Your payment may have gone through, but this page could not confirm it. Do not pay again' + (tx ? '; check the transaction.' : '.'),
        link: tx && explorer ? explorer + '/tx/' + tx : undefined
      };
    }
    if (status === 502) return { text: 'The payment service could not be reached. Nothing was charged; try again.' };
    if (status === 504) return { text: 'The server took too long to answer. Nothing was charged; try again.' };
    return { text: 'Something went wrong (' + status + '). ' + (reason ? reason + '.' : '') };
  }

  /** `0x4373…Fe6e` for an address, unchanged otherwise. */
  function shorten(address) {
    return /^0x[0-9a-fA-F]{40}$/.test(address) ? address.slice(0, 6) + '…' + address.slice(-4) : address;
  }

  root.radiusPay = {
    pick: pick,
    buildTypedData: buildTypedData,
    encodePayload: encodePayload,
    decodeHeader: decodeHeader,
    errorMessage: errorMessage,
    chainIdOf: chainIdOf,
    shorten: shorten,
    CHAINS: CHAINS
  };

  if (typeof document === 'undefined') return;

  function run() {
    var block = document.getElementById('x402-challenge');
    var challenge = null;
    try { challenge = JSON.parse(block.textContent); } catch (e) { /* no challenge: nothing to pay */ }
    var button = document.getElementById('pay');
    var status = document.getElementById('status');
    var copy = document.getElementById('copy');
    var cli = document.getElementById('cli');
    var raw = document.getElementById('challenge');

    document.querySelectorAll('.address').forEach(function (el) {
      el.textContent = shorten(el.textContent.trim());
    });
    if (raw && challenge) raw.textContent = JSON.stringify(challenge, null, 2);
    if (status.textContent.trim()) status.classList.add('error');

    function say(text, kind, link) {
      status.className = 'status' + (kind ? ' ' + kind : '');
      status.textContent = '';
      status.appendChild(document.createTextNode(text + (link ? ' ' : '')));
      if (link) {
        var a = document.createElement('a');
        a.href = link;
        a.target = '_blank';
        a.rel = 'noopener';
        a.textContent = link.indexOf('metamask') !== -1 ? 'Install MetaMask' : link.indexOf('/tx/') !== -1 ? 'View transaction' : 'Open the faucet';
        status.appendChild(a);
      }
    }

    if (copy && cli) {
      copy.addEventListener('click', function () {
        navigator.clipboard.writeText(cli.textContent).then(function () {
          copy.textContent = 'Copied';
          setTimeout(function () { copy.textContent = 'Copy'; }, 1500);
        });
      });
    }

    var offer = challenge && pick(challenge.accepts);
    if (!offer) {
      button.disabled = true;
      if (challenge) say('These terms are paid through Permit2, which this page cannot sign yet. Use the terminal command below.', 'error');
      return;
    }
    var chain = CHAINS[chainIdOf(offer.network)];

    async function pay() {
      var ethereum = root.ethereum;
      if (!ethereum) {
        say('No wallet found. Install MetaMask to pay from this page.', 'error', METAMASK);
        return;
      }
      button.disabled = true;
      try {
        say('Waiting for your wallet…');
        var accounts = await ethereum.request({ method: 'eth_requestAccounts' });
        var wanted = '0x' + chainIdOf(offer.network).toString(16);
        var current = await ethereum.request({ method: 'eth_chainId' });
        if (String(current).toLowerCase() !== wanted) {
          say('Switching to ' + (chain ? chain.chainName : offer.network) + '…');
          try {
            await ethereum.request({ method: 'wallet_switchEthereumChain', params: [{ chainId: wanted }] });
          } catch (error) {
            var unknown = error && (error.code === 4902 || (error.data && error.data.originalError && error.data.originalError.code === 4902) || /unrecognized chain/i.test(error.message || ''));
            if (!unknown || !chain) throw error;
            await ethereum.request({
              method: 'wallet_addEthereumChain',
              params: [{ chainId: wanted, chainName: chain.chainName, rpcUrls: chain.rpcUrls, blockExplorerUrls: chain.blockExplorerUrls, nativeCurrency: chain.nativeCurrency }]
            });
          }
          current = await ethereum.request({ method: 'eth_chainId' });
          if (String(current).toLowerCase() !== wanted) {
            say('Your wallet is on another network and would not switch.', 'error');
            return;
          }
          accounts = await ethereum.request({ method: 'eth_accounts' });
        }
        var from = accounts && accounts[0];
        if (!from) {
          say('No account is connected.', 'error');
          return;
        }

        say('Sign the payment in your wallet');
        var now = Math.floor(Date.now() / 1000);
        var built = buildTypedData(offer, from, now, randomNonce());
        var signature = await ethereum.request({
          method: 'eth_signTypedData_v4',
          params: [from, JSON.stringify(built.typedData)]
        });

        say('Paying…');
        var response = await fetch(root.location.href, {
          method: 'GET',
          headers: {
            'PAYMENT-SIGNATURE': encodePayload(challenge, offer, built.authorization, signature),
            'Accept': 'application/json',
            'Radius-Page': '1'
          },
          cache: 'no-store',
          credentials: 'same-origin'
        });
        if (response.ok) {
          // The purchase is delivered by the reload; the gateway gave this page a ticket for it.
          if (response.body && response.body.cancel) await response.body.cancel();
          say('Paid. Loading…', 'ok');
          root.location.reload();
          return;
        }
        var body = null;
        try { body = await response.json(); } catch (e) { /* not JSON */ }
        var settlement = decodeHeader(response.headers.get('PAYMENT-RESPONSE') || '');
        var message = errorMessage(response.status, body, settlement, offer);
        say(message.text, 'error', message.link);
      } catch (error) {
        if (error && error.code === 4001) {
          say('You rejected the request.', 'error');
        } else {
          say('The wallet reported an error: ' + ((error && error.message) || error) + '.', 'error');
        }
      } finally {
        button.disabled = false;
      }
    }

    button.addEventListener('click', pay);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', run);
  } else {
    run();
  }
})(typeof window !== 'undefined' ? window : globalThis);
