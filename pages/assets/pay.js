// The payment page's script: lists the ways to pay the challenge embedded in the page, connects
// an injected wallet (EIP-1193: MetaMask and the like), shows the wallet's balance for each
// option, pays the chosen one by signing an EIP-3009 TransferWithAuthorization, sends it to this
// same URL, and reloads once the gateway has settled it, so the purchase is delivered as a normal
// page load.
//
// Pure helpers are exposed on `radiusPay` for tests; everything that touches the page or the
// wallet lives in `run`.
(function (root) {
  'use strict';

  var METAMASK = 'https://metamask.io/download/';
  var SKEW_SECONDS = 600; // validAfter is set this far in the past, as the reference client does.

  /** The chain id of a CAIP-2 `eip155:<id>` network, or null. */
  function chainIdOf(network) {
    var match = /^eip155:(\d+)$/.exec(network || '');
    return match ? Number(match[1]) : null;
  }

  /** Whether the page can pay an offer: `exact` on an EVM network through EIP-3009. */
  function payable(offer) {
    var method = (offer.extra && offer.extra.assetTransferMethod) || 'eip3009';
    return offer.scheme === 'exact' && chainIdOf(offer.network) !== null && method === 'eip3009';
  }

  /** The first offer this page can pay. */
  function pick(accepts) {
    for (var i = 0; i < (accepts || []).length; i++) {
      if (payable(accepts[i])) return accepts[i];
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

  /** `balanceOf(address)` call data. */
  function balanceOfData(address) {
    return '0x70a08231' + address.replace(/^0x/, '').toLowerCase().padStart(64, '0');
  }

  /** A uint256 from an ABI-encoded result (or any hex), as a BigInt; null when unreadable. */
  function parseUint(result) {
    if (typeof result !== 'string' || !/^0x[0-9a-fA-F]*$/.test(result)) return null;
    return result.length > 2 ? BigInt(result) : 0n;
  }

  /** `units` of a token with `decimals` places, trailing zeros dropped, at most 6 shown. */
  function formatUnits(units, decimals) {
    var text = units.toString().padStart(decimals + 1, '0');
    var whole = text.slice(0, text.length - decimals);
    var fraction = decimals ? text.slice(text.length - decimals).slice(0, 6).replace(/0+$/, '') : '';
    return fraction ? whole + '.' + fraction : whole;
  }

  /**
   * Which option to select once balances are known: the current one if it's payable and the
   * wallet can cover it, else the first payable option the wallet can cover, else the current.
   * `balances` maps an option's index to a BigInt (or null when unknown).
   */
  function chooseOption(options, balances, current) {
    var covers = function (option) {
      var balance = balances[option.index];
      return option.payable && typeof balance === 'bigint' && balance >= BigInt(option.amountUnits);
    };
    var selected = options.find(function (o) { return o.index === current; });
    if (selected && covers(selected)) return current;
    var first = options.find(covers);
    return first ? first.index : current;
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
   * `body` is the parsed JSON body (or null), `settlement` the decoded PAYMENT-RESPONSE (or null),
   * `chain` the selected option's chain (or null).
   */
  function errorMessage(status, body, settlement, option, chain) {
    chain = chain || {};
    var reason = (body && (body.error || body.message)) || '';
    if (status === 402) {
      if (/insufficient|balance|funds/i.test(reason)) {
        return chain.faucet
          ? { text: 'Not enough ' + ((option && option.symbol) || 'tokens') + '. Get testnet funds from the faucet.', link: chain.faucet }
          : { text: 'Not enough ' + ((option && option.symbol) || 'funds') + ' in this wallet.' };
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
    payable: payable,
    buildTypedData: buildTypedData,
    encodePayload: encodePayload,
    decodeHeader: decodeHeader,
    errorMessage: errorMessage,
    chainIdOf: chainIdOf,
    shorten: shorten,
    balanceOfData: balanceOfData,
    parseUint: parseUint,
    formatUnits: formatUnits,
    chooseOption: chooseOption
  };

  if (typeof document === 'undefined') return;

  function readJson(id) {
    var block = document.getElementById(id);
    try { return block ? JSON.parse(block.textContent) : null; } catch (e) { return null; }
  }

  function run() {
    var challenge = readJson('x402-challenge');
    var page = readJson('x402-page') || { options: [] };
    var options = page.options || [];
    var button = document.getElementById('pay');
    var wallet = document.getElementById('wallet');
    var status = document.getElementById('status');
    var copy = document.getElementById('copy');
    var cli = document.getElementById('cli');
    var raw = document.getElementById('challenge');

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

    var account = null;
    var balances = {};
    var radios = Array.prototype.slice.call(document.querySelectorAll('input[name="option"]'));

    function selectedIndex() {
      var checked = radios.find(function (r) { return r.checked; });
      return checked ? Number(checked.value) : null;
    }
    function optionAt(index) {
      return options.find(function (o) { return o.index === index; }) || null;
    }
    function offerAt(index) {
      return challenge && challenge.accepts ? challenge.accepts[index] : null;
    }
    function select(index) {
      radios.forEach(function (r) { r.checked = Number(r.value) === index; });
      label();
    }
    function label() {
      var option = optionAt(selectedIndex());
      if (!account) {
        button.textContent = 'Connect wallet';
      } else if (option) {
        button.textContent = 'Pay ' + option.amount + ' ' + option.symbol + ' on ' + option.networkName;
      } else {
        button.textContent = 'Pay';
      }
      button.disabled = !!account && !(option && option.payable);
    }

    radios.forEach(function (r) { r.addEventListener('change', label); });

    var anyPayable = options.some(function (o) { return o.payable; });
    if (!challenge || !anyPayable) {
      button.disabled = true;
      if (challenge) say('These terms are paid through Permit2, which this page cannot sign yet. Use the terminal command below.', 'error');
      return;
    }
    label();

    function showBalance(option, balance) {
      var el = document.querySelector('.balance[data-index="' + option.index + '"]');
      if (!el) return;
      el.className = 'balance';
      if (typeof balance !== 'bigint') {
        el.textContent = 'balance unavailable';
        return;
      }
      el.textContent = formatUnits(balance, option.decimals) + ' ' + option.symbol;
      el.classList.add(balance >= BigInt(option.amountUnits) ? 'ok' : 'insufficient');
    }

    async function readBalance(option) {
      if (!option.chain || !option.chain.rpcUrls || !option.chain.rpcUrls[0]) return null;
      try {
        var response = await fetch(option.chain.rpcUrls[0], {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_call', params: [{ to: option.asset, data: balanceOfData(account) }, 'latest'] })
        });
        var json = await response.json();
        return parseUint(json.result);
      } catch (e) {
        return null;
      }
    }

    async function refreshBalances() {
      await Promise.all(options.map(async function (option) {
        var balance = await readBalance(option);
        balances[option.index] = balance;
        showBalance(option, balance);
      }));
      select(chooseOption(options, balances, selectedIndex()));
    }

    async function connect() {
      var ethereum = root.ethereum;
      if (!ethereum) {
        say('No wallet found. Install MetaMask to pay from this page.', 'error', METAMASK);
        return;
      }
      button.disabled = true;
      try {
        say('Waiting for your wallet…');
        var accounts = await ethereum.request({ method: 'eth_requestAccounts' });
        account = accounts && accounts[0];
        if (!account) {
          say('No account is connected.', 'error');
          return;
        }
        wallet.textContent = 'Connected ' + shorten(account);
        say('');
        await refreshBalances();
        ethereum.on && ethereum.on('accountsChanged', function (changed) {
          account = changed && changed[0];
          wallet.textContent = account ? 'Connected ' + shorten(account) : '';
          if (account) refreshBalances(); else label();
        });
      } catch (error) {
        say(error && error.code === 4001 ? 'You rejected the request.' : 'The wallet reported an error: ' + ((error && error.message) || error) + '.', 'error');
      } finally {
        label();
      }
    }

    async function pay() {
      var ethereum = root.ethereum;
      var index = selectedIndex();
      var option = optionAt(index);
      var offer = offerAt(index);
      if (!option || !offer || !payable(offer)) {
        say('Choose a way to pay.', 'error');
        return;
      }
      var chain = option.chain;
      button.disabled = true;
      try {
        var wanted = '0x' + chainIdOf(offer.network).toString(16);
        var current = await ethereum.request({ method: 'eth_chainId' });
        if (String(current).toLowerCase() !== wanted) {
          say('Switching to ' + option.networkName + '…');
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
          var accounts = await ethereum.request({ method: 'eth_accounts' });
          if (accounts && accounts[0]) account = accounts[0];
        }

        say('Sign the payment in your wallet');
        var now = Math.floor(Date.now() / 1000);
        var built = buildTypedData(offer, account, now, randomNonce());
        var signature = await ethereum.request({
          method: 'eth_signTypedData_v4',
          params: [account, JSON.stringify(built.typedData)]
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
        var message = errorMessage(response.status, body, settlement, option, chain);
        say(message.text, 'error', message.link);
      } catch (error) {
        if (error && error.code === 4001) {
          say('You rejected the request.', 'error');
        } else {
          say('The wallet reported an error: ' + ((error && error.message) || error) + '.', 'error');
        }
      } finally {
        label();
      }
    }

    button.addEventListener('click', function () {
      if (account) pay(); else connect();
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', run);
  } else {
    run();
  }
})(typeof window !== 'undefined' ? window : globalThis);
