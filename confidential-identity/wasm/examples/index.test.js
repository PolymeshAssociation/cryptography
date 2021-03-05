const cil = require('../pkg/');
const crypto = require('crypto');


let investor_did = [0x49, 0x99, 0x52, 0x43, 0x74, 0x8c, 0x4a, 0xe7, 0x11, 0x8, 0x3c, 0x97, 0x56, 0x5f, 0xfd, 0xfd, 0x60, 0xdb, 0x1d, 0x8c, 0xc5, 0x85, 0xf8, 0xa7, 0x1d, 0x99, 0x93, 0x9c, 0xbe, 0xab, 0xdd, 0x5];
let investor_unique_id = [0x96, 0xd2, 0x2c, 0x25, 0x4a, 0xe1, 0xf4, 0x44, 0xe1, 0x3c, 0x6d, 0x7f, 0xc6, 0xde, 0xc2, 0xca];
let scope_did = [0x8a, 0xe1, 0x49, 0xda, 0xb0, 0x2a, 0xa9, 0x8f, 0x7e, 0xd2, 0xe8, 0x2];

test('create CDD ID', () => {
  let cdd_claim = {"investor_did": investor_did, "investor_unique_id": investor_unique_id};
  let cdd_id_str = cil.create_cdd_id(JSON.stringify(cdd_claim));

  let got_cdd_id = JSON.parse(cdd_id_str);
  let want_cdd_id = [30, 129, 68, 184, 40, 28, 244, 188, 229, 174, 230, 87, 147, 91, 85, 31, 87, 221, 60, 110, 52, 4, 32, 196, 87, 59, 63, 99, 253, 118, 34, 41];

  expect(got_cdd_id).toEqual(want_cdd_id);
});


test('create SCOPE ID', () => {
  let seed = JSON.stringify([0x49, 0x99, 0x52, 0x43, 0x74, 0x8c, 0x4a, 0xe7, 0x11, 0x8, 0x3c, 0x97, 0x56, 0x5f, 0xfd, 0xfd, 0x60, 0xdb, 0x1d, 0x8c, 0xc5, 0x85, 0xf8, 0xa7, 0x1d, 0x99, 0x93, 0x9c, 0xbe, 0xab, 0xdd, 0x5]);
  let cdd_claim = JSON.stringify({"investor_did": investor_did, "investor_unique_id": investor_unique_id});
  let scope_claim = JSON.stringify({"scope_did": scope_did, "investor_unique_id": investor_unique_id});
  let proof = cil.create_scope_claim_proof(cdd_claim, scope_claim, seed);

  let got_proof = JSON.parse(proof);
  let want_proof = {"proof_scope_id_wellformed": {"R": [52, 240, 207, 134, 203, 75, 132, 61, 187, 169, 185, 108, 40, 204, 18, 20, 217, 242, 201, 168, 151, 85, 101, 69, 253, 17, 148, 246, 142, 229, 8, 76], "s": [149, 10, 80, 232, 187, 171, 90, 194, 228, 124, 233, 166, 108, 7, 65, 7, 126, 147, 96, 121, 148, 2, 151, 42, 33, 51, 203, 155, 217, 238, 196, 11]}, "proof_scope_id_cdd_id_match": {"challenge_responses": [[130, 28, 234, 98, 169, 25, 203, 143, 30, 113, 231, 19, 10, 74, 93, 231, 45, 110, 193, 247, 229, 235, 108, 233, 243, 53, 111, 101, 227, 223, 38, 9], [129, 62, 114, 167, 62, 5, 162, 105, 54, 94, 125, 132, 153, 235, 229, 43, 188, 83, 89, 31, 239, 159, 168, 144, 236, 123, 94, 11, 75, 207, 235, 11]], "subtract_expressions_res": [220, 229, 118, 34, 213, 251, 66, 212, 255, 115, 246, 8, 190, 216, 124, 23, 87, 134, 105, 43, 113, 166, 227, 213, 225, 203, 40, 185, 55, 115, 119, 92], "blinded_scope_did_hash": [158, 176, 157, 14, 144, 41, 41, 43, 34, 34, 101, 222, 11, 114, 191, 170, 191, 132, 132, 32, 179, 245, 148, 176, 229, 120, 161, 83, 247, 228, 173, 33]}, "scope_id": [120, 130, 245, 88, 127, 53, 254, 68, 10, 106, 181, 63, 250, 129, 32, 24, 40, 14, 20, 7, 60, 15, 157, 146, 234, 151, 249, 11, 162, 131, 89, 68]};

  expect(got_proof).toEqual(want_proof);
});


test('Generate Secure Seed', () => {
  // // In the web
  // // - Do NOT use getRandomValue (see https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues#usage_notes)
  // // - Intead use generateKey (see https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey)
  //
  // let key = window.crypto.subtle.generateKey(
  //   {
  //     name: "AES-GCM",
  //     length: 256
  //   },
  //   true,
  //   ["encrypt", "decrypt"]
  // );


  // In nodejs random bytes is a CSPRNG. A note about the bias of randomBytes: this CSPRNG is biased if the transformation
  // is not done carefully: (e.g., generating the random byte and then calculating the module of it to ge a smaller value).
  // For furthur reading check: 
  // - https://nodejs.org/api/crypto.html#crypto_crypto_randombytes_size_callback
  // - https://gist.github.com/joepie91/7105003c3b26e65efcea63f3db82dfba
  // In our case, we do not perform any transformation.
  let buff = crypto.randomBytes(32);
  let seed = buff.toJSON().data;

  let cdd_claim = {"investor_did": investor_did, "investor_unique_id": investor_unique_id};
  let scope_claim = {"scope_did": scope_did, "investor_unique_id": investor_unique_id};
  let proof = cil.create_scope_claim_proof(JSON.stringify(cdd_claim), JSON.stringify(scope_claim), JSON.stringify(seed));
  expect(proof.length).not.toEqual(0);
});


test('verify the proof - positive case', () => {
  // Check the notes in the 'Generate Secure Seed'.
  let seed = JSON.stringify(crypto.randomBytes(32).toJSON().data);
  let cdd_claim = JSON.stringify({"investor_did": investor_did, "investor_unique_id": investor_unique_id});
  let scope_claim = JSON.stringify({"scope_did": scope_did, "investor_unique_id": investor_unique_id});

  let cdd_id = cil.create_cdd_id(cdd_claim);
  let proof = cil.create_scope_claim_proof(cdd_claim, scope_claim, seed);
  expect(() => {
    cil._verify_scope_claim_proof(proof, JSON.stringify(investor_did), JSON.stringify(scope_did), cdd_id);
  }).not.toThrow();
});

test('verify the proof - negative test', () => {
  // Check the notes in the 'Generate Secure Seed'.
  let seed = JSON.stringify(crypto.randomBytes(32).toJSON().data);
  let cdd_claim = JSON.stringify({"investor_did": investor_did, "investor_unique_id": investor_unique_id});
  let scope_claim = JSON.stringify({"scope_did": scope_did, "investor_unique_id": investor_unique_id});

  let cdd_id = cil.create_cdd_id(cdd_claim);
  let proof_str = cil.create_scope_claim_proof(cdd_claim, scope_claim, seed);


  // Invalid Signature.
  var proof = JSON.parse(proof_str);
  proof.proof_scope_id_wellformed.R[0] += 1;
  expect(() => {
    cil._verify_scope_claim_proof(JSON.stringify(proof), JSON.stringify(investor_did), JSON.stringify(scope_did), cdd_id);
  }).toThrow(/signature verification failed/);


  // Invalid ZKP.
  var proof = JSON.parse(proof_str);
  proof.proof_scope_id_cdd_id_match.challenge_responses[0][0] += 1;
  expect(() => {
    cil._verify_scope_claim_proof(JSON.stringify(proof), JSON.stringify(investor_did), JSON.stringify(scope_did), cdd_id);
  }).toThrow(/Zero Knowledge Proof failed/);
});
