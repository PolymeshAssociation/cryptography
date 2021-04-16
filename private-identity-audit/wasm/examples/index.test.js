const pial = require("../pkg/");
const cil = require("../../../confidential-identity/wasm/pkg/");
const crypto = require("crypto");
const { v4: uuidv4, parse: uuidParse } = require("uuid");

const investor_did = [
  0x49,
  0x99,
  0x52,
  0x43,
  0x74,
  0x8c,
  0x4a,
  0xe7,
  0x11,
  0x8,
  0x3c,
  0x97,
  0x56,
  0x5f,
  0xfd,
  0xfd,
  0x60,
  0xdb,
  0x1d,
  0x8c,
  0xc5,
  0x85,
  0xf8,
  0xa7,
  0x1d,
  0x99,
  0x93,
  0x9c,
  0xbe,
  0xab,
  0xdd,
  0x5,
];
//const investor_unique_id = [
//  0x96,
//  0xd2,
//  0x2c,
//  0x25,
//  0x4a,
//  0xe1,
//  0xf4,
//  0x44,
//  0xe1,
//  0x3c,
//  0x6d,
//  0x7f,
//  0xc6,
//  0xde,
//  0xc2,
//  0xca,
//];

//// cdd_id is generated outside of PIAL system and is saved on the chain
//const cdd_id = [
//  30,
//  129,
//  68,
//  184,
//  40,
//  28,
//  244,
//  188,
//  229,
//  174,
//  230,
//  87,
//  147,
//  91,
//  85,
//  31,
//  87,
//  221,
//  60,
//  110,
//  52,
//  4,
//  32,
//  196,
//  87,
//  59,
//  63,
//  99,
//  253,
//  118,
//  34,
//  41,
//];

test("Prove and verify", () => {
  // // In the web
  // // - Do NOT use getRandomValue (see https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues#usage_notes)
  // // - Intead use generateKey (see https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey)
  //
  // const key = window.crypto.subtle.generateKey(
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
  let seed = JSON.stringify(buff.toJSON().data);

  // Phase 1: PUIS generates uids and commits to them and sends them to the CDD Provider.
  const rand_uuids = [uuidv4(), uuidv4(), uuidv4(), uuidv4()];
  const private_uuids = JSON.stringify(rand_uuids); // Generate 4 random uuids.

  const committed_set = pial.generate_committed_set(
    private_uuids,
    100, // Use a set of at least 100 private_uuids
    seed
  );

  const committed_uids = committed_set.committed_uids;
  const verifier_secrets = committed_set.verifier_secrets; // Kept private for phase 3.

  // Phase 2: CDD Provider receives committed_uids and generates the proofs.
  //          CDD Provider has independently received a private uuid as well.
  const investor_unique_id = [...uuidParse(rand_uuids[0])].map((v) => v);

  const cdd_claims = JSON.stringify([
    { investor_did: investor_did, investor_unique_id: investor_unique_id },
  ]);
  const cdd_id_str = cil.create_cdd_id(JSON.stringify(cdd_claims[0]));
  const cdd_ids = JSON.stringify([JSON.parse(cdd_id_str)]);

  buff = crypto.randomBytes(32);
  seed = JSON.stringify(buff.toJSON().data);
  const proofs = pial.generate_proofs(cdd_claims, committed_uids, seed);

  // Phase 3: PUIS receives the proofs. PUIS also has previous stored some verifier_secrets.
  const results = pial.verify_proofs(
    proofs.initial_messages,
    proofs.final_responses,
    cdd_ids,
    verifier_secrets,
    proofs.committed_uids
  );

  var i;
  for (i = 0; i < results.length; i++) {
    // TODO: change to assert
    console.log(results.get(0));
  }
});
