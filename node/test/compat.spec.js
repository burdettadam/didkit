const { Ed25519KeyPair } = require("crypto-ld");
const jsigs = require("jsonld-signatures");
const jsonld = require("jsonld");

const DIDKit = require("..");
const { compat } = DIDKit;

const key = {
  kty: "OKP",
  crv: "Ed25519",
  x: "PBcY2yJ4h_cLUnQNcYhplu9KQQBNpGxP4sYcMPdlu6I",
  d: "n5WUFIghmRYZi0rEYo2lz-Zg2B9B1KW4MYfJXwOXfyI",
};

describe("credential", () => {
  it("should verify issued credential", () => {
    const credential = {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1",
      ],
      id: "http://example.edu/credentials/1872",
      type: ["VerifiableCredential", "AlumniCredential"],
      issuer: "https://example.edu/issuers/565049",
      issuanceDate: "2010-01-01T19:23:24Z",
      credentialSubject: {
        id: "did:example:ebfeb1f712ebc6f1c276e12ec21",
        alumniOf: '<span lang="en">Example University</span>',
      },
    };

    const suite = new jsigs.suites.Ed25519Signature2018({
      verificationMethod: "https://example.edu/issuers/keys/1",
      key,
    });

    const vc = compat.issue({ credential, suite });

    const verifyResult = DIDKit.verifyCredential(credential, {
      proofPurpose: "assertionMethod",
    });

    expect(verifyResult["errors"].length).toBe(0);
  });
});
