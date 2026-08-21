/** RSA-OAEP-256 public JWK. Private key lives in LOGIN_PRIVATE_JWK (secret / .dev.vars). */
export const LOGIN_PUBLIC_JWK = {
  kty: "RSA",
  alg: "RSA-OAEP-256",
  e: "AQAB",
  n: "rYh_TPVr68eOBvIHaYAGiuo5KpYcFnE5VSTmjyjPLxl1S-ywh-vHDS3LkhBAyC0q3ufiYtOrEkvBUfe7dBkWdlMldtAEnPe9MHmHB6uZxIMJyOc-qAGAoGg9L1qGotj_b2ijJJq3HuMxjK9uN1Cez7ZeWi9p7nBSKjx3xZ-2FeHMkbB4I3eobCbnstJxOMtnP4b6TYY3pvrM1D_LE6nMTLIR9GuC-HnLE-SPjlThGKIjGK1nMjQW3adewGFTxAUdXv6lvghmBCogL4ZQ4VfCHlGbLRXO-a9BR85yv27bMX4uURr7yXNKh14NHV2uxFPp_P3ZYuvfRRhmtxD85AgaEQ",
  key_ops: ["encrypt"],
  ext: true,
};
