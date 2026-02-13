# ReleaseGate Attestation Demo

1. **Generate Attestation**:
   `releasegate analyze-pr --repo org/repo --pr 123 --emit-attestation release.json`

2. **Verify (Success)**:
   `releasegate verify-attestation release.json`
   > Output: VALID (ID: sha256:...)

3. **Tamper & Verify (Fail)**:
   `sed -i 's/ALLOW/BLOCK/g' release.json`
   `releasegate verify-attestation release.json`
   > Output: INVALID (Signature verification failed)
