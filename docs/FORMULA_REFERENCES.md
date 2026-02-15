# Block Mode Formula References

This project uses the mode equations from:

- NIST SP 800-38A (December 2001):
  - https://csrc.nist.gov/pubs/sp/800/38/a/final
  - PDF: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

## ECB (Section 6.1)

- `C_j = E_k(P_j)`
- `P_j = D_k(C_j)`

## CBC (Section 6.2)

- `C_1 = E_k(P_1 xor IV)`
- `C_j = E_k(P_j xor C_{j-1})` for `j >= 2`
- `P_1 = D_k(C_1) xor IV`
- `P_j = D_k(C_j) xor C_{j-1}` for `j >= 2`

## CFB (Section 6.3)

General segment form:

- `I_1 = IV`
- `I_j = LSB_{b-s}(I_{j-1}) || C_{j-1}`
- `O_j = E_k(I_j)`
- `C_j = P_j xor MSB_s(O_j)`
- `P_j = C_j xor MSB_s(O_j)`

For full-block CFB (`s = b`), this simplifies to:

- `O_j = E_k(C_{j-1})`, `C_0 = IV`
- `C_j = P_j xor O_j`
- `P_j = C_j xor O_j`

## OFB (Section 6.4)

- `I_1 = IV`
- `O_j = E_k(I_j)`
- `I_j = O_{j-1}` for `j >= 2`
- `C_j = P_j xor O_j`
- `P_j = C_j xor O_j`

## CTR (Section 6.5)

- `O_j = E_k(T_j)`
- `C_j = P_j xor O_j`
- `P_j = C_j xor O_j`

Appendix B also states that counter blocks must be unique per key.
