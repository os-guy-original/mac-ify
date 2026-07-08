#!/usr/bin/env python3
import lief, capstone

fat = lief.MachO.parse('/home/z/my-project/mac-ify/tests/real/curl_macos')
b = fat[0]
text = None
for sec in b.sections:
    if sec.name == '__text':
        text = sec; break
text_data = bytes(text.content)
text_base = text.virtual_address
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

# SSL_CTX_new at 0x1001a5020
off = 0x1001a5020 - text_base
print('=== SSL_CTX_new ===')
for i, ins in enumerate(md.disasm(text_data[off:off+0x20], 0x1001a5020)):
    print(f'  0x{ins.address:x}: {ins.bytes.hex():<22s} {ins.mnemonic} {ins.op_str}')
    if 'ret' in ins.mnemonic or 'jmp' in ins.mnemonic:
        break

# Now check: after OPENSSL_init_ssl (0x1001a49bc), the next check is test eax,eax (0x1001a49c1)
# If eax==0, je to 0x1001a4f13 which returns NULL
# OPENSSL_init_ssl calls OPENSSL_init_crypto
# Let me check what OPENSSL_init_crypto returns when called by our test
# 
# Wait - the test showed OPENSSL_init_ssl(0x200000,NULL)=1
# But inside SSL_CTX_new_ex, OPENSSL_init_ssl is called with different args
# Let me check: SSL_CTX_new calls SSL_CTX_new_ex(NULL, NULL, method)
# SSL_CTX_new_ex: rdx=method, rdi=NULL(libctx), rsi=NULL(propq)
# At 0x1001a49a1: test rdx, rdx  (check method != NULL)
# At 0x1001a49bc: call OPENSSL_init_ssl(0x200000, NULL) — edi=0x200000, esi=0
# But wait, OPENSSL_init_ssl's first arg is set at 0x1001a49b5: mov edi, 0x200000
# And esi is xor'd to 0 at 0x1001a49ba: xor esi, esi
# So OPENSSL_init_ssl(0x200000, NULL) — this is OPENSSL_init_ssl(INIT flag, NULL opts)
# Our test calls OPENSSL_init_ssl(0x200000, NULL) and gets 1
# So that's fine.

# The issue must be that SSL_CTX_new returns NULL because ssl_load_ciphers
# or ssl_load_groups returns 0 INSIDE SSL_CTX_new_ex.
# But our test calls SSL_CTX_new which returns NULL...
# Let me check if SSL_CTX_new is actually just a wrapper:
print()
print('SSL_CTX_new is a tail-call to SSL_CTX_new_ex(NULL, NULL, method)')
print('SSL_CTX_new_ex does:')
print('  1. OPENSSL_init_ssl(0x200000, NULL) -> must return 1')
print('  2. SSL_get_ex_data_X509_STORE_CTX_idx() -> must return >= 0')
print('  3. CRYPTO_zalloc(0x728, ...) -> must return non-NULL')
print('  4. CRYPTO_THREAD_lock_new() -> must return non-NULL')
print('  5. CRYPTO_strdup() -> must return non-NULL')
print('  6. OPENSSL_LH_new + set_thunks -> must return non-NULL')
print('  7. X509_STORE_new() -> must return non-NULL')
print('  8. CTLOG_STORE_new_ex() -> must return non-NULL')
print('  9. ssl_load_ciphers(ctx) -> must return non-zero')
print(' 10. ssl_load_groups(ctx) -> must return non-zero')
print(' 11. ssl_load_sigalgs(ctx) -> must return non-zero')
print(' 12. ssl_setup_sigalgs(ctx) -> must return non-zero')
print(' 13. SSL_CTX_set_ciphersuites(ctx, ...) -> must return non-zero')
print(' 14. ssl_cert_new(ctx) -> must return non-NULL')
print('Steps 9-12 call OSSL_PROVIDER_do_all which needs providers loaded')
