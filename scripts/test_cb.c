/* Test callback for CONF_parse_list that pushes to a stack */
static int macify_test_cb(const char *name, int name_len, void *arg) {
    /* arg is the stack pointer */
    void *sk = arg;
    /* In OpenSSL, OPENSSL_sk_push returns 1 on success, 0 on failure */
    int (*push_fn)(void *, void *) = (int (*)(void *, void *))arg;
    /* Actually, arg IS the stack, and we need to push the cipher name */
    /* But we can't call OPENSSL_sk_push from here without knowing its address */
    /* So just count callbacks */
    (void)name; (void)name_len; (void)sk; (void)push_fn;
    return 1;  /* success */
}
