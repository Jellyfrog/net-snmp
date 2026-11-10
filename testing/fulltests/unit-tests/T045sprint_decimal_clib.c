/* HEADER Test printing of integer values and OID subidentifiers */

/*
 * Check the decimal output of the integer value printers and of OID
 * subidentifiers for edge values. Each string is also printed into every
 * fixed buffer size: a buffer that is too small must make the print fail
 * without writing past the end of the buffer.
 */

/*
 * Run call for every buffer size below sizeof(buf), with sz holding the
 * size, and check the result against expected.
 */
#define CHECK_FIXED(desc, expected, call)                               \
    do {                                                                \
        size_t          n = strlen(expected), sz, j;                    \
        int             ret, bad = 0;                                   \
                                                                        \
        for (sz = 0; sz < sizeof(buf); sz++) {                          \
            memset(buf, 'Z', sizeof(buf));                              \
            ret = (call);                                               \
            for (j = sz; j < sizeof(buf); j++)                          \
                if (buf[j] != 'Z')                                      \
                    bad = 1;                                            \
            if (ret >= 0 ? ret != (int) n || strcmp(buf, expected) != 0 \
                : sz > n + 1)                                           \
                bad = 1;                                                \
        }                                                               \
        OKF(!bad, ("%s prints \"%s\"", desc, expected));               \
    } while (0)

static const long values[] = {
    0, 1, 9, 10, 99, 100, -1, -10, 123456789, (long) 0xffffffffUL,
    LONG_MAX, LONG_MIN
};
static const oid objid_ifin[] = { 1, 3, 6, 1, 2, 1, 2, 2, 1, 10, 4294967295UL };
static const oid objid_sysdescr[] = { 1, 3, 6, 1, 2, 1, 1, 1, 0 };
static const oid objid_unknown[] = {
    1, 3, 6, 1, 4, 1, 99999, 0, 4294967295UL, 10, 9
};
static const struct {
    const oid      *objid;
    size_t          len;
    const char     *symbolic;
} objids[] = {
    { objid_ifin, OID_LENGTH(objid_ifin), "IF-MIB::ifInOctets.4294967295" },
    { objid_sysdescr, OID_LENGTH(objid_sysdescr), "SNMPv2-MIB::sysDescr.0" },
    { objid_unknown, OID_LENGTH(objid_unknown),
      "SNMPv2-SMI::enterprises.99999.0.4294967295.10.9" },
};
char            buf[128], expected[128], mibdir[PATH_MAX];
netsnmp_variable_list var;
long            v;
size_t          i, k;

snprintf(mibdir, sizeof(mibdir), "%s/%s", ABS_SRCDIR, "mibs");
netsnmp_ds_set_string(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_MIBDIRS, mibdir);
init_snmp("T045");

memset(&var, 0, sizeof(var));
var.val.integer = &v;
var.val_len = sizeof(v);

for (i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
    v = values[i];

    var.type = ASN_INTEGER;
    snprintf(expected, sizeof(expected), "INTEGER: %ld", v);
    CHECK_FIXED("INTEGER", expected,
                snprint_by_type(buf, sz, &var, NULL, NULL, NULL));

    var.type = ASN_COUNTER;
    snprintf(expected, sizeof(expected), "Counter32: %lu",
             (unsigned long) v & 0xffffffffUL);
    CHECK_FIXED("Counter32", expected,
                snprint_by_type(buf, sz, &var, NULL, NULL, NULL));

    var.type = ASN_GAUGE;
    snprintf(expected, sizeof(expected), "Gauge32: %lu",
             (unsigned long) v & 0xffffffffUL);
    CHECK_FIXED("Gauge32", expected,
                snprint_by_type(buf, sz, &var, NULL, NULL, NULL));

    var.type = ASN_UINTEGER;
    snprintf(expected, sizeof(expected), "%lu", (unsigned long) v);
    CHECK_FIXED("UInteger32", expected,
                snprint_by_type(buf, sz, &var, NULL, NULL, NULL));

    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                           NETSNMP_DS_LIB_NUMERIC_TIMETICKS, 1);
    var.type = ASN_TIMETICKS;
    snprintf(expected, sizeof(expected), "%lu", (unsigned long) v);
    CHECK_FIXED("TimeTicks with -Ot", expected,
                snprint_by_type(buf, sz, &var, NULL, NULL, NULL));
    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                           NETSNMP_DS_LIB_NUMERIC_TIMETICKS, 0);
}

for (i = 0; i < sizeof(objids) / sizeof(objids[0]); i++) {
    CHECK_FIXED("OID", objids[i].symbolic,
                snprint_objid(buf, sz, objids[i].objid, objids[i].len));

    expected[0] = '\0';
    for (k = 0; k < objids[i].len; k++)
        snprintf(expected + strlen(expected),
                 sizeof(expected) - strlen(expected), ".%lu",
                 (unsigned long) objids[i].objid[k]);
    netsnmp_ds_set_int(NETSNMP_DS_LIBRARY_ID,
                       NETSNMP_DS_LIB_OID_OUTPUT_FORMAT,
                       NETSNMP_OID_OUTPUT_NUMERIC);
    CHECK_FIXED("OID with -On", expected,
                snprint_objid(buf, sz, objids[i].objid, objids[i].len));
    netsnmp_ds_set_int(NETSNMP_DS_LIBRARY_ID,
                       NETSNMP_DS_LIB_OID_OUTPUT_FORMAT, 0);
}

snmp_shutdown("T045");
