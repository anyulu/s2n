/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include "s2n_test.h"

#include <string.h>
#include <stdio.h>

#include <s2n.h>

#include "testlib/s2n_testlib.h"

#include "tls/s2n_cipher_suites.h"
#include "stuffer/s2n_stuffer.h"
#include "crypto/s2n_cipher.h"
#include "utils/s2n_random.h"
#include "crypto/s2n_hmac.h"
#include "tls/s2n_record.h"
#include "tls/s2n_prf.h"

// added include paths
#include "tls/s2n_security_policies.h"

char* mapToIANA (char *key) {
    if (!strcmp(key, "NULL-MD5")) return "TLS_RSA_WITH_NULL_MD5";
    if (!strcmp(key, "NULL-SHA")) return "TLS_RSA_WITH_NULL_SHA";
    if (!strcmp(key, "EXP-RC4-MD5")) return "TLS_RSA_EXPORT_WITH_RC4_40_MD5";
    if (!strcmp(key, "RC4-MD5")) return "TLS_RSA_WITH_RC4_128_MD5";
    if (!strcmp(key, "RC4-SHA")) return "TLS_RSA_WITH_RC4_128_SHA";
    if (!strcmp(key, "EXP-RC2-CBC-MD5")) return "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5";
    if (!strcmp(key, "IDEA-CBC-SHA")) return "TLS_RSA_WITH_IDEA_CBC_SHA";
    if (!strcmp(key, "EXP-DES-CBC-SHA")) return "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA";
    if (!strcmp(key, "DES-CBC-SHA")) return "TLS_RSA_WITH_DES_CBC_SHA";
    if (!strcmp(key, "DES-CBC3-SHA")) return "TLS_RSA_WITH_3DES_EDE_CBC_SHA";
    if (!strcmp(key, "EXP-DH-DSS-DES-CBC-SHA")) return "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA";
    if (!strcmp(key, "DH-DSS-DES-CBC-SHA")) return "TLS_DH_DSS_WITH_DES_CBC_SHA";
    if (!strcmp(key, "DH-DSS-DES-CBC3-SHA")) return "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA";
    if (!strcmp(key, "EXP-DH-RSA-DES-CBC-SHA")) return "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA";
    if (!strcmp(key, "DH-RSA-DES-CBC-SHA")) return "TLS_DH_RSA_WITH_DES_CBC_SHA";
    if (!strcmp(key, "DH-RSA-DES-CBC3-SHA")) return "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA";
    if (!strcmp(key, "EXP-EDH-DSS-DES-CBC-SHA")) return "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA";
    if (!strcmp(key, "EDH-DSS-DES-CBC-SHA")) return "TLS_DHE_DSS_WITH_DES_CBC_SHA";
    if (!strcmp(key, "EDH-DSS-DES-CBC3-SHA")) return "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA";
    if (!strcmp(key, "EXP-EDH-RSA-DES-CBC-SHA")) return "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA";
    if (!strcmp(key, "EDH-RSA-DES-CBC-SHA")) return "TLS_DHE_RSA_WITH_DES_CBC_SHA";
    if (!strcmp(key, "EDH-RSA-DES-CBC3-SHA")) return "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA";
    if (!strcmp(key, "EXP-ADH-RC4-MD5")) return "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5";
    if (!strcmp(key, "ADH-RC4-MD5")) return "TLS_DH_anon_WITH_RC4_128_MD5";
    if (!strcmp(key, "EXP-ADH-DES-CBC-SHA")) return "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA";
    if (!strcmp(key, "ADH-DES-CBC-SHA")) return "TLS_DH_anon_WITH_DES_CBC_SHA";
    if (!strcmp(key, "ADH-DES-CBC3-SHA")) return "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA";
    if (!strcmp(key, "KRB5-DES-CBC-SHA")) return "TLS_KRB5_WITH_DES_CBC_SHA";
    if (!strcmp(key, "KRB5-DES-CBC3-SHA")) return "TLS_KRB5_WITH_3DES_EDE_CBC_SHA";
    if (!strcmp(key, "KRB5-RC4-SHA")) return "TLS_KRB5_WITH_RC4_128_SHA";
    if (!strcmp(key, "KRB5-IDEA-CBC-SHA")) return "TLS_KRB5_WITH_IDEA_CBC_SHA";
    if (!strcmp(key, "KRB5-DES-CBC-MD5")) return "TLS_KRB5_WITH_DES_CBC_MD5";
    if (!strcmp(key, "KRB5-DES-CBC3-MD5")) return "TLS_KRB5_WITH_3DES_EDE_CBC_MD5";
    if (!strcmp(key, "KRB5-RC4-MD5")) return "TLS_KRB5_WITH_RC4_128_MD5";
    if (!strcmp(key, "KRB5-IDEA-CBC-MD5")) return "TLS_KRB5_WITH_IDEA_CBC_MD5";
    if (!strcmp(key, "EXP-KRB5-DES-CBC-SHA")) return "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA";
    if (!strcmp(key, "EXP-KRB5-RC2-CBC-SHA")) return "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA";
    if (!strcmp(key, "EXP-KRB5-RC4-SHA")) return "TLS_KRB5_EXPORT_WITH_RC4_40_SHA";
    if (!strcmp(key, "EXP-KRB5-DES-CBC-MD5")) return "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5";
    if (!strcmp(key, "EXP-KRB5-RC2-CBC-MD5")) return "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5";
    if (!strcmp(key, "EXP-KRB5-RC4-MD5")) return "TLS_KRB5_EXPORT_WITH_RC4_40_MD5";
    if (!strcmp(key, "PSK-NULL-SHA")) return "TLS_PSK_WITH_NULL_SHA";
    if (!strcmp(key, "DHE-PSK-NULL-SHA")) return "TLS_DHE_PSK_WITH_NULL_SHA";
    if (!strcmp(key, "RSA-PSK-NULL-SHA")) return "TLS_RSA_PSK_WITH_NULL_SHA";
    if (!strcmp(key, "AES128-SHA")) return "TLS_RSA_WITH_AES_128_CBC_SHA";
    if (!strcmp(key, "DH-DSS-AES128-SHA")) return "TLS_DH_DSS_WITH_AES_128_CBC_SHA";
    if (!strcmp(key, "DH-RSA-AES128-SHA")) return "TLS_DH_RSA_WITH_AES_128_CBC_SHA";
    if (!strcmp(key, "DHE-DSS-AES128-SHA")) return "TLS_DHE_DSS_WITH_AES_128_CBC_SHA";
    if (!strcmp(key, "DHE-RSA-AES128-SHA")) return "TLS_DHE_RSA_WITH_AES_128_CBC_SHA";
    if (!strcmp(key, "ADH-AES128-SHA")) return "TLS_DH_anon_WITH_AES_128_CBC_SHA";
    if (!strcmp(key, "AES256-SHA")) return "TLS_RSA_WITH_AES_256_CBC_SHA";
    if (!strcmp(key, "DH-DSS-AES256-SHA")) return "TLS_DH_DSS_WITH_AES_256_CBC_SHA";
    if (!strcmp(key, "DH-RSA-AES256-SHA")) return "TLS_DH_RSA_WITH_AES_256_CBC_SHA";
    if (!strcmp(key, "DHE-DSS-AES256-SHA")) return "TLS_DHE_DSS_WITH_AES_256_CBC_SHA";
    if (!strcmp(key, "DHE-RSA-AES256-SHA")) return "TLS_DHE_RSA_WITH_AES_256_CBC_SHA";
    if (!strcmp(key, "ADH-AES256-SHA")) return "TLS_DH_anon_WITH_AES_256_CBC_SHA";
    if (!strcmp(key, "NULL-SHA256")) return "TLS_RSA_WITH_NULL_SHA256";
    if (!strcmp(key, "AES128-SHA256")) return "TLS_RSA_WITH_AES_128_CBC_SHA256";
    if (!strcmp(key, "AES256-SHA256")) return "TLS_RSA_WITH_AES_256_CBC_SHA256";
    if (!strcmp(key, "DH-DSS-AES128-SHA256")) return "TLS_DH_DSS_WITH_AES_128_CBC_SHA256";
    if (!strcmp(key, "DH-RSA-AES128-SHA256")) return "TLS_DH_RSA_WITH_AES_128_CBC_SHA256";
    if (!strcmp(key, "DHE-DSS-AES128-SHA256")) return "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256";
    if (!strcmp(key, "CAMELLIA128-SHA")) return "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA";
    if (!strcmp(key, "DH-DSS-CAMELLIA128-SHA")) return "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA";
    if (!strcmp(key, "DH-RSA-CAMELLIA128-SHA")) return "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA";
    if (!strcmp(key, "DHE-DSS-CAMELLIA128-SHA")) return "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA";
    if (!strcmp(key, "DHE-RSA-CAMELLIA128-SHA")) return "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA";
    if (!strcmp(key, "ADH-CAMELLIA128-SHA")) return "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA";
    if (!strcmp(key, "EXP1024-RC4-MD5")) return "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5";
    if (!strcmp(key, "EXP1024-RC2-CBC-MD5")) return "TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5";
    if (!strcmp(key, "EXP1024-DES-CBC-SHA")) return "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA";
    if (!strcmp(key, "EXP1024-DHE-DSS-DES-CBC-SHA")) return "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA";
    if (!strcmp(key, "EXP1024-RC4-SHA")) return "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA";
    if (!strcmp(key, "EXP1024-DHE-DSS-RC4-SHA")) return "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA";
    if (!strcmp(key, "DHE-DSS-RC4-SHA")) return "TLS_DHE_DSS_WITH_RC4_128_SHA";
    if (!strcmp(key, "DHE-RSA-AES128-SHA256")) return "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256";
    if (!strcmp(key, "DH-DSS-AES256-SHA256")) return "TLS_DH_DSS_WITH_AES_256_CBC_SHA256";
    if (!strcmp(key, "DH-RSA-AES256-SHA256")) return "TLS_DH_RSA_WITH_AES_256_CBC_SHA256";
    if (!strcmp(key, "DHE-DSS-AES256-SHA256")) return "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256";
    if (!strcmp(key, "DHE-RSA-AES256-SHA256")) return "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256";
    if (!strcmp(key, "ADH-AES128-SHA256")) return "TLS_DH_anon_WITH_AES_128_CBC_SHA256";
    if (!strcmp(key, "ADH-AES256-SHA256")) return "TLS_DH_anon_WITH_AES_256_CBC_SHA256";
    if (!strcmp(key, "GOST94-GOST89-GOST89")) return "TLS_GOSTR341094_WITH_28147_CNT_IMIT";
    if (!strcmp(key, "GOST2001-GOST89-GOST89")) return "TLS_GOSTR341001_WITH_28147_CNT_IMIT";
    if (!strcmp(key, "GOST94-NULL-GOST94")) return "TLS_GOSTR341001_WITH_NULL_GOSTR3411";
    if (!strcmp(key, "GOST2001-GOST89-GOST89")) return "TLS_GOSTR341094_WITH_NULL_GOSTR3411";
    if (!strcmp(key, "CAMELLIA256-SHA")) return "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA";
    if (!strcmp(key, "CAMELLIA256-SHA256")) return "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256";
    if (!strcmp(key, "DH-DSS-CAMELLIA256-SHA")) return "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA";
    if (!strcmp(key, "DH-RSA-CAMELLIA256-SHA")) return "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA";
    if (!strcmp(key, "DHE-DSS-CAMELLIA256-SHA")) return "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA";
    if (!strcmp(key, "DHE-RSA-CAMELLIA256-SHA")) return "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA";
    if (!strcmp(key, "ADH-CAMELLIA256-SHA")) return "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA";
    if (!strcmp(key, "PSK-RC4-SHA")) return "TLS_PSK_WITH_RC4_128_SHA";
    if (!strcmp(key, "PSK-3DES-EDE-CBC-SHA")) return "TLS_PSK_WITH_3DES_EDE_CBC_SHA";
    if (!strcmp(key, "PSK-AES128-CBC-SHA")) return "TLS_PSK_WITH_AES_128_CBC_SHA";
    if (!strcmp(key, "PSK-AES256-CBC-SHA")) return "TLS_PSK_WITH_AES_256_CBC_SHA";
    if (!strcmp(key, "SEED-SHA")) return "TLS_RSA_WITH_SEED_CBC_SHA";
    if (!strcmp(key, "DH-DSS-SEED-SHA")) return "TLS_DH_DSS_WITH_SEED_CBC_SHA";
    if (!strcmp(key, "DH-RSA-SEED-SHA")) return "TLS_DH_RSA_WITH_SEED_CBC_SHA";
    if (!strcmp(key, "DHE-DSS-SEED-SHA")) return "TLS_DHE_DSS_WITH_SEED_CBC_SHA";
    if (!strcmp(key, "DHE-RSA-SEED-SHA")) return "TLS_DHE_RSA_WITH_SEED_CBC_SHA";
    if (!strcmp(key, "ADH-SEED-SHA")) return "TLS_DH_anon_WITH_SEED_CBC_SHA";
    if (!strcmp(key, "AES128-GCM-SHA256")) return "TLS_RSA_WITH_AES_128_GCM_SHA256";
    if (!strcmp(key, "AES256-GCM-SHA384")) return "TLS_RSA_WITH_AES_256_GCM_SHA384";
    if (!strcmp(key, "DHE-RSA-AES128-GCM-SHA256")) return "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256";
    if (!strcmp(key, "DHE-RSA-AES256-GCM-SHA384")) return "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384";
    if (!strcmp(key, "DH-RSA-AES128-GCM-SHA256")) return "TLS_DH_RSA_WITH_AES_128_GCM_SHA256";
    if (!strcmp(key, "DH-RSA-AES256-GCM-SHA384")) return "TLS_DH_RSA_WITH_AES_256_GCM_SHA384";
    if (!strcmp(key, "DHE-DSS-AES128-GCM-SHA256")) return "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256";
    if (!strcmp(key, "DHE-DSS-AES256-GCM-SHA384")) return "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384";
    if (!strcmp(key, "DH-DSS-AES128-GCM-SHA256")) return "TLS_DH_DSS_WITH_AES_128_GCM_SHA256";
    if (!strcmp(key, "DH-DSS-AES256-GCM-SHA384")) return "TLS_DH_DSS_WITH_AES_256_GCM_SHA384";
    if (!strcmp(key, "ADH-AES128-GCM-SHA256")) return "TLS_DH_anon_WITH_AES_128_GCM_SHA256";
    if (!strcmp(key, "ADH-AES256-GCM-SHA384")) return "TLS_DH_anon_WITH_AES_256_GCM_SHA384";
    if (!strcmp(key, "CAMELLIA128-SHA256")) return "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256";
    if (!strcmp(key, "DH-DSS-CAMELLIA128-SHA256")) return "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256";
    if (!strcmp(key, "DH-RSA-CAMELLIA128-SHA256")) return "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256";
    if (!strcmp(key, "DHE-DSS-CAMELLIA128-SHA256")) return "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256";
    if (!strcmp(key, "DHE-RSA-CAMELLIA128-SHA256")) return "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256";
    if (!strcmp(key, "ADH-CAMELLIA128-SHA256")) return "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256";
    if (!strcmp(key, "TLS_FALLBACK_SCSV")) return "TLS_EMPTY_RENEGOTIATION_INFO_SCSV";
    if (!strcmp(key, "TLS_AES_128_GCM_SHA256")) return "TLS_AES_128_GCM_SHA256";
    if (!strcmp(key, "TLS_AES_256_GCM_SHA384")) return "TLS_AES_256_GCM_SHA384";
    if (!strcmp(key, "TLS_CHACHA20_POLY1305_SHA256")) return "TLS_CHACHA20_POLY1305_SHA256";
    if (!strcmp(key, "TLS_AES_128_CCM_SHA256")) return "TLS_AES_128_CCM_SHA256";
    if (!strcmp(key, "TLS_AES_128_CCM_8_SHA256")) return "TLS_AES_128_CCM_8_SHA256";
    if (!strcmp(key, "ECDH-ECDSA-NULL-SHA")) return "TLS_ECDH_ECDSA_WITH_NULL_SHA";
    if (!strcmp(key, "ECDH-ECDSA-RC4-SHA")) return "TLS_ECDH_ECDSA_WITH_RC4_128_SHA";
    if (!strcmp(key, "ECDH-ECDSA-DES-CBC3-SHA")) return "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA";
    if (!strcmp(key, "ECDH-ECDSA-AES128-SHA")) return "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA";
    if (!strcmp(key, "ECDH-ECDSA-AES256-SHA")) return "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA";
    if (!strcmp(key, "ECDHE-ECDSA-NULL-SHA")) return "TLS_ECDHE_ECDSA_WITH_NULL_SHA";
    if (!strcmp(key, "ECDHE-ECDSA-RC4-SHA")) return "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA";
    if (!strcmp(key, "ECDHE-ECDSA-DES-CBC3-SHA")) return "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA";
    if (!strcmp(key, "ECDHE-ECDSA-AES128-SHA")) return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA";
    if (!strcmp(key, "ECDHE-ECDSA-AES256-SHA")) return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA";
    if (!strcmp(key, "ECDH-RSA-NULL-SHA")) return "TLS_ECDH_RSA_WITH_NULL_SHA";
    if (!strcmp(key, "ECDH-RSA-RC4-SHA")) return "TLS_ECDH_RSA_WITH_RC4_128_SHA";
    if (!strcmp(key, "ECDH-RSA-DES-CBC3-SHA")) return "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA";
    if (!strcmp(key, "ECDH-RSA-AES128-SHA")) return "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA";
    if (!strcmp(key, "ECDH-RSA-AES256-SHA")) return "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA";
    if (!strcmp(key, "ECDHE-RSA-NULL-SHA")) return "TLS_ECDHE_RSA_WITH_NULL_SHA";
    if (!strcmp(key, "ECDHE-RSA-RC4-SHA")) return "TLS_ECDHE_RSA_WITH_RC4_128_SHA";
    if (!strcmp(key, "ECDHE-RSA-DES-CBC3-SHA")) return "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA";
    if (!strcmp(key, "ECDHE-RSA-AES128-SHA")) return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA";
    if (!strcmp(key, "ECDHE-RSA-AES256-SHA")) return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA";
    if (!strcmp(key, "AECDH-NULL-SHA")) return "TLS_ECDH_anon_WITH_NULL_SHA";
    if (!strcmp(key, "AECDH-RC4-SHA")) return "TLS_ECDH_anon_WITH_RC4_128_SHA";
    if (!strcmp(key, "AECDH-DES-CBC3-SHA")) return "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA";
    if (!strcmp(key, "AECDH-AES128-SHA")) return "TLS_ECDH_anon_WITH_AES_128_CBC_SHA";
    if (!strcmp(key, "AECDH-AES256-SHA")) return "TLS_ECDH_anon_WITH_AES_256_CBC_SHA";
    if (!strcmp(key, "SRP-3DES-EDE-CBC-SHA")) return "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA";
    if (!strcmp(key, "SRP-RSA-3DES-EDE-CBC-SHA")) return "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA";
    if (!strcmp(key, "SRP-DSS-3DES-EDE-CBC-SHA")) return "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA";
    if (!strcmp(key, "SRP-AES-128-CBC-SHA")) return "TLS_SRP_SHA_WITH_AES_128_CBC_SHA";
    if (!strcmp(key, "SRP-RSA-AES-128-CBC-SHA")) return "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA";
    if (!strcmp(key, "SRP-DSS-AES-128-CBC-SHA")) return "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA";
    if (!strcmp(key, "SRP-AES-256-CBC-SHA")) return "TLS_SRP_SHA_WITH_AES_256_CBC_SHA";
    if (!strcmp(key, "SRP-RSA-AES-256-CBC-SHA")) return "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA";
    if (!strcmp(key, "SRP-DSS-AES-256-CBC-SHA")) return "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA";
    if (!strcmp(key, "ECDHE-ECDSA-AES128-SHA256")) return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256";
    if (!strcmp(key, "ECDHE-ECDSA-AES256-SHA384")) return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384";
    if (!strcmp(key, "ECDH-ECDSA-AES128-SHA256")) return "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256";
    if (!strcmp(key, "ECDH-ECDSA-AES256-SHA384")) return "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384";
    if (!strcmp(key, "ECDHE-RSA-AES128-SHA256")) return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256";
    if (!strcmp(key, "ECDHE-RSA-AES256-SHA384")) return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384";
    if (!strcmp(key, "ECDH-RSA-AES128-SHA256")) return "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256";
    if (!strcmp(key, "ECDH-RSA-AES256-SHA384")) return "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384";
    if (!strcmp(key, "ECDHE-ECDSA-AES128-GCM-SHA256")) return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
    if (!strcmp(key, "ECDHE-ECDSA-AES256-GCM-SHA384")) return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
    if (!strcmp(key, "ECDH-ECDSA-AES128-GCM-SHA256")) return "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256";
    if (!strcmp(key, "ECDH-ECDSA-AES256-GCM-SHA384")) return "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384";
    if (!strcmp(key, "ECDHE-RSA-AES128-GCM-SHA256")) return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
    if (!strcmp(key, "ECDHE-RSA-AES256-GCM-SHA384")) return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
    if (!strcmp(key, "ECDH-RSA-AES128-GCM-SHA256")) return "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256";
    if (!strcmp(key, "ECDH-RSA-AES256-GCM-SHA384")) return "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384";
    if (!strcmp(key, "ECDHE-PSK-RC4-SHA")) return "TLS_ECDHE_PSK_WITH_RC4_128_SHA";
    if (!strcmp(key, "ECDHE-PSK-3DES-EDE-CBC-SHA")) return "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA";
    if (!strcmp(key, "ECDHE-PSK-AES128-CBC-SHA")) return "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA";
    if (!strcmp(key, "ECDHE-PSK-AES256-CBC-SHA")) return "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA";
    if (!strcmp(key, "ECDHE-PSK-AES128-CBC-SHA256")) return "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256";
    if (!strcmp(key, "ECDHE-PSK-AES256-CBC-SHA384")) return "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384";
    if (!strcmp(key, "ECDHE-PSK-NULL-SHA")) return "TLS_ECDHE_PSK_WITH_NULL_SHA";
    if (!strcmp(key, "ECDHE-PSK-NULL-SHA256")) return "TLS_ECDHE_PSK_WITH_NULL_SHA256";
    if (!strcmp(key, "ECDHE-PSK-NULL-SHA384")) return "TLS_ECDHE_PSK_WITH_NULL_SHA384";
    if (!strcmp(key, "ECDHE-ECDSA-CAMELLIA128-SHA256")) return "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256";
    if (!strcmp(key, "ECDHE-ECDSA-CAMELLIA256-SHA384")) return "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384";
    if (!strcmp(key, "ECDH-ECDSA-CAMELLIA128-SHA256")) return "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256";
    if (!strcmp(key, "ECDH-ECDSA-CAMELLIA256-SHA384")) return "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384";
    if (!strcmp(key, "ECDHE-RSA-CAMELLIA128-SHA256")) return "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256";
    if (!strcmp(key, "ECDHE-RSA-CAMELLIA256-SHA384")) return "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384";
    if (!strcmp(key, "ECDH-RSA-CAMELLIA128-SHA256")) return "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256";
    if (!strcmp(key, "ECDH-RSA-CAMELLIA256-SHA384")) return "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384";
    if (!strcmp(key, "PSK-CAMELLIA128-SHA256")) return "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256";
    if (!strcmp(key, "PSK-CAMELLIA256-SHA384")) return "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384";
    if (!strcmp(key, "DHE-PSK-CAMELLIA128-SHA256")) return "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256";
    if (!strcmp(key, "DHE-PSK-CAMELLIA256-SHA384")) return "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384";
    if (!strcmp(key, "RSA-PSK-CAMELLIA128-SHA256")) return "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256";
    if (!strcmp(key, "RSA-PSK-CAMELLIA256-SHA384")) return "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384";
    if (!strcmp(key, "ECDHE-PSK-CAMELLIA128-SHA256")) return "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256";
    if (!strcmp(key, "ECDHE-PSK-CAMELLIA256-SHA384")) return "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384";
    if (!strcmp(key, "AES128-CCM")) return "TLS_RSA_WITH_AES_128_CCM";
    if (!strcmp(key, "AES256-CCM")) return "TLS_RSA_WITH_AES_256_CCM";
    if (!strcmp(key, "DHE-RSA-AES128-CCM")) return "TLS_DHE_RSA_WITH_AES_128_CCM";
    if (!strcmp(key, "DHE-RSA-AES256-CCM")) return "TLS_DHE_RSA_WITH_AES_256_CCM";
    if (!strcmp(key, "AES128-CCM8")) return "TLS_RSA_WITH_AES_128_CCM_8";
    if (!strcmp(key, "AES256-CCM8")) return "TLS_RSA_WITH_AES_256_CCM_8";
    if (!strcmp(key, "DHE-RSA-AES128-CCM8")) return "TLS_DHE_RSA_WITH_AES_128_CCM_8";
    if (!strcmp(key, "DHE-RSA-AES256-CCM8")) return "TLS_DHE_RSA_WITH_AES_256_CCM_8";
    if (!strcmp(key, "PSK-AES128-CCM")) return "TLS_PSK_WITH_AES_128_CCM";
    if (!strcmp(key, "PSK-AES256-CCM")) return "TLS_PSK_WITH_AES_256_CCM";
    if (!strcmp(key, "DHE-PSK-AES128-CCM")) return "TLS_DHE_PSK_WITH_AES_128_CCM";
    if (!strcmp(key, "DHE-PSK-AES256-CCM")) return "TLS_DHE_PSK_WITH_AES_256_CCM";
    if (!strcmp(key, "PSK-AES128-CCM8")) return "TLS_PSK_WITH_AES_128_CCM_8";
    if (!strcmp(key, "PSK-AES256-CCM8")) return "TLS_PSK_WITH_AES_256_CCM_8";
    if (!strcmp(key, "DHE-PSK-AES128-CCM8")) return "TLS_PSK_DHE_WITH_AES_128_CCM_8";
    if (!strcmp(key, "DHE-PSK-AES256-CCM8")) return "TLS_PSK_DHE_WITH_AES_256_CCM_8";
    if (!strcmp(key, "ECDHE-ECDSA-AES128-CCM")) return "TLS_ECDHE_ECDSA_WITH_AES_128_CCM";
    if (!strcmp(key, "ECDHE-ECDSA-AES256-CCM")) return "TLS_ECDHE_ECDSA_WITH_AES_256_CCM";
    if (!strcmp(key, "ECDHE-ECDSA-AES128-CCM8")) return "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8";
    if (!strcmp(key, "ECDHE-ECDSA-AES256-CCM8")) return "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8";
    if (!strcmp(key, "ECDHE-RSA-CHACHA20-POLY1305-OLD")) return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256_OLD";
    if (!strcmp(key, "ECDHE-ECDSA-CHACHA20-POLY1305-OLD")) return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256_OLD";
    if (!strcmp(key, "ECDHE-RSA-CHACHA20-POLY1305")) return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256";
    if (!strcmp(key, "ECDHE-ECDSA-CHACHA20-POLY1305")) return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256";
    if (!strcmp(key, "DHE-RSA-CHACHA20-POLY1305-OLD")) return "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256_OLD";
    if (!strcmp(key, "GOST-MD5")) return "TLS_GOSTR341094_RSA_WITH_28147_CNT_MD5";
    if (!strcmp(key, "GOST-GOST94")) return "TLS_RSA_WITH_28147_CNT_GOST94";
    if (!strcmp(key, "RC4-MD5")) return "SSL_CK_RC4_128_WITH_MD5";
    if (!strcmp(key, "EXP-RC4-MD5")) return "SSL_CK_RC4_128_EXPORT40_WITH_MD5";
    if (!strcmp(key, "RC2-CBC-MD5")) return "SSL_CK_RC2_128_CBC_WITH_MD5";
    if (!strcmp(key, "EXP-RC2-CBC-MD5")) return "SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5";
    if (!strcmp(key, "IDEA-CBC-MD5")) return "SSL_CK_IDEA_128_CBC_WITH_MD5";
    if (!strcmp(key, "DES-CBC-MD5")) return "SSL_CK_DES_64_CBC_WITH_MD5";
    if (!strcmp(key, "DES-CBC-SHA")) return "SSL_CK_DES_64_CBC_WITH_SHA";
    if (!strcmp(key, "DES-CBC3-MD5")) return "SSL_CK_DES_192_EDE3_CBC_WITH_MD5";
    if (!strcmp(key, "DES-CBC3-SHA")) return "SSL_CK_DES_192_EDE3_CBC_WITH_SHA";
    if (!strcmp(key, "RC4-64-MD5")) return "SSL_CK_RC4_64_WITH_MD5";
    if (!strcmp(key, "DES-CFB-M1")) return "SSL_CK_DES_64_CFB64_WITH_MD5_1";
    if (!strcmp(key, "NULL")) return "SSL_CK_NULL";
    if (!strcmp(key, "DHE-RSA-CHACHA20-POLY1305")) return "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256";
    if (!strcmp(key, "ECDHE-BIKE-RSA-AES256-GCM-SHA384")) return "TLS_ECDHE_BIKE_RSA_WITH_AES_256_GCM_SHA384";
    if (!strcmp(key, "ECDHE-SIKE-RSA-AES256-GCM-SHA384")) return "TLS_ECDHE_SIKE_RSA_WITH_AES_256_GCM_SHA384";
    if (!strcmp(key, "TLS_NULL_WITH_NULL_NULL")) return "TLS_NULL_WITH_NULL_NULL";
}

int main(int argc, char **argv)
{
    FILE *fp;
    fp = fopen("../../../test2.java", "w");
    int num = 0;
    while (security_policy_selection[num].version != NULL) {
        num ++;
    }
    int ifPrint[num];
    memset(ifPrint, 0, num*sizeof(int));
    for ( int index  = 0; index < num; index++)
    {
        if (ifPrint[index] == 1) continue;
        struct s2n_security_policy *thisPolicy = security_policy_selection[index].security_policy;
        fprintf(fp, "case \"TLS_POLICY_%s\":\n", security_policy_selection[index].version);
        ifPrint[index] = 1;
        for (int index2 = index+1; index2 < num; index2++) {
            if (security_policy_selection[index].security_policy == security_policy_selection[index2].security_policy) {
                fprintf(fp, "case \"TLS_POLICY_%s\":\n", security_policy_selection[index2].version);
                ifPrint[index2] = 1;
            }
        }
        switch (thisPolicy->minimum_protocol_version)
        {
        case 20:
            fprintf(fp, "    return new TlsPolicy(ProtocolVersion.SSLv2, asList(\n");
            break;
        case 30:
            fprintf(fp, "    return new TlsPolicy(ProtocolVersion.SSLv3, asList(\n");
            break;
        case 31:
            fprintf(fp, "    return new TlsPolicy(ProtocolVersion.TLSv10, asList(\n");
            break;
        case 32:
            fprintf(fp, "    return new TlsPolicy(ProtocolVersion.TLSv11, asList(\n");
            break;
        case 33:
            fprintf(fp, "    return new TlsPolicy(ProtocolVersion.TLSv12, asList(\n");
            break;
        }
        int lineNum = thisPolicy->cipher_preferences->count;
        for (int i = 0; i < lineNum-1; i++) {
            fprintf(fp, "        \"%s\",\n", mapToIANA(thisPolicy->cipher_preferences->suites[i]->name));
        }
        fprintf(fp, "        \"%s\"\n", mapToIANA(thisPolicy->cipher_preferences->suites[lineNum-1]->name));
        fprintf(fp, "    ));\n");
    }
    fclose(fp);

// origin codes
    struct s2n_connection *conn;
    uint8_t mac_key[] = "sample mac key";
    uint8_t des3_key[] = "12345678901234567890123";
    struct s2n_blob des3 = {.data = des3_key,.size = sizeof(des3_key) };
    uint8_t random_data[S2N_DEFAULT_FRAGMENT_LENGTH + 1];
    struct s2n_blob r = {.data = random_data, .size = sizeof(random_data)};

    BEGIN_TEST();

    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
    EXPECT_OK(s2n_get_urandom_data(&r));

    /* Peer and we are in sync */
    conn->server = &conn->secure;
    conn->client = &conn->secure;

    /* test the 3des cipher with a SHA1 hash */
    conn->secure.cipher_suite->record_alg = &s2n_record_alg_3des_sha;
    EXPECT_SUCCESS(conn->secure.cipher_suite->record_alg->cipher->init(&conn->secure.server_key));
    EXPECT_SUCCESS(conn->secure.cipher_suite->record_alg->cipher->init(&conn->secure.client_key));
    EXPECT_SUCCESS(conn->secure.cipher_suite->record_alg->cipher->set_encryption_key(&conn->secure.server_key, &des3));
    EXPECT_SUCCESS(conn->secure.cipher_suite->record_alg->cipher->set_decryption_key(&conn->secure.client_key, &des3));
    EXPECT_SUCCESS(s2n_hmac_init(&conn->secure.client_record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));
    EXPECT_SUCCESS(s2n_hmac_init(&conn->secure.server_record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));
    conn->actual_protocol_version = S2N_TLS11;

    int max_aligned_fragment = S2N_DEFAULT_FRAGMENT_LENGTH - (S2N_DEFAULT_FRAGMENT_LENGTH % 8);
    for (int i = 0; i <= max_aligned_fragment + 1; i++) {
        struct s2n_blob in = {.data = random_data,.size = i };
        int bytes_written;

        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->out));
        EXPECT_SUCCESS(bytes_written = s2n_record_write(conn, TLS_APPLICATION_DATA, &in));

        if (i < max_aligned_fragment - 20 - 8 - 1) {
            EXPECT_EQUAL(bytes_written, i);
        } else {
            EXPECT_EQUAL(bytes_written, max_aligned_fragment - 20 - 8 - 1);
        }

        uint16_t predicted_length = bytes_written + 1 + 20 + 8;
        if (predicted_length % 8) {
            predicted_length += (8 - (predicted_length % 8));
        }
        EXPECT_EQUAL(conn->out.blob.data[0], TLS_APPLICATION_DATA);
        EXPECT_EQUAL(conn->out.blob.data[1], 3);
        EXPECT_EQUAL(conn->out.blob.data[2], 2);
        EXPECT_EQUAL(conn->out.blob.data[3], (predicted_length >> 8) & 0xff);
        EXPECT_EQUAL(conn->out.blob.data[4], predicted_length & 0xff);

        /* The data should be encrypted */
        if (bytes_written > 10) {
            EXPECT_NOT_EQUAL(memcmp(conn->out.blob.data + 5, random_data, bytes_written), 0);
        }

        /* Copy the encrypted out data to the in data */
        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));
        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in));
        EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->header_in, 5));
        EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->in, s2n_stuffer_data_available(&conn->out)));

        /* Let's decrypt it */
        uint8_t content_type;
        uint16_t fragment_length;
        EXPECT_SUCCESS(s2n_record_header_parse(conn, &content_type, &fragment_length));
        EXPECT_SUCCESS(s2n_record_parse(conn));
        EXPECT_EQUAL(content_type, TLS_APPLICATION_DATA);
        EXPECT_EQUAL(fragment_length, predicted_length);

        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in));
        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));
    }

    EXPECT_SUCCESS(conn->secure.cipher_suite->record_alg->cipher->destroy_key(&conn->secure.server_key));
    EXPECT_SUCCESS(conn->secure.cipher_suite->record_alg->cipher->destroy_key(&conn->secure.client_key));
    EXPECT_SUCCESS(s2n_connection_free(conn));

    END_TEST();
}
