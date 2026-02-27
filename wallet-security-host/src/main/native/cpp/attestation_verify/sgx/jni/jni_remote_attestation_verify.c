// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

#include "jni_remote_attestation_verify.h"

#define QUOTE_VERIFICATION_STATUS_SUCCESS                 0
#define QUOTE_VERIFICATION_STATUS_GET_DATA_SIZE_FAILED    1
#define QUOTE_VERIFICATION_STATUS_QUOTE_VERIFY_FAILED     2
#define QUOTE_VERIFICATION_STATUS_MEMORY_MALLOC_FAILED    3
#define QUOTE_VERIFICATION_VERSION_CHECK_SUCCESS          0
#define QUOTE_VERIFICATION_VERSION_CHECK_FAILED          -1
#define QUOTE_VERIFICATION_SUCCESS                        0
#define QUOTE_VERIFICATION_OUT_OF_DATA                    1
#define QUOTE_VERIFICATION_NO_TERMINAL                    2
#define QUOTE_VERIFICATION_FAILED_WITH_TERMINAL           3

static JNINativeMethod sgx_remote_attestation_verify_methods[] = {
    {"nativeVerifyAttestationReport", SGX_ENCLAVE_REMOTE_ATTESTATION_VERIFY_SIGNATURE, (void *)&JavaEnclave_SGX_ENCLAVE_REMOTE_ATTESTATION_VERIFY},
};

void set_int_field_value(JNIEnv *env, jclass class_mirror, jobject obj, const char *field_name, jint value) {
    jfieldID field_id = (*env)->GetFieldID(env, class_mirror, field_name, "I");
    (*env)->SetIntField(env, obj, field_id, value);
}

verify_result_wrapper ecdsa_quote_verification_qvl(const uint8_t* quote, uint32_t length) {
    verify_result_wrapper result;
    result.status = QUOTE_VERIFICATION_STATUS_SUCCESS;
    result.version_check = QUOTE_VERIFICATION_VERSION_CHECK_SUCCESS;
    result.verify_flag = QUOTE_VERIFICATION_SUCCESS;

    quote3_error_t dcap_ret = SGX_QL_ERROR_UNEXPECTED;
    uint32_t supplemental_data_size = 0;
    uint8_t *p_supplemental_data = NULL;
    time_t current_time = 0;
    uint32_t collateral_expiration_status = 1;
    sgx_ql_qv_result_t quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;

    // Step one, get supplemental_data_size.
    dcap_ret = sgx_qv_get_quote_supplemental_data_size(&supplemental_data_size);
    if (dcap_ret != SGX_QL_SUCCESS) {
        // printf("Teaclave Java TEE SDK Remote Attestation Error: sgx_qv_get_quote_supplemental_data_size failed: 0x%04x\n", dcap_ret);
        result.status = QUOTE_VERIFICATION_STATUS_GET_DATA_SIZE_FAILED;
        return result;
    }
//    if (supplemental_data_size != sizeof(sgx_ql_qv_supplemental_t)) {
//        // printf("Teaclave Java TEE SDK Remote Attestation Warning: sgx_qv_get_quote_supplemental_data_size returned size is not same with header definition in SGX SDK, please make sure you are using same version of SGX SDK and DCAP QVL.\n");
//        result.version_check = QUOTE_VERIFICATION_VERSION_CHECK_FAILED;
//        return result;
//    }

    p_supplemental_data = (uint8_t*)malloc(supplemental_data_size);
    if (p_supplemental_data != NULL) {
        memset(p_supplemental_data, 0, sizeof(supplemental_data_size));
    } else {
        result.status = QUOTE_VERIFICATION_STATUS_MEMORY_MALLOC_FAILED;
        return result;
    }

    current_time = time(NULL);
    dcap_ret = sgx_qv_verify_quote(
        quote, length, NULL,
        current_time, &collateral_expiration_status,
        &quote_verification_result, NULL,
        supplemental_data_size, p_supplemental_data);

    free(p_supplemental_data);

    if (dcap_ret != SGX_QL_SUCCESS) {
        result.status = QUOTE_VERIFICATION_STATUS_QUOTE_VERIFY_FAILED;
        return result;
    }

//    printf("==== SGX DCAP Verify Quote Result ====\n");
//    printf("dcap_ret = 0x%08x (%d)\n",(unsigned int)dcap_ret,(int)dcap_ret);
//    printf("quote_verification_result = 0x%08x (%d)\n",(unsigned int)quote_verification_result,(int)quote_verification_result);
//    printf("collateral_expiration_status = %u\n",collateral_expiration_status);
//    printf("======================================\n");

    /*
      quote_verification_result (sgx_ql_qv_result_t)：Quote 是否真实可信

      0x0000: The Quote verification passed and is at the latest TCB level.

      0xA001: The Quote verification passed and the platform is patched to the latest
              TCB level but additional configuration of the SGX platform may be needed.

      0xA002: The Quote is good but TCB level of the platform is out of date.
              The platform needs patching to be at the latest TCB level.

      0xA003: The Quote is good but the TCB level of the platform is out of date and
              additional configuration of the SGX platform at its current patching
              level may be needed.

      0xA004: INVALID_SIGNATURE.
              The Quote signature is invalid. (Terminal result – must reject)

      0xA005: REVOKED.
              The platform has been revoked. (Terminal result – must reject)

      0xA006: UNSPECIFIED.
              The verification result is unspecified or an unexpected error occurred.
              (Terminal result – must reject)

      0xA007: The TCB level of the platform is up to date,
              but SGX SW Hardening is needed.

      0xA008: The TCB level of the platform is up to date,
              but additional configuration of the platform at its current patching
              level may be needed. Moreover, SGX SW Hardening is also needed.
     */

     /*
        collateral_expiration_status：用来验证它的证书链是否还在有效期内
            0 → collateral 没过期
            1 → collateral 已过期
     */

    switch (quote_verification_result) {
        case SGX_QL_QV_RESULT_OK://0x0000
            if (collateral_expiration_status == 0) {
                // Verification completed successfully.
                result.verify_flag = QUOTE_VERIFICATION_SUCCESS;
            } else {
                // Verification completed, but collateral is out of date based on 'expiration_check_date' you provided.
                result.verify_flag = QUOTE_VERIFICATION_OUT_OF_DATA;
            }
            break;
        case SGX_QL_QV_RESULT_CONFIG_NEEDED://0xA001
        case SGX_QL_QV_RESULT_OUT_OF_DATE://0xA002
        case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED://0xA003
        case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED://0xA007
        case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED://0xA008
            // Verification completed with Non-terminal result, you could view value of quote_verification_result for more info.
            //可认为符合安全要求：由于阿里云 ECS 的服务器默认开启了超线程，因此在使用sgx_tvl_verify_qve_report_and_identity()、tee_verify_quote()和sgx_qv_verify_quote()等接口验证时，quote_verification_result可能会出现非0值，但其中[0x0000,0xA001,0xA002,0xA003,0xA007,0xA008]值均可认为符合安全要求。
            result.verify_flag = QUOTE_VERIFICATION_SUCCESS;
            break;
        case SGX_QL_QV_RESULT_INVALID_SIGNATURE: //0xA004
        case SGX_QL_QV_RESULT_REVOKED://0xA005
        case SGX_QL_QV_RESULT_UNSPECIFIED://0xA006
            //must reject：远程证明验证失败，必须拒绝
        default:
            // Verification completed with Terminal result, you could view value of quote_verification_result for more info.
            result.verify_flag = QUOTE_VERIFICATION_FAILED_WITH_TERMINAL;
            break;
    }
    return result;
}

JNIEXPORT void JNICALL Java_org_apache_teaclave_javasdk_host_SGXRemoteAttestationVerify_registerNatives(JNIEnv *env, jclass cls) {
    (*env)->RegisterNatives(env, cls, sgx_remote_attestation_verify_methods, sizeof(sgx_remote_attestation_verify_methods)/sizeof(sgx_remote_attestation_verify_methods[0]));
}

JNIEXPORT jint JNICALL
JavaEnclave_SGX_ENCLAVE_REMOTE_ATTESTATION_VERIFY(JNIEnv *env, jclass mirror, jbyteArray quote, jobject jResult) {
    jbyte *quote_copy = (*env)->GetByteArrayElements(env, quote, NULL);
    int quote_length = (*env)->GetArrayLength(env, quote);
    verify_result_wrapper result = ecdsa_quote_verification_qvl(quote_copy, quote_length);
    (*env)->ReleaseByteArrayElements(env, quote, quote_copy, 0);

    jclass j_result_class = (*env)->GetObjectClass(env, jResult);
    set_int_field_value(env, j_result_class, jResult, "status", (jint)result.status);
    set_int_field_value(env, j_result_class, jResult, "versionCheck", (jint)result.version_check);
    set_int_field_value(env, j_result_class, jResult, "verifyFlag", (jint)result.verify_flag);

    return 0;
}