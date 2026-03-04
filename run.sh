#!/bin/bash

# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

# Setting PCCS_URL for SGX Remote Attestation.
# PCCS_URL should be changed according to ECS location.
# PCCS_URL=https://sgx-dcap-server.cn-hongkong.aliyuncs.com/sgx/certification/v3/
echo "PCCS_URL=https://sgx-dcap-server-vpc.ap-southeast-5.aliyuncs.com/sgx/certification/v4/" > /etc/sgx_default_qcnl.conf
echo "USE_SECURE_CERT=TRUE" >> /etc/sgx_default_qcnl.conf

mvn -Pnative clean package

OCCLUM_RELEASE_ENCLAVE=true java -Dspring.profiles.active=test \
-cp wallet-security-host/target/wallet-security-host-0.1.0-jar-with-dependencies.jar:wallet-security-enclave/target/wallet-security-enclave-0.1.0-jar-with-dependencies.jar \
com.ida.wallet.security.host.WalletSecuritySgxHostApplication

#OCCLUM_RELEASE_ENCLAVE=true nohup stdbuf -oL -eL java \
# -cp wallet-security-host/target/wallet-security-host-0.1.0-jar-with-dependencies.jar:wallet-security-enclave/target/wallet-security-enclave-0.1.0-jar-with-dependencies.jar \
# com.ida.wallet.security.host.WalletSecuritySgxHostApplication \
# 2>&1 | tee /work/test/wallet-security.log &