"""
rfcControlPlane.py — Part 1: Post-Handshake Control-Plane Engine for IKEv2 / IPsec.

Evaluates unified IKE handshake session state upon IKE_AUTH completion or steady-state
lifecycle events against RFC requirements across:
- Category 1: IKEv2 Protocol Compliance (RFC 7296, RFC 9395)
- Category 2: IKEv2 Cryptographic Transforms (RFC 8247)
- Category 3: Encryption Rules (RFC 8247 §2.1, RFC 8221 §2.1)
- Category 4: PRF Rules (RFC 8247 §2.2)
- Category 5: Integrity Rules (RFC 8247 §2.3, RFC 8221 §2.2)
- Category 6: Diffie-Hellman / Key Exchange (RFC 8247 §2.4, RFC 9370)
- Category 7: Identity & Authentication (RFC 7296 §3.8, RFC 7427)
- Category 9: Security Association Lifecycle (RFC 7296 §1.3, §1.4)
- Category 11: NAT Traversal (RFC 3948, RFC 7296 §2.23)
- Static Child SA Proposals (RFC 8221)

Strictly decouples RFC Compliance, Cryptographic Posture, PQC Status, and Hybrid Classification.
"""

from __future__ import annotations

from typing import Any

try:
    from .rfcEngineModels import (
        ApplicableContext,
        HybridClassification,
        PqcClassification,
        RequirementLevel,
        RuleCategory,
        RuleEvaluationResult,
        RuleStatus,
        SecurityPosture,
        Severity,
        SpecSourceType,
    )
    from .rfcRegistries import (
        AEAD_ENCR_IDS,
        CERT_KEY_TYPE_OIDS,
        CERT_SIG_ALGO_OIDS,
        ESP_ENCR_REGISTRY,
        ESP_INTEG_REGISTRY,
        IKEV2_AUTH_METHODS_REGISTRY,
        IKEV2_DH_REGISTRY,
        IKEV2_ENCR_REGISTRY,
        IKEV2_INTEG_REGISTRY,
        IKEV2_PRF_REGISTRY,
        PQC_SIG_ALGO_REGISTRY,
    )
except ImportError:
    from rfcEngineModels import (
        ApplicableContext,
        HybridClassification,
        PqcClassification,
        RequirementLevel,
        RuleCategory,
        RuleEvaluationResult,
        RuleStatus,
        SecurityPosture,
        Severity,
        SpecSourceType,
    )
    from rfcRegistries import (
        AEAD_ENCR_IDS,
        CERT_KEY_TYPE_OIDS,
        CERT_SIG_ALGO_OIDS,
        ESP_ENCR_REGISTRY,
        ESP_INTEG_REGISTRY,
        IKEV2_AUTH_METHODS_REGISTRY,
        IKEV2_DH_REGISTRY,
        IKEV2_ENCR_REGISTRY,
        IKEV2_INTEG_REGISTRY,
        IKEV2_PRF_REGISTRY,
        PQC_SIG_ALGO_REGISTRY,
    )

try:
    from cert_engine.certHealthEngine import evaluate_auth_health
except ImportError:
    from certHealthEngine import evaluate_auth_health


class RfcControlPlaneEngine:
    """Evaluates control-plane IKE handshake session state against RFC specifications."""

    def __init__(self) -> None:
        pass

    def evaluate_session(self, session: dict[str, Any]) -> list[RuleEvaluationResult]:
        """Execute all Part 1 control-plane rules against the session dictionary."""
        results: list[RuleEvaluationResult] = []

        # Category 1: IKEv2 Protocol Compliance
        results.extend(self._eval_category_1_protocol(session))

        # Extract negotiated IKE_SA_INIT transforms
        init_transforms = self._get_init_transforms(session)

        # Category 2: IKEv2 Cryptographic Transforms
        results.extend(self._eval_category_2_transforms(init_transforms))

        # Category 3: Encryption Rules
        results.extend(self._eval_category_3_encryption(init_transforms, session))

        # Category 4: PRF Rules
        results.extend(self._eval_category_4_prf(init_transforms))

        # Category 5: Integrity Rules
        results.extend(self._eval_category_5_integrity(init_transforms))

        # Category 6: Diffie-Hellman / Key Exchange
        results.extend(self._eval_category_6_dh(init_transforms, session))

        # Category 7: Identity & Authentication
        results.extend(self._eval_category_7_auth(session))

        # Category 9: Security Association Lifecycle
        results.extend(self._eval_category_9_lifecycle(session))

        # Category 11: NAT Traversal
        results.extend(self._eval_category_11_natt(session))

        # Static Child SA Evaluation (ESP Proposal in IKE_AUTH)
        results.extend(self._eval_static_child_sa(session))

        return results

    # Category 1: IKEv2 Protocol Compliance (RFC 7296, RFC 9395)

    def _eval_category_1_protocol(self, session: dict[str, Any]) -> list[RuleEvaluationResult]:
        results = []
        common = session.get("common", {})

        # 1. Version validation (RFC 7296 §3.1, RFC 9395)
        # Note: can come from common.ike_version or exchange_type/version fields
        ike_ver = common.get("ike_version")
        if ike_ver is None:
            # Check if exchange_type or isakmp indicates IKEv1 or IKEv2
            if "IKE_SA_INIT" in session or session.get("exchange_type") in (34, 35, 36, 37, 38, 43):
                ike_ver = 2
            elif session.get("exchange_type") in (1, 2, 4, 5):  # IKEv1 Phase 1/2 exchanges
                ike_ver = 1

        if ike_ver == 2:
            results.append(RuleEvaluationResult(
                rule_id="IKE-PROTO-VER-001",
                rfc="RFC 7296",
                section="§3.1",
                category=RuleCategory.CAT1_IKEV2_PROTOCOL.value,
                condition="Major version validation",
                requirement_level=RequirementLevel.MUST.value,
                applicable_context=ApplicableContext.HANDSHAKE.value,
                status=RuleStatus.PASS,
                severity=Severity.INFORMATIONAL,
                reason="IKE major version is 2 as required by RFC 7296.",
                observed_value=f"Major Version {ike_ver}",
                expected_requirement="Major version MUST be 2",
            ))
        elif ike_ver == 1:
            results.append(RuleEvaluationResult(
                rule_id="IKE-PROTO-VER-001",
                rfc="RFC 9395",
                section="§1",
                category=RuleCategory.CAT1_IKEV2_PROTOCOL.value,
                condition="Major version validation",
                requirement_level=RequirementLevel.MUST_NOT.value,
                applicable_context=ApplicableContext.HANDSHAKE.value,
                status=RuleStatus.FAIL,
                severity=Severity.CRITICAL,
                reason="IKEv1 is deprecated under RFC 9395 and MUST NOT be used.",
                observed_value="Major Version 1",
                expected_requirement="Major version MUST be 2 (IKEv1 is deprecated)",
            ))
        else:
            results.append(RuleEvaluationResult(
                rule_id="IKE-PROTO-VER-001",
                rfc="RFC 7296",
                section="§3.1",
                category=RuleCategory.CAT1_IKEV2_PROTOCOL.value,
                condition="Major version validation",
                requirement_level=RequirementLevel.MUST.value,
                applicable_context=ApplicableContext.HANDSHAKE.value,
                status=RuleStatus.NOT_VERIFIABLE,
                severity=Severity.LOW,
                reason="IKE major version was not supplied in the input data.",
                observed_value=None,
                expected_requirement="Major version MUST be 2",
            ))

        # 2. State machine ordering: IKE_SA_INIT (MsgID 0) -> [IKE_INTERMEDIATE] -> IKE_AUTH (RFC 7296 §1.2, §2.1)
        # Check message IDs if provided
        msg_id = common.get("message_id")
        exch_type = session.get("exchange_type") or common.get("exchange_type")
        if msg_id is not None:
            if exch_type in (34, "IKE_SA_INIT") and msg_id != 0:
                results.append(RuleEvaluationResult(
                    rule_id="IKE-PROTO-ORDER-001",
                    rfc="RFC 7296",
                    section="§2.1",
                    category=RuleCategory.CAT1_IKEV2_PROTOCOL.value,
                    condition="IKE_SA_INIT Message ID check",
                    requirement_level=RequirementLevel.MUST.value,
                    applicable_context=ApplicableContext.HANDSHAKE.value,
                    status=RuleStatus.FAIL,
                    severity=Severity.HIGH,
                    reason=f"IKE_SA_INIT must have Message ID 0; observed {msg_id}.",
                    observed_value=msg_id,
                    expected_requirement="Message ID MUST be 0 for IKE_SA_INIT",
                ))
            else:
                results.append(RuleEvaluationResult(
                    rule_id="IKE-PROTO-ORDER-001",
                    rfc="RFC 7296",
                    section="§2.1",
                    category=RuleCategory.CAT1_IKEV2_PROTOCOL.value,
                    condition="State machine sequence validation",
                    requirement_level=RequirementLevel.MUST.value,
                    applicable_context=ApplicableContext.HANDSHAKE.value,
                    status=RuleStatus.PASS,
                    severity=Severity.INFORMATIONAL,
                    reason="Message ID conforms to sequential ordering.",
                    observed_value=msg_id,
                    expected_requirement="Sequential Message ID progression",
                ))
        else:
            # If session has both IKE_SA_INIT and IKE_AUTH, verify both are present
            has_init = "IKE_SA_INIT" in session
            has_auth = "IKE_AUTH" in session
            if has_init and has_auth:
                results.append(RuleEvaluationResult(
                    rule_id="IKE-PROTO-ORDER-001",
                    rfc="RFC 7296",
                    section="§1.2",
                    category=RuleCategory.CAT1_IKEV2_PROTOCOL.value,
                    condition="State machine sequence validation",
                    requirement_level=RequirementLevel.MUST.value,
                    applicable_context=ApplicableContext.HANDSHAKE.value,
                    status=RuleStatus.PASS,
                    severity=Severity.INFORMATIONAL,
                    reason="Both IKE_SA_INIT and IKE_AUTH exchange contexts present in valid state machine order.",
                    observed_value="IKE_SA_INIT -> IKE_AUTH",
                    expected_requirement="IKE_SA_INIT -> IKE_AUTH state progression",
                ))
            elif has_init and not has_auth:
                results.append(RuleEvaluationResult(
                    rule_id="IKE-PROTO-ORDER-001",
                    rfc="RFC 7296",
                    section="§1.2",
                    category=RuleCategory.CAT1_IKEV2_PROTOCOL.value,
                    condition="State machine sequence validation",
                    requirement_level=RequirementLevel.MUST.value,
                    applicable_context=ApplicableContext.HANDSHAKE.value,
                    status=RuleStatus.PASS,
                    severity=Severity.INFORMATIONAL,
                    reason="Initial IKE_SA_INIT state observed.",
                    observed_value="IKE_SA_INIT",
                    expected_requirement="Valid exchange progression",
                ))
            else:
                results.append(RuleEvaluationResult(
                    rule_id="IKE-PROTO-ORDER-001",
                    rfc="RFC 7296",
                    section="§1.2",
                    category=RuleCategory.CAT1_IKEV2_PROTOCOL.value,
                    condition="State machine sequence validation",
                    requirement_level=RequirementLevel.MUST.value,
                    applicable_context=ApplicableContext.HANDSHAKE.value,
                    status=RuleStatus.NOT_VERIFIABLE,
                    severity=Severity.LOW,
                    reason="Handshake exchange records were not supplied.",
                    observed_value=None,
                    expected_requirement="IKE_SA_INIT -> IKE_AUTH sequence",
                ))

        # 3. Payload Requirements for IKE_SA_INIT (RFC 7296 §1.2, §3.3, §3.4)
        if "IKE_SA_INIT" in session:
            init_data = session["IKE_SA_INIT"]
            proposals = init_data.get("proposals", [])
            ke = init_data.get("key_exchange")
            has_ke_in_tx = any(
                p.get("transforms", {}).get("dh_group") for p in proposals
            )

            if len(proposals) > 0 and (ke is not None or has_ke_in_tx):
                results.append(RuleEvaluationResult(
                    rule_id="IKE-PROTO-INIT-PL-001",
                    rfc="RFC 7296",
                    section="§1.2",
                    category=RuleCategory.CAT1_IKEV2_PROTOCOL.value,
                    condition="IKE_SA_INIT mandatory payload presence (SA, KE)",
                    requirement_level=RequirementLevel.MUST.value,
                    applicable_context=ApplicableContext.HANDSHAKE.value,
                    status=RuleStatus.PASS,
                    severity=Severity.INFORMATIONAL,
                    reason="IKE_SA_INIT contains mandatory SA and KE payloads.",
                    observed_value=f"{len(proposals)} proposal(s), KE present",
                    expected_requirement="SA and KE payloads MUST be present",
                ))
            else:
                results.append(RuleEvaluationResult(
                    rule_id="IKE-PROTO-INIT-PL-001",
                    rfc="RFC 7296",
                    section="§1.2",
                    category=RuleCategory.CAT1_IKEV2_PROTOCOL.value,
                    condition="IKE_SA_INIT mandatory payload presence (SA, KE)",
                    requirement_level=RequirementLevel.MUST.value,
                    applicable_context=ApplicableContext.HANDSHAKE.value,
                    status=RuleStatus.FAIL,
                    severity=Severity.CRITICAL,
                    reason="IKE_SA_INIT is missing mandatory SA proposals or KE payload.",
                    observed_value=f"{len(proposals)} proposal(s), KE={'present' if ke or has_ke_in_tx else 'missing'}",
                    expected_requirement="SA and KE payloads MUST be present",
                ))

        # 4. Critical Bit Handling (RFC 7296 §3.2)
        unsupported_crit = session.get("unsupported_critical_payload", False)
        if unsupported_crit:
            results.append(RuleEvaluationResult(
                rule_id="IKE-PROTO-CRIT-001",
                rfc="RFC 7296",
                section="§3.2",
                category=RuleCategory.CAT1_IKEV2_PROTOCOL.value,
                condition="Critical-bit handling on unsupported payload",
                requirement_level=RequirementLevel.MUST.value,
                applicable_context=ApplicableContext.HANDSHAKE.value,
                status=RuleStatus.FAIL,
                severity=Severity.CRITICAL,
                reason="Unknown payload with Critical bit set was encountered without proper rejection/handling.",
                observed_value="Unsupported Critical Payload = True",
                expected_requirement="MUST reject with UNSUPPORTED_CRITICAL_PAYLOAD",
            ))

        return results

    # Category 2: IKEv2 Cryptographic Transforms (RFC 8247)

    def _eval_category_2_transforms(self, tx: dict[str, list[dict]]) -> list[RuleEvaluationResult]:
        results = []

        # Audit ENCR Transform requirement level
        encr_entry = self._first(tx.get("encryption", []))
        if encr_entry is not None:
            encr_id = encr_entry.get("id")
            reg = IKEV2_ENCR_REGISTRY.get(encr_id)
            if reg:
                req = reg["req_level"]
                status = (
                    RuleStatus.FAIL if req == RequirementLevel.MUST_NOT
                    else (RuleStatus.WARNING if req == RequirementLevel.SHOULD_NOT else RuleStatus.PASS)
                )
                severity = (
                    Severity.CRITICAL if req == RequirementLevel.MUST_NOT
                    else (Severity.MEDIUM if req == RequirementLevel.SHOULD_NOT else Severity.INFORMATIONAL)
                )
                results.append(RuleEvaluationResult(
                    rule_id="IKE-TRANS-ENCR-001",
                    rfc=reg["rfc"],
                    section=reg["section"],
                    category=RuleCategory.CAT2_CRYPTO_TRANSFORMS.value,
                    condition=f"ENCR transform requirement status ({reg['name']})",
                    requirement_level=req.value,
                    applicable_context=ApplicableContext.HANDSHAKE.value,
                    status=status,
                    severity=severity,
                    reason=reg["reason"],
                    observed_value=f"{reg['name']} (ID {encr_id})",
                    expected_requirement=f"Requirement level: {req.value}",
                    spec_source=reg["spec_source"].value,
                ))
            else:
                results.append(RuleEvaluationResult(
                    rule_id="IKE-TRANS-ENCR-001",
                    rfc="RFC 8247",
                    section="§2.1",
                    category=RuleCategory.CAT2_CRYPTO_TRANSFORMS.value,
                    condition="ENCR transform recognition",
                    requirement_level=RequirementLevel.MUST.value,
                    applicable_context=ApplicableContext.HANDSHAKE.value,
                    status=RuleStatus.WARNING,
                    severity=Severity.HIGH,
                    reason=f"Encryption algorithm ID {encr_id} is not standard in RFC 8247 registry.",
                    observed_value=f"ID {encr_id}",
                    expected_requirement="Recognized RFC 8247 transform ID",
                    spec_source=SpecSourceType.IANA_REGISTRY.value,
                ))

        # Audit PRF Transform requirement level
        prf_entry = self._first(tx.get("prf", []))
        if prf_entry is not None:
            prf_id = prf_entry.get("id")
            reg = IKEV2_PRF_REGISTRY.get(prf_id)
            if reg:
                req = reg["req_level"]
                status = (
                    RuleStatus.FAIL if req == RequirementLevel.MUST_NOT
                    else (RuleStatus.WARNING if req == RequirementLevel.SHOULD_NOT else RuleStatus.PASS)
                )
                severity = (
                    Severity.CRITICAL if req == RequirementLevel.MUST_NOT
                    else (Severity.MEDIUM if req == RequirementLevel.SHOULD_NOT else Severity.INFORMATIONAL)
                )
                results.append(RuleEvaluationResult(
                    rule_id="IKE-TRANS-PRF-001",
                    rfc=reg["rfc"],
                    section=reg["section"],
                    category=RuleCategory.CAT2_CRYPTO_TRANSFORMS.value,
                    condition=f"PRF transform requirement status ({reg['name']})",
                    requirement_level=req.value,
                    applicable_context=ApplicableContext.HANDSHAKE.value,
                    status=status,
                    severity=severity,
                    reason=reg["reason"],
                    observed_value=f"{reg['name']} (ID {prf_id})",
                    expected_requirement=f"Requirement level: {req.value}",
                    spec_source=reg["spec_source"].value,
                ))

        # Audit INTEG Transform requirement level
        integ_entry = self._first(tx.get("integrity", []))
        if integ_entry is not None:
            integ_id = integ_entry.get("id")
            reg = IKEV2_INTEG_REGISTRY.get(integ_id)
            if reg:
                req = reg["req_level"]
                # Handled further in Category 5 with AEAD context
                if integ_id != 0:  # ID 0 is evaluated in context with AEAD
                    status = (
                        RuleStatus.FAIL if req == RequirementLevel.MUST_NOT
                        else (RuleStatus.WARNING if req == RequirementLevel.SHOULD_NOT else RuleStatus.PASS)
                    )
                    severity = (
                        Severity.CRITICAL if req == RequirementLevel.MUST_NOT
                        else (Severity.MEDIUM if req == RequirementLevel.SHOULD_NOT else Severity.INFORMATIONAL)
                    )
                    results.append(RuleEvaluationResult(
                        rule_id="IKE-TRANS-INTEG-001",
                        rfc=reg["rfc"],
                        section=reg["section"],
                        category=RuleCategory.CAT2_CRYPTO_TRANSFORMS.value,
                        condition=f"INTEG transform requirement status ({reg['name']})",
                        requirement_level=req.value,
                        applicable_context=ApplicableContext.HANDSHAKE.value,
                        status=status,
                        severity=severity,
                        reason=reg["reason"],
                        observed_value=f"{reg['name']} (ID {integ_id})",
                        expected_requirement=f"Requirement level: {req.value}",
                        spec_source=reg["spec_source"].value,
                    ))

        # Audit DH Transform requirement level
        dh_entry = self._first(tx.get("dh_group", []))
        if dh_entry is not None:
            dh_id = dh_entry.get("id")
            reg = IKEV2_DH_REGISTRY.get(dh_id)
            if reg:
                req = reg["req_level"]
                status = (
                    RuleStatus.FAIL if req == RequirementLevel.MUST_NOT
                    else (RuleStatus.WARNING if req == RequirementLevel.SHOULD_NOT else RuleStatus.PASS)
                )
                severity = (
                    Severity.CRITICAL if req == RequirementLevel.MUST_NOT
                    else (Severity.MEDIUM if req == RequirementLevel.SHOULD_NOT else Severity.INFORMATIONAL)
                )
                results.append(RuleEvaluationResult(
                    rule_id="IKE-TRANS-DH-001",
                    rfc=reg["rfc"],
                    section=reg["section"],
                    category=RuleCategory.CAT2_CRYPTO_TRANSFORMS.value,
                    condition=f"DH Group requirement status ({reg['name']})",
                    requirement_level=req.value,
                    applicable_context=ApplicableContext.HANDSHAKE.value,
                    status=status,
                    severity=severity,
                    reason=reg["reason"],
                    observed_value=f"{reg['name']} (ID {dh_id})",
                    expected_requirement=f"Requirement level: {req.value}",
                    spec_source=reg["spec_source"].value,
                ))

        return results

    # Category 3: Encryption Rules (RFC 8247 §2.1, RFC 8221 §2.1)

    def _eval_category_3_encryption(
        self, tx: dict[str, list[dict]], session: dict[str, Any]
    ) -> list[RuleEvaluationResult]:
        results = []
        encr_entry = self._first(tx.get("encryption", []))
        integ_entry = self._first(tx.get("integrity", []))

        if encr_entry is None:
            results.append(RuleEvaluationResult(
                rule_id="IKE-ENCR-PRESENCE-001",
                rfc="RFC 7296",
                section="§3.3.2",
                category=RuleCategory.CAT3_ENCRYPTION.value,
                condition="Encryption transform presence in IKE SA",
                requirement_level=RequirementLevel.MUST.value,
                applicable_context=ApplicableContext.HANDSHAKE.value,
                status=RuleStatus.FAIL,
                severity=Severity.CRITICAL,
                reason="IKE SA proposal does not contain an encryption transform.",
                observed_value="None",
                expected_requirement="Encryption transform MUST be present",
            ))
            return results

        encr_id = encr_entry.get("id")
        key_len = encr_entry.get("length")
        is_aead = encr_id in AEAD_ENCR_IDS

        # 1. Prohibited ciphers (3DES, DES, Blowfish, RC5, IDEA, CAST)
        prohibited_ids = {1, 2, 3, 4, 5, 6, 7, 8, 9}
        if encr_id in prohibited_ids:
            reg = IKEV2_ENCR_REGISTRY.get(encr_id, {})
            results.append(RuleEvaluationResult(
                rule_id="IKE-ENCR-PROHIBIT-001",
                rfc="RFC 8247",
                section="§2.1",
                category=RuleCategory.CAT3_ENCRYPTION.value,
                condition="Prohibited encryption algorithm check",
                requirement_level=RequirementLevel.MUST_NOT.value,
                applicable_context=ApplicableContext.HANDSHAKE.value,
                status=RuleStatus.FAIL,
                severity=Severity.CRITICAL,
                reason=f"{reg.get('name', f'Cipher {encr_id}')} is insecure and prohibited under RFC 8247.",
                observed_value=f"{reg.get('name', 'ID ' + str(encr_id))}",
                expected_requirement="MUST NOT be used",
            ))
        elif encr_id == 11:  # ENCR_NULL in IKE SA
            results.append(RuleEvaluationResult(
                rule_id="IKE-ENCR-NULL-001",
                rfc="RFC 7296 / RFC 8247",
                section="§3.3.2 / §2.1",
                category=RuleCategory.CAT3_ENCRYPTION.value,
                condition="ENCR_NULL prohibited in IKE SA",
                requirement_level=RequirementLevel.MUST_NOT.value,
                applicable_context=ApplicableContext.HANDSHAKE.value,
                status=RuleStatus.FAIL,
                severity=Severity.CRITICAL,
                reason="ENCR_NULL is strictly prohibited for IKE SA protection.",
                observed_value="ENCR_NULL (ID 11)",
                expected_requirement="MUST NOT be used in IKE SA",
            ))
        else:
            results.append(RuleEvaluationResult(
                rule_id="IKE-ENCR-PROHIBIT-001",
                rfc="RFC 8247",
                section="§2.1",
                category=RuleCategory.CAT3_ENCRYPTION.value,
                condition="Encryption algorithm legitimacy",
                requirement_level=RequirementLevel.MUST.value,
                applicable_context=ApplicableContext.HANDSHAKE.value,
                status=RuleStatus.PASS,
                severity=Severity.INFORMATIONAL,
                reason="Encryption algorithm is not prohibited.",
                observed_value=f"ID {encr_id}",
                expected_requirement="Permitted encryption algorithm",
            ))

        # 2. Key-size verification
        if key_len is not None:
            if encr_id in (12, 20):  # AES-CBC, AES-GCM
                if key_len == 192:
                    results.append(RuleEvaluationResult(
                        rule_id="IKE-ENCR-KEYLEN-001",
                        rfc="RFC 8247",
                        section="§2.1",
                        category=RuleCategory.CAT3_ENCRYPTION.value,
                        condition="AES key size compliance",
                        requirement_level=RequirementLevel.SHOULD_NOT.value,
                        applicable_context=ApplicableContext.HANDSHAKE.value,
                        status=RuleStatus.WARNING,
                        severity=Severity.LOW,
                        reason="192-bit AES key length is SHOULD NOT under RFC 8247 (prefer 128 or 256 bits).",
                        observed_value="192 bits",
                        expected_requirement="128 or 256 bits recommended",
                    ))
                elif key_len in (128, 256):
                    results.append(RuleEvaluationResult(
                        rule_id="IKE-ENCR-KEYLEN-001",
                        rfc="RFC 8247",
                        section="§2.1",
                        category=RuleCategory.CAT3_ENCRYPTION.value,
                        condition="AES key size compliance",
                        requirement_level=RequirementLevel.MUST.value,
                        applicable_context=ApplicableContext.HANDSHAKE.value,
                        status=RuleStatus.PASS,
                        severity=Severity.INFORMATIONAL,
                        reason="Key length conforms to RFC 8247 requirements.",
                        observed_value=f"{key_len} bits",
                        expected_requirement="128 or 256 bits",
                    ))
                else:
                    results.append(RuleEvaluationResult(
                        rule_id="IKE-ENCR-KEYLEN-001",
                        rfc="RFC 8247",
                        section="§2.1",
                        category=RuleCategory.CAT3_ENCRYPTION.value,
                        condition="AES key size compliance",
                        requirement_level=RequirementLevel.MUST.value,
                        applicable_context=ApplicableContext.HANDSHAKE.value,
                        status=RuleStatus.FAIL,
                        severity=Severity.HIGH,
                        reason=f"Unsupported AES key length {key_len} bits.",
                        observed_value=f"{key_len} bits",
                        expected_requirement="128 or 256 bits",
                    ))

        # 3. AEAD vs Separate Integrity Enforcement (RFC 8247 §2.1, §2.3)
        integ_id = integ_entry.get("id") if integ_entry else None
        if is_aead:
            if integ_id is not None and integ_id != 0:
                results.append(RuleEvaluationResult(
                    rule_id="IKE-ENCR-AEAD-PAIRING-001",
                    rfc="RFC 8247",
                    section="§2.1",
                    category=RuleCategory.CAT3_ENCRYPTION.value,
                    condition="AEAD cipher paired with traditional integrity transform",
                    requirement_level=RequirementLevel.MUST_NOT.value,
                    applicable_context=ApplicableContext.HANDSHAKE.value,
                    status=RuleStatus.FAIL,
                    severity=Severity.CRITICAL,
                    reason="Combined-mode AEAD ciphers MUST NOT be paired with a separate integrity transform.",
                    observed_value=f"AEAD ENCR={encr_id} paired with INTEG={integ_id}",
                    expected_requirement="INTEG MUST be NONE (0) when AEAD is negotiated",
                ))
            else:
                results.append(RuleEvaluationResult(
                    rule_id="IKE-ENCR-AEAD-PAIRING-001",
                    rfc="RFC 8247",
                    section="§2.1",
                    category=RuleCategory.CAT3_ENCRYPTION.value,
                    condition="AEAD cipher integrity pairing",
                    requirement_level=RequirementLevel.MUST.value,
                    applicable_context=ApplicableContext.HANDSHAKE.value,
                    status=RuleStatus.PASS,
                    severity=Severity.INFORMATIONAL,
                    reason="AEAD cipher is correctly paired with Transform ID 0 (NONE).",
                    observed_value=f"ENCR={encr_id}, INTEG=0",
                    expected_requirement="INTEG MUST be NONE (0) with AEAD",
                ))
        else:
            # Non-AEAD block cipher MUST be paired with explicit integrity algorithm
            if integ_id == 0 or integ_id is None:
                results.append(RuleEvaluationResult(
                    rule_id="IKE-ENCR-NONAEAD-PAIRING-001",
                    rfc="RFC 8247",
                    section="§2.1",
                    category=RuleCategory.CAT3_ENCRYPTION.value,
                    condition="Non-AEAD cipher paired without integrity protection",
                    requirement_level=RequirementLevel.MUST_NOT.value,
                    applicable_context=ApplicableContext.HANDSHAKE.value,
                    status=RuleStatus.FAIL,
                    severity=Severity.CRITICAL,
                    reason="Traditional non-AEAD block ciphers MUST be paired with an explicit integrity algorithm.",
                    observed_value=f"Non-AEAD ENCR={encr_id} paired with INTEG={integ_id}",
                    expected_requirement="INTEG MUST NOT be NONE (0) for non-AEAD ciphers",
                ))
            else:
                results.append(RuleEvaluationResult(
                    rule_id="IKE-ENCR-NONAEAD-PAIRING-001",
                    rfc="RFC 8247",
                    section="§2.1",
                    category=RuleCategory.CAT3_ENCRYPTION.value,
                    condition="Non-AEAD cipher integrity pairing",
                    requirement_level=RequirementLevel.MUST.value,
                    applicable_context=ApplicableContext.HANDSHAKE.value,
                    status=RuleStatus.PASS,
                    severity=Severity.INFORMATIONAL,
                    reason="Non-AEAD cipher is paired with explicit integrity transform.",
                    observed_value=f"ENCR={encr_id}, INTEG={integ_id}",
                    expected_requirement="Explicit integrity algorithm present",
                ))

        return results

    # Category 4: PRF Rules (RFC 8247 §2.2)

    def _eval_category_4_prf(self, tx: dict[str, list[dict]]) -> list[RuleEvaluationResult]:
        results = []
        prf_entry = self._first(tx.get("prf", []))

        if prf_entry is None:
            results.append(RuleEvaluationResult(
                rule_id="IKE-PRF-MANDATORY-001",
                rfc="RFC 7296 / RFC 8247",
                section="§3.3.2 / §2.2",
                category=RuleCategory.CAT4_PRF.value,
                condition="PRF mandatory presence in Phase 1 IKE SA",
                requirement_level=RequirementLevel.MUST.value,
                applicable_context=ApplicableContext.HANDSHAKE.value,
                status=RuleStatus.FAIL,
                severity=Severity.CRITICAL,
                reason="PRF transform is mandatory for IKE SA key derivation and was not proposed.",
                observed_value="Missing",
                expected_requirement="PRF transform MUST be present in IKE SA",
            ))
            return results

        prf_id = prf_entry.get("id")
        reg = IKEV2_PRF_REGISTRY.get(prf_id)

        if reg:
            if reg["req_level"] == RequirementLevel.MUST_NOT:
                results.append(RuleEvaluationResult(
                    rule_id="IKE-PRF-PROHIBIT-001",
                    rfc=reg["rfc"],
                    section=reg["section"],
                    category=RuleCategory.CAT4_PRF.value,
                    condition=f"Prohibited PRF algorithm ({reg['name']})",
                    requirement_level=RequirementLevel.MUST_NOT.value,
                    applicable_context=ApplicableContext.HANDSHAKE.value,
                    status=RuleStatus.FAIL,
                    severity=Severity.CRITICAL,
                    reason=f"{reg['name']} is cryptographically broken/deprecated and prohibited under RFC 8247.",
                    observed_value=reg["name"],
                    expected_requirement="MUST NOT be used",
                ))
            elif reg["req_level"] == RequirementLevel.SHOULD_NOT:
                results.append(RuleEvaluationResult(
                    rule_id="IKE-PRF-WEAK-001",
                    rfc=reg["rfc"],
                    section=reg["section"],
                    category=RuleCategory.CAT4_PRF.value,
                    condition=f"Discouraged PRF algorithm ({reg['name']})",
                    requirement_level=RequirementLevel.SHOULD_NOT.value,
                    applicable_context=ApplicableContext.HANDSHAKE.value,
                    status=RuleStatus.WARNING,
                    severity=Severity.MEDIUM,
                    reason=f"{reg['name']} is SHOULD NOT under RFC 8247.",
                    observed_value=reg["name"],
                    expected_requirement="HMAC-SHA2-256 or stronger recommended",
                ))
            else:
                results.append(RuleEvaluationResult(
                    rule_id="IKE-PRF-STATUS-001",
                    rfc=reg["rfc"],
                    section=reg["section"],
                    category=RuleCategory.CAT4_PRF.value,
                    condition=f"Compliant PRF algorithm ({reg['name']})",
                    requirement_level=reg["req_level"].value,
                    applicable_context=ApplicableContext.HANDSHAKE.value,
                    status=RuleStatus.PASS,
                    severity=Severity.INFORMATIONAL,
                    reason=f"{reg['name']} satisfies RFC 8247 PRF requirements.",
                    observed_value=reg["name"],
                    expected_requirement=f"Requirement level: {reg['req_level'].value}",
                ))
        else:
            results.append(RuleEvaluationResult(
                rule_id="IKE-PRF-VALID-001",
                rfc="RFC 8247",
                section="§2.2",
                category=RuleCategory.CAT4_PRF.value,
                condition="PRF transform identification",
                requirement_level=RequirementLevel.MUST.value,
                applicable_context=ApplicableContext.HANDSHAKE.value,
                status=RuleStatus.WARNING,
                severity=Severity.HIGH,
                reason=f"PRF transform ID {prf_id} is unrecognized in RFC 8247 registry.",
                observed_value=f"ID {prf_id}",
                expected_requirement="Recognized PRF ID",
            ))

        return results

    # Category 5: Integrity Rules (RFC 8247 §2.3, RFC 8221 §2.2)

    def _eval_category_5_integrity(self, tx: dict[str, list[dict]]) -> list[RuleEvaluationResult]:
        results = []
        integ_entry = self._first(tx.get("integrity", []))

        if integ_entry is None:
            # If encryption is AEAD, missing explicit integ is fine; otherwise missing
            encr_entry = self._first(tx.get("encryption", []))
            encr_id = encr_entry.get("id") if encr_entry else None
            if encr_id in AEAD_ENCR_IDS:
                results.append(RuleEvaluationResult(
                    rule_id="IKE-INTEG-AEAD-IMPLICIT-001",
                    rfc="RFC 8247",
                    section="§2.3",
                    category=RuleCategory.CAT5_INTEGRITY.value,
                    condition="Implicit integrity via AEAD cipher",
                    requirement_level=RequirementLevel.MUST.value,
                    applicable_context=ApplicableContext.HANDSHAKE.value,
                    status=RuleStatus.PASS,
                    severity=Severity.INFORMATIONAL,
                    reason="Integrity is implicitly provided by negotiated AEAD cipher.",
                    observed_value="AEAD implicit integrity",
                    expected_requirement="AEAD cipher provides integrity",
                ))
            else:
                results.append(RuleEvaluationResult(
                    rule_id="IKE-INTEG-MANDATORY-001",
                    rfc="RFC 8247",
                    section="§2.3",
                    category=RuleCategory.CAT5_INTEGRITY.value,
                    condition="Integrity transform presence for non-AEAD cipher",
                    requirement_level=RequirementLevel.MUST.value,
                    applicable_context=ApplicableContext.HANDSHAKE.value,
                    status=RuleStatus.FAIL,
                    severity=Severity.CRITICAL,
                    reason="Integrity transform is mandatory when non-AEAD encryption is negotiated.",
                    observed_value="Missing",
                    expected_requirement="Explicit integrity transform MUST be present",
                ))
            return results

        integ_id = integ_entry.get("id")
        reg = IKEV2_INTEG_REGISTRY.get(integ_id)

        if reg:
            if integ_id != 0:  # Evaluated for standalone algorithms
                if reg["req_level"] == RequirementLevel.MUST_NOT:
                    results.append(RuleEvaluationResult(
                        rule_id="IKE-INTEG-PROHIBIT-001",
                        rfc=reg["rfc"],
                        section=reg["section"],
                        category=RuleCategory.CAT5_INTEGRITY.value,
                        condition=f"Prohibited integrity algorithm ({reg['name']})",
                        requirement_level=RequirementLevel.MUST_NOT.value,
                        applicable_context=ApplicableContext.HANDSHAKE.value,
                        status=RuleStatus.FAIL,
                        severity=Severity.CRITICAL,
                        reason=f"{reg['name']} is cryptographically weak or truncated below safe bounds and prohibited.",
                        observed_value=reg["name"],
                        expected_requirement="MUST NOT be used",
                    ))
                elif reg["req_level"] == RequirementLevel.SHOULD_NOT:
                    results.append(RuleEvaluationResult(
                        rule_id="IKE-INTEG-WEAK-001",
                        rfc=reg["rfc"],
                        section=reg["section"],
                        category=RuleCategory.CAT5_INTEGRITY.value,
                        condition=f"Discouraged integrity algorithm ({reg['name']})",
                        requirement_level=RequirementLevel.SHOULD_NOT.value,
                        applicable_context=ApplicableContext.HANDSHAKE.value,
                        status=RuleStatus.WARNING,
                        severity=Severity.MEDIUM,
                        reason=f"{reg['name']} is SHOULD NOT under RFC 8247.",
                        observed_value=reg["name"],
                        expected_requirement="HMAC-SHA2-256-128 or stronger recommended",
                    ))
                else:
                    results.append(RuleEvaluationResult(
                        rule_id="IKE-INTEG-STATUS-001",
                        rfc=reg["rfc"],
                        section=reg["section"],
                        category=RuleCategory.CAT5_INTEGRITY.value,
                        condition=f"Compliant integrity algorithm ({reg['name']})",
                        requirement_level=reg["req_level"].value,
                        applicable_context=ApplicableContext.HANDSHAKE.value,
                        status=RuleStatus.PASS,
                        severity=Severity.INFORMATIONAL,
                        reason=f"{reg['name']} satisfies RFC 8247 integrity requirements.",
                        observed_value=reg["name"],
                        expected_requirement=f"Requirement level: {reg['req_level'].value}",
                    ))
        else:
            results.append(RuleEvaluationResult(
                rule_id="IKE-INTEG-VALID-001",
                rfc="RFC 8247",
                section="§2.3",
                category=RuleCategory.CAT5_INTEGRITY.value,
                condition="Integrity transform recognition",
                requirement_level=RequirementLevel.MUST.value,
                applicable_context=ApplicableContext.HANDSHAKE.value,
                status=RuleStatus.WARNING,
                severity=Severity.HIGH,
                reason=f"Integrity transform ID {integ_id} is unrecognized in RFC 8247 registry.",
                observed_value=f"ID {integ_id}",
                expected_requirement="Recognized integrity ID",
            ))

        return results

    # Category 6: Diffie-Hellman / Key Exchange (RFC 8247 §2.4, RFC 9370)

    def _eval_category_6_dh(
        self, tx: dict[str, list[dict]], session: dict[str, Any]
    ) -> list[RuleEvaluationResult]:
        results = []
        dh_entry = self._first(tx.get("dh_group", []))

        if dh_entry is None:
            results.append(RuleEvaluationResult(
                rule_id="IKE-DH-MANDATORY-001",
                rfc="RFC 7296 / RFC 8247",
                section="§3.3.2 / §2.4",
                category=RuleCategory.CAT6_DH_KEY_EXCHANGE.value,
                condition="Diffie-Hellman group mandatory presence in IKE SA",
                requirement_level=RequirementLevel.MUST.value,
                applicable_context=ApplicableContext.HANDSHAKE.value,
                status=RuleStatus.FAIL,
                severity=Severity.CRITICAL,
                reason="Diffie-Hellman key exchange group is mandatory in IKE_SA_INIT and was not proposed.",
                observed_value="Missing",
                expected_requirement="DH group MUST be present in IKE_SA_INIT",
            ))
            return results

        dh_id = dh_entry.get("id")
        reg = IKEV2_DH_REGISTRY.get(dh_id)

        if reg:
            if reg["req_level"] == RequirementLevel.MUST_NOT:
                results.append(RuleEvaluationResult(
                    rule_id="IKE-DH-PROHIBIT-001",
                    rfc=reg["rfc"],
                    section=reg["section"],
                    category=RuleCategory.CAT6_DH_KEY_EXCHANGE.value,
                    condition=f"Prohibited DH group ({reg['name']})",
                    requirement_level=RequirementLevel.MUST_NOT.value,
                    applicable_context=ApplicableContext.HANDSHAKE.value,
                    status=RuleStatus.FAIL,
                    severity=Severity.CRITICAL,
                    reason=f"{reg['name']} is vulnerable / broken and strictly prohibited under RFC 8247.",
                    observed_value=f"{reg['name']} (ID {dh_id})",
                    expected_requirement="MUST NOT be used",
                    spec_source=reg["spec_source"].value,
                ))
            elif reg["req_level"] == RequirementLevel.SHOULD_NOT:
                results.append(RuleEvaluationResult(
                    rule_id="IKE-DH-DISCOURAGED-001",
                    rfc=reg["rfc"],
                    section=reg["section"],
                    category=RuleCategory.CAT6_DH_KEY_EXCHANGE.value,
                    condition=f"Discouraged DH group ({reg['name']})",
                    requirement_level=RequirementLevel.SHOULD_NOT.value,
                    applicable_context=ApplicableContext.HANDSHAKE.value,
                    status=RuleStatus.WARNING,
                    severity=Severity.MEDIUM,
                    reason=f"{reg['name']} is SHOULD NOT under RFC 8247.",
                    observed_value=reg["name"],
                    expected_requirement="Group 14 (2048-bit), Group 19 (P-256), or Curve25519 recommended",
                    spec_source=reg["spec_source"].value,
                ))
            else:
                results.append(RuleEvaluationResult(
                    rule_id="IKE-DH-STATUS-001",
                    rfc=reg["rfc"],
                    section=reg["section"],
                    category=RuleCategory.CAT6_DH_KEY_EXCHANGE.value,
                    condition=f"Compliant Key Exchange ({reg['name']})",
                    requirement_level=reg["req_level"].value,
                    applicable_context=ApplicableContext.HANDSHAKE.value,
                    status=RuleStatus.PASS,
                    severity=Severity.INFORMATIONAL,
                    reason=f"{reg['name']} satisfies RFC implementation requirements.",
                    observed_value=reg["name"],
                    expected_requirement=f"Requirement level: {reg['req_level'].value}",
                    spec_source=reg["spec_source"].value,
                ))
        else:
            results.append(RuleEvaluationResult(
                rule_id="IKE-DH-VALID-001",
                rfc="RFC 8247",
                section="§2.4",
                category=RuleCategory.CAT6_DH_KEY_EXCHANGE.value,
                condition="Key exchange transform recognition",
                requirement_level=RequirementLevel.MUST.value,
                applicable_context=ApplicableContext.HANDSHAKE.value,
                status=RuleStatus.WARNING,
                severity=Severity.HIGH,
                reason=f"Key exchange method ID {dh_id} is unrecognized in RFC 8247 registry.",
                observed_value=f"ID {dh_id}",
                expected_requirement="Recognized DH group or KEM ID",
            ))

        # Multiple Key Exchange (RFC 9370) Evaluation
        notifs = set(session.get("notify", {}).get("notify_types", []))
        has_multi_ke_notify = 16440 in notifs  # ADDITIONAL_KEY_EXCHANGE

        # Count additional key exchange transforms
        addke_count = 0
        for i in range(1, 8):
            if tx.get(f"additional_key_exchange_{i}"):
                addke_count += 1

        if has_multi_ke_notify or addke_count > 0:
            if addke_count > 7:
                results.append(RuleEvaluationResult(
                    rule_id="IKE-DH-MULTIKE-LIMIT-001",
                    rfc="RFC 9370",
                    section="§2.2",
                    category=RuleCategory.CAT6_DH_KEY_EXCHANGE.value,
                    condition="RFC 9370 additional key exchange round limit",
                    requirement_level=RequirementLevel.MUST.value,
                    applicable_context=ApplicableContext.HANDSHAKE.value,
                    status=RuleStatus.FAIL,
                    severity=Severity.CRITICAL,
                    reason=f"RFC 9370 permits at most 7 additional key exchanges; observed {addke_count}.",
                    observed_value=f"{addke_count} additional rounds",
                    expected_requirement="At most 7 additional key exchanges",
                    spec_source=SpecSourceType.PUBLISHED_RFC.value,
                ))
            else:
                results.append(RuleEvaluationResult(
                    rule_id="IKE-DH-MULTIKE-VALID-001",
                    rfc="RFC 9370",
                    section="§2.1",
                    category=RuleCategory.CAT6_DH_KEY_EXCHANGE.value,
                    condition="RFC 9370 multiple key exchange negotiation",
                    requirement_level=RequirementLevel.MUST.value,
                    applicable_context=ApplicableContext.HANDSHAKE.value,
                    status=RuleStatus.PASS,
                    severity=Severity.INFORMATIONAL,
                    reason=f"Multiple Key Exchange negotiated with {addke_count} additional round(s).",
                    observed_value=f"{addke_count} additional KE round(s)",
                    expected_requirement="Valid RFC 9370 negotiation",
                    spec_source=SpecSourceType.PUBLISHED_RFC.value,
                ))

        return results

    # Category 7: Identity & Authentication (RFC 7296 §3.8, RFC 7427)

    def _eval_category_7_auth(self, session: dict[str, Any]) -> list[RuleEvaluationResult]:
        results = []
        auth_data = session.get("IKE_AUTH", {}).get("authentication", {})
        cert_data = session.get("IKE_AUTH", {}).get("certificate", {})
        notifs = set(session.get("notify", {}).get("notify_types", []))

        auth_type = auth_data.get("auth_type")
        if auth_type is None:
            # Check top level or if IKE_AUTH was omitted
            if "IKE_AUTH" in session:
                results.append(RuleEvaluationResult(
                    rule_id="IKE-AUTH-MANDATORY-001",
                    rfc="RFC 7296",
                    section="§3.8",
                    category=RuleCategory.CAT7_AUTHENTICATION.value,
                    condition="AUTH payload presence in IKE_AUTH",
                    requirement_level=RequirementLevel.MUST.value,
                    applicable_context=ApplicableContext.HANDSHAKE.value,
                    status=RuleStatus.FAIL,
                    severity=Severity.CRITICAL,
                    reason="AUTH payload is mandatory in IKE_AUTH exchange and is missing.",
                    observed_value="Missing",
                    expected_requirement="AUTH payload MUST be present in IKE_AUTH",
                ))
            else:
                results.append(RuleEvaluationResult(
                    rule_id="IKE-AUTH-MANDATORY-001",
                    rfc="RFC 7296",
                    section="§3.8",
                    category=RuleCategory.CAT7_AUTHENTICATION.value,
                    condition="AUTH payload presence in IKE_AUTH",
                    requirement_level=RequirementLevel.MUST.value,
                    applicable_context=ApplicableContext.HANDSHAKE.value,
                    status=RuleStatus.NOT_VERIFIABLE,
                    severity=Severity.LOW,
                    reason="IKE_AUTH exchange data was not supplied.",
                    observed_value=None,
                    expected_requirement="AUTH payload in IKE_AUTH",
                ))
            return results

        reg = IKEV2_AUTH_METHODS_REGISTRY.get(auth_type)
        if reg:
            if reg["req_level"] == RequirementLevel.MUST_NOT:
                results.append(RuleEvaluationResult(
                    rule_id="IKE-AUTH-METHOD-001",
                    rfc=reg["rfc"],
                    section=reg["section"],
                    category=RuleCategory.CAT7_AUTHENTICATION.value,
                    condition=f"Prohibited authentication method ({reg['name']})",
                    requirement_level=RequirementLevel.MUST_NOT.value,
                    applicable_context=ApplicableContext.HANDSHAKE.value,
                    status=RuleStatus.FAIL,
                    severity=Severity.CRITICAL,
                    reason=f"{reg['name']} is broken and prohibited under RFC 8247.",
                    observed_value=reg["name"],
                    expected_requirement="MUST NOT be used",
                ))
            elif reg["req_level"] == RequirementLevel.SHOULD_NOT:
                results.append(RuleEvaluationResult(
                    rule_id="IKE-AUTH-METHOD-001",
                    rfc=reg["rfc"],
                    section=reg["section"],
                    category=RuleCategory.CAT7_AUTHENTICATION.value,
                    condition=f"Legacy authentication method ({reg['name']})",
                    requirement_level=RequirementLevel.SHOULD_NOT.value,
                    applicable_context=ApplicableContext.HANDSHAKE.value,
                    status=RuleStatus.WARNING,
                    severity=Severity.LOW,
                    reason=reg["reason"],
                    observed_value=reg["name"],
                    expected_requirement="RFC 7427 Digital Signature (Method 14) recommended",
                ))
            else:
                results.append(RuleEvaluationResult(
                    rule_id="IKE-AUTH-METHOD-001",
                    rfc=reg["rfc"],
                    section=reg["section"],
                    category=RuleCategory.CAT7_AUTHENTICATION.value,
                    condition=f"Valid authentication method ({reg['name']})",
                    requirement_level=reg["req_level"].value,
                    applicable_context=ApplicableContext.HANDSHAKE.value,
                    status=RuleStatus.PASS,
                    severity=Severity.INFORMATIONAL,
                    reason=f"{reg['name']} is an RFC-compliant authentication method.",
                    observed_value=reg["name"],
                    expected_requirement=f"Requirement level: {reg['req_level'].value}",
                ))
        else:
            results.append(RuleEvaluationResult(
                rule_id="IKE-AUTH-METHOD-001",
                rfc="RFC 7296",
                section="§3.8",
                category=RuleCategory.CAT7_AUTHENTICATION.value,
                condition="Authentication method identification",
                requirement_level=RequirementLevel.MUST.value,
                applicable_context=ApplicableContext.HANDSHAKE.value,
                status=RuleStatus.WARNING,
                severity=Severity.HIGH,
                reason=f"Authentication method ID {auth_type} is unrecognized in IANA registry.",
                observed_value=f"ID {auth_type}",
                expected_requirement="Recognized IKEv2 auth method",
            ))

        # Digital Signature (Method 14) Hash Signaling (RFC 7427)
        if auth_type == 14:
            has_hash_notify = (16443 in notifs) or (16431 in notifs)
            if has_hash_notify:
                results.append(RuleEvaluationResult(
                    rule_id="IKE-AUTH-RFC7427-HASH-001",
                    rfc="RFC 7427",
                    section="§3",
                    category=RuleCategory.CAT7_AUTHENTICATION.value,
                    condition="RFC 7427 SIGNATURE_HASH_ALGORITHMS notification presence",
                    requirement_level=RequirementLevel.SHOULD.value,
                    applicable_context=ApplicableContext.HANDSHAKE.value,
                    status=RuleStatus.PASS,
                    severity=Severity.INFORMATIONAL,
                    reason="Explicit hash algorithm signaling notification present.",
                    observed_value="Notify 16443 / 16431 present",
                    expected_requirement="SIGNATURE_HASH_ALGORITHMS notification",
                    spec_source=SpecSourceType.PUBLISHED_RFC.value,
                ))
            else:
                results.append(RuleEvaluationResult(
                    rule_id="IKE-AUTH-RFC7427-HASH-001",
                    rfc="RFC 7427",
                    section="§3",
                    category=RuleCategory.CAT7_AUTHENTICATION.value,
                    condition="RFC 7427 SIGNATURE_HASH_ALGORITHMS notification presence",
                    requirement_level=RequirementLevel.SHOULD.value,
                    applicable_context=ApplicableContext.HANDSHAKE.value,
                    status=RuleStatus.WARNING,
                    severity=Severity.LOW,
                    reason="Digital Signature (Method 14) used without SIGNATURE_HASH_ALGORITHMS notification.",
                    observed_value="Absent",
                    expected_requirement="SIGNATURE_HASH_ALGORITHMS notification SHOULD be sent",
                    spec_source=SpecSourceType.PUBLISHED_RFC.value,
                ))

        # Dedicated PKI & Certificate Health Auditing if auth_metadata is provided
        if "auth_metadata" in session:
            cert_report = evaluate_auth_health(session["auth_metadata"])
            for finding in cert_report.all_findings:
                status = RuleStatus.PASS if finding.status.value == "PASS" else (RuleStatus.WARNING if finding.status.value == "WARNING" else RuleStatus.FAIL)
                sev = (
                    Severity.CRITICAL if finding.severity.value == "CRITICAL"
                    else Severity.HIGH if finding.severity.value == "HIGH"
                    else Severity.MEDIUM if finding.severity.value == "MEDIUM"
                    else Severity.INFORMATIONAL
                )
                results.append(RuleEvaluationResult(
                    rule_id=finding.rule_id,
                    rfc="RFC 5280 / RFC 7427",
                    section="§4",
                    category=RuleCategory.CAT7_AUTHENTICATION.value,
                    condition=f"{finding.target}: {finding.condition}",
                    requirement_level=RequirementLevel.MUST.value if status == RuleStatus.FAIL else RequirementLevel.SHOULD.value,
                    applicable_context=ApplicableContext.HANDSHAKE.value,
                    status=status,
                    severity=sev,
                    reason=f"{finding.reason} | Remediation: {finding.remediation}",
                    observed_value=finding.observed,
                    expected_requirement=finding.expected,
                    spec_source=SpecSourceType.PUBLISHED_RFC.value,
                ))
            return results

        # Legacy Certificate Auditing (RFC 7296 §3.6)
        cert_sig_oid = (
            cert_data.get("cert_sig_algo_oid")
            or session.get("cert_sig_algo_oid")
        )
        cert_key_oid = (
            cert_data.get("cert_key_type_oid")
            or session.get("cert_key_type_oid")
        )
        cert_key_len = (
            cert_data.get("cert_key_len")
            or session.get("cert_key_len")
        )

        if cert_sig_oid:
            sig_reg = CERT_SIG_ALGO_OIDS.get(cert_sig_oid)
            if sig_reg and sig_reg.get("broken"):
                results.append(RuleEvaluationResult(
                    rule_id="IKE-AUTH-CERT-SIG-001",
                    rfc="RFC 8247",
                    section="§3",
                    category=RuleCategory.CAT7_AUTHENTICATION.value,
                    condition=f"Certificate signature algorithm check ({sig_reg['name']})",
                    requirement_level=RequirementLevel.MUST_NOT.value,
                    applicable_context=ApplicableContext.HANDSHAKE.value,
                    status=RuleStatus.FAIL,
                    severity=Severity.CRITICAL,
                    reason=f"Certificate signed with broken algorithm: {sig_reg['reason']}",
                    observed_value=f"{sig_reg['name']} ({cert_sig_oid})",
                    expected_requirement="Secure signature algorithm (SHA-256 or stronger)",
                ))
            else:
                results.append(RuleEvaluationResult(
                    rule_id="IKE-AUTH-CERT-SIG-001",
                    rfc="RFC 8247",
                    section="§3",
                    category=RuleCategory.CAT7_AUTHENTICATION.value,
                    condition="Certificate signature algorithm security",
                    requirement_level=RequirementLevel.MUST.value,
                    applicable_context=ApplicableContext.HANDSHAKE.value,
                    status=RuleStatus.PASS,
                    severity=Severity.INFORMATIONAL,
                    reason="Certificate signature algorithm is secure.",
                    observed_value=cert_sig_oid,
                    expected_requirement="Secure signature algorithm",
                ))

        if cert_key_oid:
            key_reg = CERT_KEY_TYPE_OIDS.get(cert_key_oid)
            if key_reg and key_reg.get("broken"):
                results.append(RuleEvaluationResult(
                    rule_id="IKE-AUTH-CERT-KEY-001",
                    rfc="RFC 8247",
                    section="§3",
                    category=RuleCategory.CAT7_AUTHENTICATION.value,
                    condition=f"Certificate public key type ({key_reg['name']})",
                    requirement_level=RequirementLevel.MUST_NOT.value,
                    applicable_context=ApplicableContext.HANDSHAKE.value,
                    status=RuleStatus.FAIL,
                    severity=Severity.CRITICAL,
                    reason=f"Certificate public key algorithm {key_reg['name']} is broken and prohibited.",
                    observed_value=cert_key_oid,
                    expected_requirement="Modern public key algorithm",
                ))
            elif key_reg and "min_bits" in key_reg and cert_key_len is not None:
                if cert_key_len < key_reg["min_bits"]:
                    results.append(RuleEvaluationResult(
                        rule_id="IKE-AUTH-CERT-KEYLEN-001",
                        rfc="RFC 8247",
                        section="§3",
                        category=RuleCategory.CAT7_AUTHENTICATION.value,
                        condition=f"Certificate key length ({key_reg['name']})",
                        requirement_level=RequirementLevel.MUST.value,
                        applicable_context=ApplicableContext.HANDSHAKE.value,
                        status=RuleStatus.FAIL,
                        severity=Severity.CRITICAL,
                        reason=f"Certificate key length {cert_key_len} bits is below minimum {key_reg['min_bits']} bits.",
                        observed_value=f"{cert_key_len} bits",
                        expected_requirement=f"At least {key_reg['min_bits']} bits",
                    ))
                else:
                    results.append(RuleEvaluationResult(
                        rule_id="IKE-AUTH-CERT-KEYLEN-001",
                        rfc="RFC 8247",
                        section="§3",
                        category=RuleCategory.CAT7_AUTHENTICATION.value,
                        condition=f"Certificate key length ({key_reg['name']})",
                        requirement_level=RequirementLevel.MUST.value,
                        applicable_context=ApplicableContext.HANDSHAKE.value,
                        status=RuleStatus.PASS,
                        severity=Severity.INFORMATIONAL,
                        reason=f"Certificate key length {cert_key_len} bits meets or exceeds requirement.",
                        observed_value=f"{cert_key_len} bits",
                        expected_requirement=f"At least {key_reg['min_bits']} bits",
                    ))

        return results

    # Category 9: Security Association Lifecycle (RFC 7296 §1.3, §1.4)

    def _eval_category_9_lifecycle(self, session: dict[str, Any]) -> list[RuleEvaluationResult]:
        results = []
        auth = session.get("IKE_AUTH", {})
        ts_data = auth.get("traffic_selectors", {})
        tsi = ts_data.get("initiator", [])
        tsr = ts_data.get("responder", [])

        # Traffic Selectors check
        if tsi and tsr:
            results.append(RuleEvaluationResult(
                rule_id="IKE-SA-TS-001",
                rfc="RFC 7296",
                section="§3.10",
                category=RuleCategory.CAT9_SA_LIFECYCLE.value,
                condition="Traffic Selectors presence and format",
                requirement_level=RequirementLevel.MUST.value,
                applicable_context=ApplicableContext.HANDSHAKE.value,
                status=RuleStatus.PASS,
                severity=Severity.INFORMATIONAL,
                reason="Traffic Selectors (TSi/TSr) present with valid range specifications.",
                observed_value=f"{len(tsi)} TSi, {len(tsr)} TSr",
                expected_requirement="Valid TSi and TSr payloads",
            ))
        elif "IKE_AUTH" in session:
            # If IKE_AUTH is present but TS is empty, check if Childless IKEv2 (RFC 6027)
            notifs = set(session.get("notify", {}).get("notify_types", []))
            if 16418 in notifs:  # CHILDLESS_IKEV2_SUPPORTED
                results.append(RuleEvaluationResult(
                    rule_id="IKE-SA-TS-001",
                    rfc="RFC 6027",
                    section="§3",
                    category=RuleCategory.CAT9_SA_LIFECYCLE.value,
                    condition="Childless IKEv2 negotiation",
                    requirement_level=RequirementLevel.MAY.value,
                    applicable_context=ApplicableContext.HANDSHAKE.value,
                    status=RuleStatus.PASS,
                    severity=Severity.INFORMATIONAL,
                    reason="Childless IKEv2 negotiated; Traffic Selectors omitted as permitted by RFC 6027.",
                    observed_value="CHILDLESS_IKEV2_SUPPORTED",
                    expected_requirement="TS omitted in Childless IKEv2",
                ))
            else:
                results.append(RuleEvaluationResult(
                    rule_id="IKE-SA-TS-001",
                    rfc="RFC 7296",
                    section="§3.10",
                    category=RuleCategory.CAT9_SA_LIFECYCLE.value,
                    condition="Traffic Selectors presence",
                    requirement_level=RequirementLevel.MUST.value,
                    applicable_context=ApplicableContext.HANDSHAKE.value,
                    status=RuleStatus.NOT_VERIFIABLE,
                    severity=Severity.LOW,
                    reason="Traffic Selectors were not populated in the IKE_AUTH record.",
                    observed_value="Empty TS",
                    expected_requirement="TSi and TSr payloads",
                ))
        else:
            results.append(RuleEvaluationResult(
                rule_id="IKE-SA-TS-001",
                rfc="RFC 7296",
                section="§3.10",
                category=RuleCategory.CAT9_SA_LIFECYCLE.value,
                condition="Traffic Selectors verification",
                requirement_level=RequirementLevel.MUST.value,
                applicable_context=ApplicableContext.HANDSHAKE.value,
                status=RuleStatus.NOT_VERIFIABLE,
                severity=Severity.LOW,
                reason="Handshake data insufficient to verify Traffic Selectors.",
                observed_value=None,
                expected_requirement="TSi and TSr payloads",
            ))

        # Rekeying check (RFC 7296 §1.3.3)
        lifecycle = session.get("lifecycle_events", [])
        create_child = session.get("CREATE_CHILD_SA")
        rekey_observed = any(
            (e.get("exchange") == "CREATE_CHILD_SA" or 16393 in e.get("notify_types", []))
            for e in lifecycle
        ) or (create_child is not None)
        if rekey_observed:
            results.append(RuleEvaluationResult(
                rule_id="IKE-SA-REKEY-001",
                rfc="RFC 7296",
                section="§1.3.3",
                category=RuleCategory.CAT9_SA_LIFECYCLE.value,
                condition="Child SA Rekeying verification",
                requirement_level=RequirementLevel.MUST.value,
                applicable_context=ApplicableContext.HANDSHAKE.value,
                status=RuleStatus.PASS,
                severity=Severity.INFORMATIONAL,
                reason="SA rekeying event observed and parsed.",
                observed_value="CREATE_CHILD_SA / REKEY_SA present",
                expected_requirement="Valid rekey exchange",
            ))
        else:
            results.append(RuleEvaluationResult(
                rule_id="IKE-SA-REKEY-001",
                rfc="RFC 7296",
                section="§1.3.3",
                category=RuleCategory.CAT9_SA_LIFECYCLE.value,
                condition="Child SA Rekeying verification",
                requirement_level=RequirementLevel.MUST.value,
                applicable_context=ApplicableContext.HANDSHAKE.value,
                status=RuleStatus.NOT_VERIFIABLE,
                severity=Severity.LOW,
                reason="No CREATE_CHILD_SA rekey events observed in the supplied trace.",
                observed_value=None,
                expected_requirement="Observable rekey event",
            ))

        # SA Deletion check (RFC 7296 §1.4.1)
        info = session.get("INFORMATIONAL", {})
        del_list = info.get("delete", [])
        if del_list:
            results.append(RuleEvaluationResult(
                rule_id="IKE-SA-DELETE-001",
                rfc="RFC 7296",
                section="§1.4.1",
                category=RuleCategory.CAT9_SA_LIFECYCLE.value,
                condition="SA Deletion verification",
                requirement_level=RequirementLevel.MUST.value,
                applicable_context=ApplicableContext.HANDSHAKE.value,
                status=RuleStatus.PASS,
                severity=Severity.INFORMATIONAL,
                reason="SA Deletion payload correctly formed.",
                observed_value=f"{len(del_list)} delete payload(s)",
                expected_requirement="Valid Delete payload",
            ))
        else:
            results.append(RuleEvaluationResult(
                rule_id="IKE-SA-DELETE-001",
                rfc="RFC 7296",
                section="§1.4.1",
                category=RuleCategory.CAT9_SA_LIFECYCLE.value,
                condition="SA Deletion verification",
                requirement_level=RequirementLevel.MUST.value,
                applicable_context=ApplicableContext.HANDSHAKE.value,
                status=RuleStatus.NOT_VERIFIABLE,
                severity=Severity.LOW,
                reason="No SA deletion events observed in the supplied trace.",
                observed_value=None,
                expected_requirement="Observable delete event",
            ))

        return results

    # Category 11: NAT Traversal (RFC 3948, RFC 7296 §2.23)

    def _eval_category_11_natt(self, session: dict[str, Any]) -> list[RuleEvaluationResult]:
        results = []
        common = session.get("common", {})
        src_port = common.get("src_port")
        dst_port = common.get("dst_port")
        notifs = set(session.get("notify", {}).get("notify_types", []))

        nat_src_present = 16388 in notifs  # NAT_DETECTION_SOURCE_IP
        nat_dst_present = 16389 in notifs  # NAT_DETECTION_DESTINATION_IP

        if nat_src_present and nat_dst_present:
            results.append(RuleEvaluationResult(
                rule_id="IKE-NATT-DETECT-001",
                rfc="RFC 7296",
                section="§2.23",
                category=RuleCategory.CAT11_NAT_TRAVERSAL.value,
                condition="NAT detection notifications presence",
                requirement_level=RequirementLevel.MUST.value,
                applicable_context=ApplicableContext.HANDSHAKE.value,
                status=RuleStatus.PASS,
                severity=Severity.INFORMATIONAL,
                reason="Both NAT_DETECTION_SOURCE_IP and NAT_DETECTION_DESTINATION_IP present.",
                observed_value="Notify 16388 & 16389 present",
                expected_requirement="NAT detection notifications",
            ))
        elif nat_src_present or nat_dst_present:
            results.append(RuleEvaluationResult(
                rule_id="IKE-NATT-DETECT-001",
                rfc="RFC 7296",
                section="§2.23",
                category=RuleCategory.CAT11_NAT_TRAVERSAL.value,
                condition="NAT detection notifications presence",
                requirement_level=RequirementLevel.MUST.value,
                applicable_context=ApplicableContext.HANDSHAKE.value,
                status=RuleStatus.WARNING,
                severity=Severity.LOW,
                reason="Only one NAT detection notification was supplied (expected both source and destination).",
                observed_value=f"Notify 16388={nat_src_present}, 16389={nat_dst_present}",
                expected_requirement="Both NAT detection notifications",
            ))
        else:
            results.append(RuleEvaluationResult(
                rule_id="IKE-NATT-DETECT-001",
                rfc="RFC 7296",
                section="§2.23",
                category=RuleCategory.CAT11_NAT_TRAVERSAL.value,
                condition="NAT detection notifications presence",
                requirement_level=RequirementLevel.MUST.value,
                applicable_context=ApplicableContext.HANDSHAKE.value,
                status=RuleStatus.NOT_VERIFIABLE,
                severity=Severity.LOW,
                reason="No NAT-D notifications observed.",
                observed_value=None,
                expected_requirement="NAT detection notifications",
            ))

        # Port floating verification: if port 4500 is used, NAT-T floating is active
        if src_port == 4500 or dst_port == 4500:
            results.append(RuleEvaluationResult(
                rule_id="IKE-NATT-PORTFLOAT-001",
                rfc="RFC 7296",
                section="§2.23",
                category=RuleCategory.CAT11_NAT_TRAVERSAL.value,
                condition="Port 4500 NAT traversal floating",
                requirement_level=RequirementLevel.MUST.value,
                applicable_context=ApplicableContext.HANDSHAKE.value,
                status=RuleStatus.PASS,
                severity=Severity.INFORMATIONAL,
                reason="Peers correctly transitioned to UDP port 4500 for NAT traversal.",
                observed_value=f"src_port={src_port}, dst_port={dst_port}",
                expected_requirement="UDP 4500 for NAT-T",
            ))
        elif src_port == 500 and dst_port == 500:
            results.append(RuleEvaluationResult(
                rule_id="IKE-NATT-PORTFLOAT-001",
                rfc="RFC 7296",
                section="§2.23",
                category=RuleCategory.CAT11_NAT_TRAVERSAL.value,
                condition="Standard UDP 500 operation (no NAT)",
                requirement_level=RequirementLevel.MUST.value,
                applicable_context=ApplicableContext.HANDSHAKE.value,
                status=RuleStatus.PASS,
                severity=Severity.INFORMATIONAL,
                reason="Peers operating over standard UDP 500 (native mode).",
                observed_value="UDP 500",
                expected_requirement="UDP 500 or 4500",
            ))
        else:
            results.append(RuleEvaluationResult(
                rule_id="IKE-NATT-PORTFLOAT-001",
                rfc="RFC 7296",
                section="§2.23",
                category=RuleCategory.CAT11_NAT_TRAVERSAL.value,
                condition="Port floating verification",
                requirement_level=RequirementLevel.MUST.value,
                applicable_context=ApplicableContext.HANDSHAKE.value,
                status=RuleStatus.NOT_VERIFIABLE,
                severity=Severity.LOW,
                reason="Ports were not supplied in the session header.",
                observed_value=None,
                expected_requirement="UDP 500 or 4500",
            ))

        return results

    # Static Child SA Proposals (RFC 8221)

    def _eval_static_child_sa(self, session: dict[str, Any]) -> list[RuleEvaluationResult]:
        results = []
        child_proposals = session.get("IKE_AUTH", {}).get("child_sa", {}).get("proposals", [])

        if not child_proposals:
            results.append(RuleEvaluationResult(
                rule_id="ESP-STATIC-PROPOSAL-001",
                rfc="RFC 7296",
                section="§1.2",
                category=RuleCategory.CAT8_ESP_IPSEC.value,
                condition="Child SA proposal presence in IKE_AUTH",
                requirement_level=RequirementLevel.MUST.value,
                applicable_context=ApplicableContext.HANDSHAKE.value,
                status=RuleStatus.NOT_VERIFIABLE,
                severity=Severity.LOW,
                reason="No Child SA proposals observed in IKE_AUTH.",
                observed_value=None,
                expected_requirement="Child SA proposal in IKE_AUTH",
            ))
            return results

        first_prop = child_proposals[0]
        tx = first_prop.get("transforms", {})
        encr_entry = self._first(tx.get("encryption", []))
        integ_entry = self._first(tx.get("integrity", []))

        if encr_entry is not None:
            encr_id = encr_entry.get("id")
            reg = ESP_ENCR_REGISTRY.get(encr_id)
            if reg:
                if reg["req_level"] == RequirementLevel.MUST_NOT:
                    results.append(RuleEvaluationResult(
                        rule_id="ESP-STATIC-ENCR-001",
                        rfc=reg["rfc"],
                        section=reg["section"],
                        category=RuleCategory.CAT8_ESP_IPSEC.value,
                        condition=f"Prohibited ESP encryption algorithm ({reg['name']})",
                        requirement_level=RequirementLevel.MUST_NOT.value,
                        applicable_context=ApplicableContext.HANDSHAKE.value,
                        status=RuleStatus.FAIL,
                        severity=Severity.CRITICAL,
                        reason=reg["reason"],
                        observed_value=reg["name"],
                        expected_requirement="MUST NOT be used in ESP",
                    ))
                else:
                    results.append(RuleEvaluationResult(
                        rule_id="ESP-STATIC-ENCR-001",
                        rfc=reg["rfc"],
                        section=reg["section"],
                        category=RuleCategory.CAT8_ESP_IPSEC.value,
                        condition=f"Compliant ESP encryption algorithm ({reg['name']})",
                        requirement_level=reg["req_level"].value,
                        applicable_context=ApplicableContext.HANDSHAKE.value,
                        status=RuleStatus.PASS,
                        severity=Severity.INFORMATIONAL,
                        reason=f"{reg['name']} satisfies RFC 8221 ESP requirements.",
                        observed_value=reg["name"],
                        expected_requirement=f"Requirement level: {reg['req_level'].value}",
                    ))

        # Check AEAD consistency in ESP
        if encr_entry is not None:
            encr_id = encr_entry.get("id")
            integ_id = integ_entry.get("id") if integ_entry else None
            is_aead = encr_id in AEAD_ENCR_IDS

            if is_aead:
                if integ_id is not None and integ_id != 0:
                    results.append(RuleEvaluationResult(
                        rule_id="ESP-STATIC-AEAD-001",
                        rfc="RFC 8221",
                        section="§2.1",
                        category=RuleCategory.CAT8_ESP_IPSEC.value,
                        condition="ESP AEAD integrity pairing",
                        requirement_level=RequirementLevel.MUST_NOT.value,
                        applicable_context=ApplicableContext.HANDSHAKE.value,
                        status=RuleStatus.FAIL,
                        severity=Severity.CRITICAL,
                        reason="ESP AEAD algorithm MUST NOT be paired with a separate integrity transform.",
                        observed_value=f"ENCR={encr_id}, INTEG={integ_id}",
                        expected_requirement="INTEG MUST be NONE (0)",
                    ))
                else:
                    results.append(RuleEvaluationResult(
                        rule_id="ESP-STATIC-AEAD-001",
                        rfc="RFC 8221",
                        section="§2.1",
                        category=RuleCategory.CAT8_ESP_IPSEC.value,
                        condition="ESP AEAD integrity pairing",
                        requirement_level=RequirementLevel.MUST.value,
                        applicable_context=ApplicableContext.HANDSHAKE.value,
                        status=RuleStatus.PASS,
                        severity=Severity.INFORMATIONAL,
                        reason="ESP AEAD algorithm correctly paired with INTEG NONE (0).",
                        observed_value=f"ENCR={encr_id}, INTEG=0",
                        expected_requirement="INTEG NONE (0)",
                    ))

        return results

    # Decoupled Security Posture, PQC, and Hybrid Classifications

    def evaluate_security_posture(self, session: dict[str, Any]) -> SecurityPosture:
        """Evaluate classical cryptographic posture (STRONG, ACCEPTABLE, WEAK, BROKEN)."""
        tx = self._get_init_transforms(session)
        encr_entry = self._first(tx.get("encryption", []))
        prf_entry = self._first(tx.get("prf", []))
        integ_entry = self._first(tx.get("integrity", []))
        dh_entry = self._first(tx.get("dh_group", []))

        encr_id = encr_entry.get("id") if encr_entry else None
        prf_id = prf_entry.get("id") if prf_entry else None
        integ_id = integ_entry.get("id") if integ_entry else None
        dh_id = dh_entry.get("id") if dh_entry else None

        # Check broken algorithms
        broken_encr = {1, 2, 4, 5, 6, 7, 8, 9, 11}
        broken_prf = {1, 2, 3}
        broken_integ = {1, 2, 3, 4, 6, 7}
        broken_dh = {0, 1, 2, 5, 22, 25, 26}

        if (encr_id in broken_encr or prf_id in broken_prf
                or (integ_id in broken_integ and encr_id not in AEAD_ENCR_IDS)
                or dh_id in broken_dh):
            return SecurityPosture.BROKEN

        # Check weak algorithms
        if encr_id == 3 or dh_id in (23, 24, 27):
            return SecurityPosture.WEAK

        # Check strong vs acceptable
        if encr_id in (20, 28) and prf_id in (5, 6, 7) and dh_id in (19, 20, 21, 31, 32):
            return SecurityPosture.STRONG

        if encr_id == 12 and dh_id in (14, 15, 16):
            return SecurityPosture.ACCEPTABLE

        return SecurityPosture.ACCEPTABLE

    def evaluate_pqc_status(self, session: dict[str, Any]) -> PqcClassification:
        """Determine PQC readiness (NONE, PQC_KEM, PPK, PQC_SIG, COMPOSITE)."""
        tx = self._get_init_transforms(session)
        notifs = set(session.get("notify", {}).get("notify_types", []))

        # Check DH group
        dh_entry = self._first(tx.get("dh_group", []))
        dh_id = dh_entry.get("id") if dh_entry else None

        if dh_id in (1035, 1036, 1037, 1038):
            return PqcClassification.COMPOSITE

        if dh_id in (35, 36, 37, 38, 39, 40):
            return PqcClassification.PQC_KEM

        # Check additional key exchange transforms (RFC 9370)
        for i in range(1, 8):
            for entry in tx.get(f"additional_key_exchange_{i}", []):
                ke_id = entry.get("id")
                if ke_id in (35, 36, 37, 38, 39, 40):
                    return PqcClassification.PQC_KEM

        # Check PPK (RFC 8784)
        if 16435 in notifs:  # USE_PPK
            return PqcClassification.PPK

        # Check PQC Signature
        sig_pqc_id = session.get("sig_pqc_id")
        if sig_pqc_id in PQC_SIG_ALGO_REGISTRY:
            return PqcClassification.PQC_SIG

        cert_key_oid = session.get("cert_key_type_oid") or session.get("IKE_AUTH", {}).get("certificate", {}).get("cert_key_type_oid")
        if cert_key_oid and cert_key_oid in CERT_KEY_TYPE_OIDS:
            if CERT_KEY_TYPE_OIDS[cert_key_oid].get("type") == "PQC":
                return PqcClassification.PQC_SIG

        return PqcClassification.NONE

    def evaluate_hybrid_status(self, session: dict[str, Any]) -> HybridClassification:
        """Determine whether the exchange genuinely combines classical and PQC mechanisms."""
        tx = self._get_init_transforms(session)
        notifs = set(session.get("notify", {}).get("notify_types", []))

        # Check direct composite KEM transform IDs
        dh_entry = self._first(tx.get("dh_group", []))
        dh_id = dh_entry.get("id") if dh_entry else None
        if dh_id in (1035, 1036, 1037, 1038):
            return HybridClassification.HYBRID

        # Check RFC 9370 Multiple Key Exchange combination:
        # Classical DH in primary KE + PQC KEM in additional KE
        is_primary_classical = (
            dh_id is not None
            and dh_id in IKEV2_DH_REGISTRY
            and IKEV2_DH_REGISTRY[dh_id].get("type") == "CLASSICAL"
        )

        has_additional_pqc = False
        for i in range(1, 8):
            for entry in tx.get(f"additional_key_exchange_{i}", []):
                ke_id = entry.get("id")
                if ke_id in (35, 36, 37, 38, 39, 40):
                    has_additional_pqc = True
                    break

        if is_primary_classical and has_additional_pqc:
            return HybridClassification.HYBRID

        # If only classical is present
        if is_primary_classical and not has_additional_pqc and 16435 not in notifs:
            return HybridClassification.NOT_HYBRID

        # If data is insufficient
        if dh_id is None:
            return HybridClassification.NOT_VERIFIABLE

        return HybridClassification.NOT_HYBRID

    # Internal Helpers

    def _get_init_transforms(self, session: dict[str, Any]) -> dict[str, list[dict]]:
        """Extract the transforms dictionary from the first IKE_SA_INIT proposal."""
        proposals = session.get("IKE_SA_INIT", {}).get("proposals", [])
        if proposals and isinstance(proposals, list):
            return proposals[0].get("transforms", {})
        return {}

    def _first(self, lst: list[dict], default: Any = None) -> dict | None:
        if lst and isinstance(lst, list) and len(lst) > 0:
            return lst[0]
        return default
