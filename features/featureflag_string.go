// Code generated by "stringer -type=FeatureFlag"; DO NOT EDIT.

package features

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[unused-0]
	_ = x[PerformValidationRPC-1]
	_ = x[ACME13KeyRollover-2]
	_ = x[SimplifiedVAHTTP-3]
	_ = x[TLSSNIRevalidation-4]
	_ = x[AllowRenewalFirstRL-5]
	_ = x[SetIssuedNamesRenewalBit-6]
	_ = x[FasterRateLimit-7]
	_ = x[ProbeCTLogs-8]
	_ = x[RevokeAtRA-9]
	_ = x[NewAuthorizationSchema-10]
	_ = x[DisableAuthz2Orders-11]
	_ = x[EarlyOrderRateLimit-12]
	_ = x[FasterGetOrderForNames-13]
	_ = x[PrecertificateOCSP-14]
	_ = x[CAAValidationMethods-15]
	_ = x[CAAAccountURI-16]
	_ = x[HeadNonceStatusOK-17]
	_ = x[EnforceMultiVA-18]
	_ = x[MultiVAFullResults-19]
	_ = x[RemoveWFE2AccountID-20]
	_ = x[CheckRenewalFirst-21]
	_ = x[MandatoryPOSTAsGET-22]
	_ = x[AllowV1Registration-23]
	_ = x[ParallelCheckFailedValidation-24]
	_ = x[DeleteUnusedChallenges-25]
	_ = x[V1DisableNewValidations-26]
	_ = x[PrecertificateRevocation-27]
	_ = x[StripDefaultSchemePort-28]
	_ = x[GetAuthorizationsPerf-29]
}

const _FeatureFlag_name = "unusedPerformValidationRPCACME13KeyRolloverSimplifiedVAHTTPTLSSNIRevalidationAllowRenewalFirstRLSetIssuedNamesRenewalBitFasterRateLimitProbeCTLogsRevokeAtRANewAuthorizationSchemaDisableAuthz2OrdersEarlyOrderRateLimitFasterGetOrderForNamesPrecertificateOCSPCAAValidationMethodsCAAAccountURIHeadNonceStatusOKEnforceMultiVAMultiVAFullResultsRemoveWFE2AccountIDCheckRenewalFirstMandatoryPOSTAsGETAllowV1RegistrationParallelCheckFailedValidationDeleteUnusedChallengesV1DisableNewValidationsPrecertificateRevocationStripDefaultSchemePortGetAuthorizationsPerf"

var _FeatureFlag_index = [...]uint16{0, 6, 26, 43, 59, 77, 96, 120, 135, 146, 156, 178, 197, 216, 238, 256, 276, 289, 306, 320, 338, 357, 374, 392, 411, 440, 462, 485, 509, 531, 552}

func (i FeatureFlag) String() string {
	if i < 0 || i >= FeatureFlag(len(_FeatureFlag_index)-1) {
		return "FeatureFlag(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _FeatureFlag_name[_FeatureFlag_index[i]:_FeatureFlag_index[i+1]]
}
