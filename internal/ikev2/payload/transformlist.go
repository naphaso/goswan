package payload

var (
	ENCR_AES_CBC_128 = Transform{
		Type:        TransformTypeEncr,
		TransformID: ID_ENCR_AES_CBC,
		KeyLength:   128,
	}
	ENCR_AES_CBC_192 = Transform{
		Type:        TransformTypeEncr,
		TransformID: ID_ENCR_AES_CBC,
		KeyLength:   192,
	}
	ENCR_AES_CBC_256 = Transform{
		Type:        TransformTypeEncr,
		TransformID: ID_ENCR_AES_CBC,
		KeyLength:   256,
	}
	ENCR_AES_CTR_128 = Transform{
		Type:        TransformTypeEncr,
		TransformID: ID_ENCR_AES_CTR,
		KeyLength:   128,
	}
	ENCR_AES_CTR_192 = Transform{
		Type:        TransformTypeEncr,
		TransformID: ID_ENCR_AES_CTR,
		KeyLength:   192,
	}
	ENCR_AES_CTR_256 = Transform{
		Type:        TransformTypeEncr,
		TransformID: ID_ENCR_AES_CTR,
		KeyLength:   256,
	}
	ENCR_CAMELLIA_CBC_128 = Transform{
		Type:        TransformTypeEncr,
		TransformID: ID_ENCR_CAMELLIA_CBC,
		KeyLength:   128,
	}
	ENCR_CAMELLIA_CBC_192 = Transform{
		Type:        TransformTypeEncr,
		TransformID: ID_ENCR_CAMELLIA_CBC,
		KeyLength:   192,
	}
	ENCR_CAMELLIA_CBC_256 = Transform{
		Type:        TransformTypeEncr,
		TransformID: ID_ENCR_CAMELLIA_CBC,
		KeyLength:   256,
	}
	ENCR_3DES = Transform{
		Type:        TransformTypeEncr,
		TransformID: ID_ENCR_3DES,
	}
	ENCR_AES_CCM_16_128 = Transform{
		Type:        TransformTypeEncr,
		TransformID: ID_ENCR_AES_CCM_16,
		KeyLength:   128,
	}
	ENCR_AES_CCM_16_192 = Transform{
		Type:        TransformTypeEncr,
		TransformID: ID_ENCR_AES_CCM_16,
		KeyLength:   192,
	}
	ENCR_AES_CCM_16_256 = Transform{
		Type:        TransformTypeEncr,
		TransformID: ID_ENCR_AES_CCM_16,
		KeyLength:   256,
	}
	ENCR_AES_GCM_16_128 = Transform{
		Type:        TransformTypeEncr,
		TransformID: ID_ENCR_AES_GCM_16,
		KeyLength:   128,
	}
	ENCR_AES_GCM_16_192 = Transform{
		Type:        TransformTypeEncr,
		TransformID: ID_ENCR_AES_GCM_16,
		KeyLength:   192,
	}
	ENCR_AES_GCM_16_256 = Transform{
		Type:        TransformTypeEncr,
		TransformID: ID_ENCR_AES_GCM_16,
		KeyLength:   256,
	}
	ENCR_CHACHA20_POLY1305 = Transform{
		Type:        TransformTypeEncr,
		TransformID: ID_ENCR_CHACHA20_POLY1305,
	}
	ENCR_AES_CCM_8_128 = Transform{
		Type:        TransformTypeEncr,
		TransformID: ID_ENCR_AES_CCM_8,
		KeyLength:   128,
	}
	ENCR_AES_CCM_8_192 = Transform{
		Type:        TransformTypeEncr,
		TransformID: ID_ENCR_AES_CCM_8,
		KeyLength:   192,
	}
	ENCR_AES_CCM_8_256 = Transform{
		Type:        TransformTypeEncr,
		TransformID: ID_ENCR_AES_CCM_8,
		KeyLength:   256,
	}
	ENCR_AES_CCM_12_128 = Transform{
		Type:        TransformTypeEncr,
		TransformID: ID_ENCR_AES_CCM_12,
		KeyLength:   128,
	}
	ENCR_AES_CCM_12_192 = Transform{
		Type:        TransformTypeEncr,
		TransformID: ID_ENCR_AES_CCM_12,
		KeyLength:   192,
	}
	ENCR_AES_CCM_12_256 = Transform{
		Type:        TransformTypeEncr,
		TransformID: ID_ENCR_AES_CCM_12,
		KeyLength:   256,
	}
	ENCR_AES_GCM_8_128 = Transform{
		Type:        TransformTypeEncr,
		TransformID: ID_ENCR_AES_GCM_8,
		KeyLength:   128,
	}
	ENCR_AES_GCM_8_192 = Transform{
		Type:        TransformTypeEncr,
		TransformID: ID_ENCR_AES_GCM_8,
		KeyLength:   192,
	}
	ENCR_AES_GCM_8_256 = Transform{
		Type:        TransformTypeEncr,
		TransformID: ID_ENCR_AES_GCM_8,
		KeyLength:   256,
	}
	ENCR_AES_GCM_12_128 = Transform{
		Type:        TransformTypeEncr,
		TransformID: ID_ENCR_AES_GCM_12,
		KeyLength:   128,
	}
	ENCR_AES_GCM_12_192 = Transform{
		Type:        TransformTypeEncr,
		TransformID: ID_ENCR_AES_GCM_12,
		KeyLength:   192,
	}
	ENCR_AES_GCM_12_256 = Transform{
		Type:        TransformTypeEncr,
		TransformID: ID_ENCR_AES_GCM_12,
		KeyLength:   256,
	}

	// integrity algorithms
	INTEG_AUTH_HMAC_SHA2_256_128 = Transform{
		Type:        TransformTypeInteg,
		TransformID: ID_INTEG_AUTH_HMAC_SHA2_256_128,
	}
	INTEG_AUTH_HMAC_SHA2_384_192 = Transform{
		Type:        TransformTypeInteg,
		TransformID: ID_INTEG_AUTH_HMAC_SHA2_384_192,
	}
	INTEG_AUTH_HMAC_SHA2_512_256 = Transform{
		Type:        TransformTypeInteg,
		TransformID: ID_INTEG_AUTH_HMAC_SHA2_512_256,
	}
	INTEG_AUTH_AES_XCBC_96 = Transform{
		Type:        TransformTypeInteg,
		TransformID: ID_INTEG_AUTH_AES_XCBC_96,
	}
	INTEG_AUTH_AES_CMAC_96 = Transform{
		Type:        TransformTypeInteg,
		TransformID: ID_INTEG_AUTH_AES_CMAC_96,
	}
	INTEG_AUTH_HMAC_SHA1_96 = Transform{
		Type:        TransformTypeInteg,
		TransformID: ID_INTEG_AUTH_HMAC_SHA1_96,
	}

	// PRF algorithms
	PRF_HMAC_SHA1 = Transform{
		Type:        TransformTypePRF,
		TransformID: ID_PRF_HMAC_SHA1,
	}
	PRF_AES_128_CBC = Transform{
		Type:        TransformTypePRF,
		TransformID: ID_PRF_AES_128_CBC,
	}
	PRF_HMAC_SHA2_256 = Transform{
		Type:        TransformTypePRF,
		TransformID: ID_PRF_HMAC_SHA2_256,
	}
	PRF_HMAC_SHA2_384 = Transform{
		Type:        TransformTypePRF,
		TransformID: ID_PRF_HMAC_SHA2_384,
	}
	PRF_HMAC_SHA2_512 = Transform{
		Type:        TransformTypePRF,
		TransformID: ID_PRF_HMAC_SHA2_512,
	}
	PRF_AES_128_CMAC6 = Transform{
		Type:        TransformTypePRF,
		TransformID: ID_PRF_AES_128_CMAC6,
	}

	// DH parameters
	DH_MODP_2048 = Transform{
		Type:        TransformTypeDH,
		TransformID: ID_DH_MODP_2048,
	}
	DH_MODP_3072 = Transform{
		Type:        TransformTypeDH,
		TransformID: ID_DH_MODP_3072,
	}
	DH_MODP_4096 = Transform{
		Type:        TransformTypeDH,
		TransformID: ID_DH_MODP_4096,
	}
	DH_MODP_6144 = Transform{
		Type:        TransformTypeDH,
		TransformID: ID_DH_MODP_6144,
	}
	DH_MODP_8192 = Transform{
		Type:        TransformTypeDH,
		TransformID: ID_DH_MODP_8192,
	}
	DH_ECP_RANDOM_256 = Transform{
		Type:        TransformTypeDH,
		TransformID: ID_DH_ECP_RANDOM_256,
	}
	DH_ECP_RANDOM_384 = Transform{
		Type:        TransformTypeDH,
		TransformID: ID_DH_ECP_RANDOM_384,
	}
	DH_ECP_RANDOM_521 = Transform{
		Type:        TransformTypeDH,
		TransformID: ID_DH_ECP_RANDOM_521,
	}
	DH_ECP_BRAINPOOL_256 = Transform{
		Type:        TransformTypeDH,
		TransformID: ID_DH_ECP_BRAINPOOL_256,
	}
	DH_ECP_BRAINPOOL_384 = Transform{
		Type:        TransformTypeDH,
		TransformID: ID_DH_ECP_BRAINPOOL_384,
	}
	DH_ECP_BRAINPOOL_512 = Transform{
		Type:        TransformTypeDH,
		TransformID: ID_DH_ECP_BRAINPOOL_512,
	}
	DH_CURVE25519 = Transform{
		Type:        TransformTypeDH,
		TransformID: ID_DH_CURVE25519,
	}
	DH_CURVE448 = Transform{
		Type:        TransformTypeDH,
		TransformID: ID_DH_CURVE448,
	}
	DH_NTRU_112 = Transform{
		Type:        TransformTypeDH,
		TransformID: ID_DH_NTRU_112,
	}
	DH_NTRU_128 = Transform{
		Type:        TransformTypeDH,
		TransformID: ID_DH_NTRU_128,
	}
	DH_NTRU_192 = Transform{
		Type:        TransformTypeDH,
		TransformID: ID_DH_NTRU_192,
	}
	DH_NTRU_256 = Transform{
		Type:        TransformTypeDH,
		TransformID: ID_DH_NTRU_256,
	}
	DH_NEWHOPE_128 = Transform{
		Type:        TransformTypeDH,
		TransformID: ID_DH_NEWHOPE_128,
	}
)
