package payload

// currently there is only one attribute type, in TV format, it's key value, so we just skip this abstraction

type TransformType uint8

const (
	TransformTypeEncr  TransformType = 1
	TransformTypePRF                 = 2
	TransformTypeInteg               = 3
	TransformTypeDH                  = 4
)

type TransformID uint16

const (
	ID_ENCR_3DES              = 3
	ID_ENCR_AES_CBC           = 12
	ID_ENCR_AES_CTR           = 13
	ID_ENCR_AES_CCM_8         = 14
	ID_ENCR_AES_CCM_12        = 15
	ID_ENCR_AES_CCM_16        = 16
	ID_ENCR_AES_GCM_8         = 18
	ID_ENCR_AES_GCM_12        = 19
	ID_ENCR_AES_GCM_16        = 20
	ID_ENCR_CAMELLIA_CBC      = 23
	ID_ENCR_CHACHA20_POLY1305 = 28

	ID_INTEG_AUTH_HMAC_SHA2_256_128 = 12
	ID_INTEG_AUTH_HMAC_SHA2_384_192 = 13
	ID_INTEG_AUTH_HMAC_SHA2_512_256 = 14
	ID_INTEG_AUTH_AES_XCBC_96       = 5
	ID_INTEG_AUTH_AES_CMAC_96       = 8
	ID_INTEG_AUTH_HMAC_SHA1_96      = 2

	ID_PRF_HMAC_SHA1     = 2
	ID_PRF_AES_128_CBC   = 4
	ID_PRF_HMAC_SHA2_256 = 5
	ID_PRF_HMAC_SHA2_384 = 6
	ID_PRF_HMAC_SHA2_512 = 7
	ID_PRF_AES_128_CMAC6 = 8

	ID_DH_MODP_2048         = 14
	ID_DH_MODP_3072         = 15
	ID_DH_MODP_4096         = 16
	ID_DH_MODP_6144         = 17
	ID_DH_MODP_8192         = 18
	ID_DH_ECP_RANDOM_256    = 19
	ID_DH_ECP_RANDOM_384    = 20
	ID_DH_ECP_RANDOM_521    = 21
	ID_DH_ECP_BRAINPOOL_256 = 28
	ID_DH_ECP_BRAINPOOL_384 = 29
	ID_DH_ECP_BRAINPOOL_512 = 30
	ID_DH_CURVE25519        = 31
	ID_DH_CURVE448          = 32

	// extensions
	ID_DH_NTRU_112 = 1030
	ID_DH_NTRU_128 = 1031
	ID_DH_NTRU_192 = 1032
	ID_DH_NTRU_256 = 1033

	ID_DH_NEWHOPE_128 = 1040
)

type Transform struct {
	Critical    bool
	Type        TransformType
	TransformID TransformID
	KeyLength   uint16

	Data []byte
}
