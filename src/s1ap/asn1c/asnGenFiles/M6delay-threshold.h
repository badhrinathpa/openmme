/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "./asn1c/S1AP-IEs.asn"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -findirect-choice -pdu=S1AP-PDU`
 */

#ifndef	_M6delay_threshold_H_
#define	_M6delay_threshold_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum M6delay_threshold {
	M6delay_threshold_ms30	= 0,
	M6delay_threshold_ms40	= 1,
	M6delay_threshold_ms50	= 2,
	M6delay_threshold_ms60	= 3,
	M6delay_threshold_ms70	= 4,
	M6delay_threshold_ms80	= 5,
	M6delay_threshold_ms90	= 6,
	M6delay_threshold_ms100	= 7,
	M6delay_threshold_ms150	= 8,
	M6delay_threshold_ms300	= 9,
	M6delay_threshold_ms500	= 10,
	M6delay_threshold_ms750	= 11
	/*
	 * Enumeration is extensible
	 */
} e_M6delay_threshold;

/* M6delay-threshold */
typedef long	 M6delay_threshold_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_M6delay_threshold_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_M6delay_threshold;
extern const asn_INTEGER_specifics_t asn_SPC_M6delay_threshold_specs_1;
asn_struct_free_f M6delay_threshold_free;
asn_struct_print_f M6delay_threshold_print;
asn_constr_check_f M6delay_threshold_constraint;
ber_type_decoder_f M6delay_threshold_decode_ber;
der_type_encoder_f M6delay_threshold_encode_der;
xer_type_decoder_f M6delay_threshold_decode_xer;
xer_type_encoder_f M6delay_threshold_encode_xer;
oer_type_decoder_f M6delay_threshold_decode_oer;
oer_type_encoder_f M6delay_threshold_encode_oer;
per_type_decoder_f M6delay_threshold_decode_uper;
per_type_encoder_f M6delay_threshold_encode_uper;
per_type_decoder_f M6delay_threshold_decode_aper;
per_type_encoder_f M6delay_threshold_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _M6delay_threshold_H_ */
#include <asn_internal.h>
