/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-PDU-Contents"
 * 	found in "./asn1c/S1AP-PDU-Contents.asn"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -findirect-choice -pdu=S1AP-PDU`
 */

#ifndef	_E_RABAdmittedList_H_
#define	_E_RABAdmittedList_H_


#include <asn_application.h>

/* Including external dependencies */
#include "E-RAB-IE-ContainerList.h"

#ifdef __cplusplus
extern "C" {
#endif

/* E-RABAdmittedList */
typedef E_RAB_IE_ContainerList_456P2_t	 E_RABAdmittedList_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_E_RABAdmittedList_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_E_RABAdmittedList;
asn_struct_free_f E_RABAdmittedList_free;
asn_struct_print_f E_RABAdmittedList_print;
asn_constr_check_f E_RABAdmittedList_constraint;
ber_type_decoder_f E_RABAdmittedList_decode_ber;
der_type_encoder_f E_RABAdmittedList_encode_der;
xer_type_decoder_f E_RABAdmittedList_decode_xer;
xer_type_encoder_f E_RABAdmittedList_encode_xer;
oer_type_decoder_f E_RABAdmittedList_decode_oer;
oer_type_encoder_f E_RABAdmittedList_encode_oer;
per_type_decoder_f E_RABAdmittedList_decode_uper;
per_type_encoder_f E_RABAdmittedList_encode_uper;
per_type_decoder_f E_RABAdmittedList_decode_aper;
per_type_encoder_f E_RABAdmittedList_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _E_RABAdmittedList_H_ */
#include <asn_internal.h>
