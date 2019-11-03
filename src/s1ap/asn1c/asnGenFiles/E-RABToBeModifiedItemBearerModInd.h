/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-PDU-Contents"
 * 	found in "./asn1c/S1AP-PDU-Contents.asn"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -findirect-choice -pdu=S1AP-PDU`
 */

#ifndef	_E_RABToBeModifiedItemBearerModInd_H_
#define	_E_RABToBeModifiedItemBearerModInd_H_


#include <asn_application.h>

/* Including external dependencies */
#include "E-RAB-ID.h"
#include "TransportLayerAddress.h"
#include "GTP-TEID.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ProtocolExtensionContainer;

/* E-RABToBeModifiedItemBearerModInd */
typedef struct E_RABToBeModifiedItemBearerModInd {
	E_RAB_ID_t	 e_RAB_ID;
	TransportLayerAddress_t	 transportLayerAddress;
	GTP_TEID_t	 dL_GTP_TEID;
	struct ProtocolExtensionContainer	*iE_Extensions;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} E_RABToBeModifiedItemBearerModInd_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_E_RABToBeModifiedItemBearerModInd;
extern asn_SEQUENCE_specifics_t asn_SPC_E_RABToBeModifiedItemBearerModInd_specs_1;
extern asn_TYPE_member_t asn_MBR_E_RABToBeModifiedItemBearerModInd_1[4];

#ifdef __cplusplus
}
#endif

#endif	/* _E_RABToBeModifiedItemBearerModInd_H_ */
#include <asn_internal.h>
