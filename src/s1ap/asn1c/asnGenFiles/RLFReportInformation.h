/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "./asn1c/S1AP-IEs.asn"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -findirect-choice -pdu=S1AP-PDU`
 */

#ifndef	_RLFReportInformation_H_
#define	_RLFReportInformation_H_


#include <asn_application.h>

/* Including external dependencies */
#include "UE-RLF-Report-Container.h"
#include "UE-RLF-Report-Container-for-extended-bands.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ProtocolExtensionContainer;

/* RLFReportInformation */
typedef struct RLFReportInformation {
	UE_RLF_Report_Container_t	 uE_RLF_Report_Container;
	UE_RLF_Report_Container_for_extended_bands_t	*uE_RLF_Report_Container_for_extended_bands;	/* OPTIONAL */
	struct ProtocolExtensionContainer	*iE_Extensions;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RLFReportInformation_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RLFReportInformation;
extern asn_SEQUENCE_specifics_t asn_SPC_RLFReportInformation_specs_1;
extern asn_TYPE_member_t asn_MBR_RLFReportInformation_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _RLFReportInformation_H_ */
#include <asn_internal.h>
