/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-PDU-Contents"
 * 	found in "./asn1c/S1AP-PDU-Contents.asn"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -findirect-choice -pdu=S1AP-PDU`
 */

#ifndef	_LocationReportingControl_H_
#define	_LocationReportingControl_H_


#include <asn_application.h>

/* Including external dependencies */
#include "ProtocolIE-Container.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* LocationReportingControl */
typedef struct LocationReportingControl {
	ProtocolIE_Container_129P58_t	 protocolIEs;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LocationReportingControl_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LocationReportingControl;

#ifdef __cplusplus
}
#endif

#endif	/* _LocationReportingControl_H_ */
#include <asn_internal.h>