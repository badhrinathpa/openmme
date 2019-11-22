/*
 * Copyright (c) 2003-2018, Great Software Laboratory Pvt. Ltd.
 * Copyright (c) 2017 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

#include "options.h"
#include "ipc_api.h"
#include "main.h"
#include "s1ap.h"
#include "s1ap_config.h"
#include "sctp_conn.h"
#include "s1ap_structs.h"
#include "s1ap_msg_codes.h"
#include "s1ap_ie.h"
#include "ProtocolIE-ID.h"
#include "ProtocolIE-Field.h"
#include "s11_common_proc_info.h"
#include "InitiatingMessage.h"
#include "UE-S1AP-ID-pair.h"

//------------------------------------------------------------------------------
int s1ap_mme_encode_initiating(
  struct s1ap_common_req_Q_msg *message_p,
  uint8_t **buffer,
  uint32_t *length)
{
    log_msg(LOG_INFO, "MME initiating msg Encode.\n");
    switch (message_p->IE_type) {
        case S1AP_CTX_REL_CMD:
            log_msg(LOG_INFO, "Ue Context release Command Encode.\n");
            return s1ap_mme_encode_ue_context_release_command(
                      message_p, buffer, length);
        default:
            log_msg(
                  LOG_WARNING,
                  "Unknown procedure ID (%d) for initiating message_p\n",
                  (int) message_p->IE_type);
      }

  return -1;
}

int s1ap_mme_encode_ue_context_release_command(
  struct s1ap_common_req_Q_msg *s1apPDU,
  uint8_t **buffer,
  uint32_t *length)
{
	S1AP_PDU_t                              pdu = {(S1AP_PDU_PR_NOTHING)};
    InitiatingMessage_t *initiating_msg = NULL;
	S1AP_PDU_t                             *pdu_p = &pdu;
	int                                     enc_ret = -1;
	memset ((void *)pdu_p, 0, sizeof (S1AP_PDU_t));

    pdu.present = S1AP_PDU_PR_initiatingMessage;
    pdu.choice.initiatingMessage = (InitiatingMessage_t*)malloc(sizeof(InitiatingMessage_t));
    if(pdu.choice.initiatingMessage == NULL)
    {
        log_msg(LOG_ERROR,"malloc failed.\n");
        return -1;
    }
    initiating_msg = pdu.choice.initiatingMessage;
    initiating_msg->procedureCode = ProcedureCode_id_UEContextRelease;
    initiating_msg->criticality = 0;
    initiating_msg->value.present = InitiatingMessage__value_PR_UEContextReleaseCommand;  
    //proto_c = &initiating_msg->value.choice.UEContextReleaseCommand.protocolIEs;
            
    UEContextReleaseCommand_IEs_t val[2];
    UE_S1AP_IDs_t ue_id_val;
    struct UE_S1AP_ID_pair s1apId_pair;
    if((s1apPDU->mme_s1ap_ue_id != 0xFFFFFFFF) 
        && (s1apPDU->enb_s1ap_ue_id != 0xFFFFFFFF))
    {
        log_msg(LOG_INFO,"S1ap Id pair.\n");
        ue_id_val.present = UE_S1AP_IDs_PR_uE_S1AP_ID_pair;
        s1apId_pair.eNB_UE_S1AP_ID = s1apPDU->enb_s1ap_ue_id;
        s1apId_pair.mME_UE_S1AP_ID = s1apPDU->mme_s1ap_ue_id;
        ue_id_val.choice.uE_S1AP_ID_pair = (struct UE_S1AP_ID_pair*)malloc(sizeof(struct UE_S1AP_ID_pair));
        if(ue_id_val.choice.uE_S1AP_ID_pair == NULL)
        {
            log_msg(LOG_ERROR,"malloc failed.\n");
            free(pdu.choice.initiatingMessage);
            return -1;
        }
        memcpy(ue_id_val.choice.uE_S1AP_ID_pair, &s1apId_pair, sizeof(struct UE_S1AP_ID_pair));
    }
    else if(s1apPDU->mme_s1ap_ue_id != 0xFFFFFFFF)
    {
        ue_id_val.present = UE_S1AP_IDs_PR_mME_UE_S1AP_ID;
        ue_id_val.choice.mME_UE_S1AP_ID = s1apPDU->mme_s1ap_ue_id;
    }
    else
    {
        ue_id_val.present = UE_S1AP_IDs_PR_NOTHING;
    }

    val[0].id = ProtocolIE_ID_id_UE_S1AP_IDs;
    val[0].criticality = 0;
    val[0].value.present = UEContextReleaseCommand_IEs__value_PR_UE_S1AP_IDs;
    memcpy(&val[0].value.choice.UE_S1AP_IDs, &ue_id_val, sizeof(UE_S1AP_IDs_t));

    val[1].id = ProtocolIE_ID_id_Cause;
    val[1].criticality = 1;
    val[1].value.present = UEContextReleaseCommand_IEs__value_PR_Cause;
    //memcpy(&val[1].value.choice.Cause, &s1apPDU->cause, sizeof(Cause_t));
    val[1].value.choice.Cause.present = s1apPDU->cause.present;
    switch(s1apPDU->cause.present)
    {
        case Cause_PR_radioNetwork:
            val[1].value.choice.Cause.choice.radioNetwork
                = s1apPDU->cause.choice.radioNetwork;
        break;
        case Cause_PR_transport:
            val[1].value.choice.Cause.choice.transport
                = s1apPDU->cause.choice.transport;
        break;
        case Cause_PR_nas:
            val[1].value.choice.Cause.choice.nas
                = s1apPDU->cause.choice.nas;
        break;
        case Cause_PR_protocol:
            val[1].value.choice.Cause.choice.protocol
                = s1apPDU->cause.choice.protocol;
        break;
        case Cause_PR_misc:
            val[1].value.choice.Cause.choice.misc
                = s1apPDU->cause.choice.misc;
        break;
        case Cause_PR_NOTHING:
        default:
            log_msg(LOG_WARNING,"Unknown Cause type:%d\n",s1apPDU->cause.present);
    }

    log_msg(LOG_INFO,"Add values to list.\n");
    ASN_SEQUENCE_ADD(&initiating_msg->value.choice.UEContextReleaseCommand.protocolIEs.list, &val[0]);
    ASN_SEQUENCE_ADD(&initiating_msg->value.choice.UEContextReleaseCommand.protocolIEs.list, &val[1]);

    if ((enc_ret = aper_encode_to_new_buffer (&asn_DEF_S1AP_PDU, 0, &pdu, (void **)buffer)) < 0) 
    {
        log_msg(LOG_ERROR, "Encoding of Ctx Release Cmd failed\n");
        return -1;
    }

    log_msg(LOG_INFO,"free allocated msgs");
    free(ue_id_val.choice.uE_S1AP_ID_pair);
    free(pdu.choice.initiatingMessage);
    
    *length = enc_ret;
    return enc_ret; 
}
