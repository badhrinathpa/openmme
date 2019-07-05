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
#include <pthread.h>
#include <string.h>
#include <unistd.h>

#include "mme_app.h"
#include "ue_table.h"
#include "err_codes.h"
#include "message_queues.h"
#include "stage1_info.h"
#include "ipc_api.h"
#include "stage1_s6a_msg.h"
#include "monitor_message.h"
#include "unix_conn.h"

/************************************************************************
Current file : Stage 1 handler.
ATTACH stages :
-->	Stage 1 : IAM-->[stage1 handler]-->AIR, ULR
	Stage 2 : AIA, ULA -->[stage2 handler]--> Auth req
	Stage 3 : Auth resp-->[stage1 handler]-->Sec mode cmd
	Stage 4 : sec mode resp-->[stage1 handler]-->esm infor req
	Stage 5 : esm infor resp-->[stage1 handler]-->create session
	Stage 6 : create session resp-->[stage1 handler]-->init ctx setup
	Stage 7 : attach complete-->[stage1 handler]-->modify bearer
**************************************************************************/

/****Globals and externs ***/

extern struct UE_info * g_UE_list[];
extern int g_UE_cnt;
extern int g_mme_hdlr_status;

/*source Q : Read feom*/
static int g_Q1_fd;

/*Destination Q : Write to*/
static int g_Q_s6a_air;
//static int g_Q_s6a_ulr;

/*Making global just to avoid stack passing*/
static char buf[INITUE_STAGE1_BUF_SIZE];
static struct s6a_Q_msg s6a_req;

extern mme_config g_mme_cfg;
extern uint32_t attach_stage1_counter;
/****Global and externs end***/

/**
Initialize the stage settings, Q,
destination communication etc.
*/
static void
init_stage()
{
	if ((g_Q1_fd  = open_ipc_channel(INITUE_STAGE1_QUEUE, IPC_READ)) == -1){
		log_msg(LOG_ERROR, "Error in opening reader stage 1 IPC channel : %s\n",
			INITUE_STAGE1_QUEUE);
		pthread_exit(NULL);
	}
	log_msg(LOG_INFO, "Stage1 reader - init UE msg: Connected.\n");

	log_msg(LOG_INFO, "Stage1 writer - AIR: waiting.\n");
	/*Open destination queue for writing. It is AIR, ULR Q in this stage*/
	g_Q_s6a_air = open_ipc_channel(S6A_REQ_STAGE1_QUEUE, IPC_WRITE);

	if (g_Q_s6a_air == -1) {
		log_msg(LOG_ERROR, "Error in opening Writer IPC channel: S6A - AIR\n");
		pthread_exit(NULL);
	}
	log_msg(LOG_INFO, "Stage1 writer - AIR: Connected\n");
	return;
}

/**
* Read next message from stage Q for processing.
*/
static int
read_next_msg()
{
	int bytes_read=0;

	memset(buf, 0, INITUE_STAGE1_BUF_SIZE);
	while (bytes_read < INITUE_STAGE1_BUF_SIZE) {//TODO : Recheck condition
		if ((bytes_read = read_ipc_channel(
			g_Q1_fd, buf, INITUE_STAGE1_BUF_SIZE)) == -1) {
			log_msg(LOG_ERROR, "Error in reading \n");
			/* TODO : Add proper error handling */
		}
		log_msg(LOG_INFO, "Init UE Message Received: %d", bytes_read);
	}

	return bytes_read;
}

void
handle_monitor_imsi_req(struct monitor_imsi_req *mir, int sock_fd)
{
	struct monitor_imsi_rsp mia = {0};
	struct UE_info *ue_entry = NULL;

    for(int i = 0;i <= g_UE_cnt;i++)
	{
	    ue_entry = GET_UE_ENTRY(i);
	    if(ue_entry && 
	       (UNASSIGNED_ENTRY != ue_entry->ue_state))
        { 
           char imsi[16] = {0};
           mia.result = 2;

	       /*Parse and validate  the buffer*/
           imsi_bin_to_str(ue_entry->IMSI, imsi);
           log_msg(LOG_ERROR, "imsi: %s", imsi);
           if(strcmp((const char *)imsi, 
                     (const char*)mir->imsi) == 0)
           {
               mia.bearer_id = ue_entry->bearer_id;
               mia.result = 1;
               memcpy(mia.imsi, imsi, IMSI_STR_LEN);
               memcpy(&mia.tai, &ue_entry->tai, sizeof(struct TAI));
               memcpy(&mia.ambr, &ue_entry->ambr, sizeof(struct AMBR));
               /*memcpy(&mia.s11_sgw_c_fteid, &ue_entry->s11_sgw_c_fteid, sizeof(struct fteid));
                 memcpy(&mia.s5s8_pgw_c_fteid, &ue_entry->s5s8_pgw_c_fteid, sizeof(struct fteid));
                 memcpy(&mia.s1u_sgw_u_fteid, &ue_entry->s1u_sgw_u_fteid, sizeof(struct fteid));
                 memcpy(&mia.s5s8_pgw_u_fteid, &ue_entry->s5s8_pgw_u_fteid, sizeof(struct fteid));
                 memcpy(&mia.s1u_enb_u_fteid, &ue_entry->s1u_enb_u_fteid, sizeof(struct fteid));*/
               break; 
           }
	    }
	}
	
	unsigned char buf[BUFFER_SIZE] = {0};
	struct monitor_resp_msg resp;
	resp.hdr = MONITOR_IMSI_RSP;
        //resp.result = 0;
	memcpy(&resp.data.mia, &mia, 
	      sizeof(struct monitor_imsi_rsp));
	//memcpy(buf, &resp, sizeof(struct monitor_resp_msg));
	memcpy(buf, &mia, sizeof(struct monitor_imsi_rsp));
	//send_unix_msg(sock_fd, buf, sizeof(struct monitor_resp_msg));
	send_unix_msg(sock_fd, buf, sizeof(struct monitor_imsi_rsp));

	return;
}

void
handle_imsi_list_req(struct monitor_imsi_req *mir, int sock_fd)
{
	struct monitor_imsi_list_rsp mia = {0};
	struct UE_info *ue_entry = NULL;

    char** imsi_list = (char**)malloc(sizeof(char*) * g_UE_cnt);
    if(imsi_list)
    {
        mia.no_of_ue = g_UE_cnt;
        mia.imsi_list = (unsigned char**)imsi_list;
        for(int i = 0, j=0;i <= g_UE_cnt;i++)
        {
            ue_entry = GET_UE_ENTRY(i);
            if(ue_entry && 
               (UNASSIGNED_ENTRY != ue_entry->ue_state))
            { 
                char* imsiVal = (char*)malloc(sizeof(char)*16);
                char imsi[16] = {0};

                imsi_bin_to_str(ue_entry->IMSI, imsi);
                if(imsiVal)
                {
                    memcpy(imsiVal, imsi, IMSI_STR_LEN);
                    imsi_list[j++] = imsiVal;
                }
            }
        }
    }
	
	unsigned char buf[BUFFER_SIZE] = {0};
	memcpy(buf, &mia.no_of_ue, sizeof(int));
    char* bufPtr = (char*)buf + sizeof(int);
    int size = sizeof(int);
    for(int i = 0;i< mia.no_of_ue;i++)
    {
        memcpy(bufPtr, mia.imsi_list[i], IMSI_STR_LEN);
        bufPtr += IMSI_STR_LEN;
        size += IMSI_STR_LEN;
    }
	
    send_unix_msg(sock_fd, buf, size);

	return;
}


/**
* Monitor message processing.
*/
void
handle_monitor_processing(void *message)
{
        log_msg(LOG_INFO, "Monitor Message Received");
	int sock_fd = 0;
	memcpy(&sock_fd, (char*)message, sizeof(int));
	char *msg = ((char *) message) + (sizeof(int));
	/*struct monitor_req_msg *msg = (struct monitor_req_msg*)message + sizeof(sock_fd);
	switch(msg->hdr){
	case MONITOR_IMSI_REQ:
		handle_monitor_imsi_req((struct monitor_imsi_req *)&(msg->data.mir), sock_fd);
		break;

	default:
		log_msg(LOG_ERROR, "Unknown message received from HSS - %d\n",
			msg->hdr);
	}*/
	struct monitor_imsi_req* mir = (struct monitor_imsi_req*)msg;
    switch(mir->req_type)
    {
        case 0:
            {
	            handle_monitor_imsi_req(mir, sock_fd);
                break;
            }
        case 1:
            {
	            handle_imsi_list_req(mir, sock_fd);
                break;
            }
            
    }

	/*free allocated message buffer*/
	free(message);
	return;
}

/**
* Stage specific message processing.
*/
static int
stage1_processing()
{
	struct ue_attach_info *ue_info = (struct ue_attach_info*)buf;
	int index = ++g_UE_cnt;
	struct UE_info *ue_entry = NULL;



	if (index%UE_POOL_CNT == 0) {

		log_msg(LOG_INFO, "UE Buffer Pool is full \n");
		g_UE_cnt--;
		index = get_index_from_list();

		if (index != -1) {
			log_msg(LOG_INFO, "Index is  received from the list\n");
		} else {
			log_msg(LOG_ERROR, "Error: No Index found in the list \n");
			exit(-1);
		}

	}

	/*Parse and validate  the buffer*/
	if (NULL == ue_info) {
		/*Error case handling. This should be handled in s1ap only.*/
		return E_FAIL;
	}

	/**TODO
	Find the UE if already exists in hash
	Delete exisint UE entry.
	*/

	/*Allocate new UE entry in the hash*/
	/*Copy UE information*/
	ue_entry = GET_UE_ENTRY(index);
	ue_entry->ue_state = ATTACH_STAGE1;
	ue_entry->s1ap_enb_ue_id = ue_info->s1ap_enb_ue_id;
	ue_entry->enb_fd = ue_info->enb_fd;
	ue_entry->esm_info_tx_required = ue_info->esm_info_tx_required;

	memcpy(&(ue_entry->IMSI), &(ue_info->IMSI),
		BINARY_IMSI_LEN);
	memcpy(&(ue_entry->tai), &(ue_info->tai),
		sizeof(struct TAI));
	memcpy(&(ue_entry->utran_cgi), &(ue_info->utran_cgi),
		sizeof(struct CGI));
	//g_UE_list[0][index].rrc_cause = info->ue_info.rrc_cause;
	memcpy(&(ue_entry->ue_net_capab), &(ue_info->ue_net_capab),
		sizeof(struct UE_net_capab));
	memcpy(&(ue_entry->ms_net_capab), &(ue_info->ms_net_capab),
		sizeof(struct MS_net_capab));
	memcpy(&(ue_entry->pti), &(ue_info->pti), 1);

	ue_entry->bearer_id = 5;

	/*Collect information for next processing*/
	//memcpy(&(s6a_req.imsi), gUE_list[0][index].imsi, 8);
	memcpy(&(s6a_req.imsi), &(ue_info->IMSI), BINARY_IMSI_LEN);
	memcpy(&(s6a_req.tai), &(ue_info->tai), sizeof(struct TAI));
	s6a_req.ue_idx = index;

	/*post to next processing*/

	return SUCCESS;
}

#if 0
void
create_dummy_msg()
{
	memcpy(&(s6a_req.imsi), "208014567891234", 16);
	s6a_req.tai.plmn_id = g_mme_cfg.plmn_id;
	s6a_req.tai.tac = 10;
	//struct PLMN visited_plmn;
	/*e-utran auth info??*/
	s6a_req.ue_idx = 123;
}
#endif

/**
* Post message to next handler of the stage
*/
static int
post_to_next()
{
	//test create_dummy_msg();
	write_ipc_channel(g_Q_s6a_air, (char *)&(s6a_req), S6A_REQ_Q_MSG_SIZE);
	attach_stage1_counter++;
	return SUCCESS;
}

/**
* Thread exit function for future reference.
*/
void
shutdown_stage1()
{
	close_ipc_channel(g_Q1_fd);
	log_msg(LOG_INFO, "Shutdown Stage1 handler \n");
	pthread_exit(NULL);
	return;
}

/**
* Thread function for stage.
*/
void*
stage1_handler(void *data)
{
	init_stage();
	log_msg(LOG_INFO, "Stage 1 Ready.\n");
	g_mme_hdlr_status <<= 1;
	g_mme_hdlr_status |= 1;
	check_mme_hdlr_status();

	//Test
	//post_to_next();

	while(1){
		read_next_msg();

		stage1_processing();

		post_to_next();
	}

	return NULL;
}
