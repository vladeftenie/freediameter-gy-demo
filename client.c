#include "utils.h"

static struct dict_object *ccr_cmd = NULL;
static struct dict_object *cca_cmd = NULL;
static struct dict_object *app_dcca = NULL;
static struct dict_object *avp_session_id = NULL;
static struct dict_object *avp_origin_host = NULL;
static struct dict_object *avp_origin_realm = NULL;
static struct dict_object *avp_dest_realm = NULL;
static struct dict_object *avp_auth_app_id = NULL;
static struct dict_object *avp_cc_request_type = NULL;
static struct dict_object *avp_cc_request_number = NULL;
static struct dict_object *avp_result_code = NULL;
static struct dict_object *avp_service_context_id = NULL;
static struct dict_object *avp_requested_service_unit = NULL;
static struct dict_object *avp_used_service_unit = NULL;
static struct dict_object *avp_granted_service_unit = NULL;
static struct dict_object *avp_cc_total_octets = NULL;
static int keep_running = 1;

static uint64_t granted_quota = 0;
static uint64_t total_used = 0;

uint64_t quotas[] = {
    800ULL * 1024 * 1024,   /* 800MB */
    1024ULL * 1024 * 1024,  /* 1GB */
    1228ULL * 1024 * 1024   /* 1.2GB */
};


static void signal_handler(int sig)
{
    fd_log_notice("Received signal %d, shutting down...\n", sig);
    keep_running = 0;
}

/* Helper function to add Service-Unit AVP with octets */
static int add_service_unit(struct msg *msg, struct dict_object *service_unit_avp, uint64_t octets)
{
    struct avp *avp_su, *avp_octets;
    union avp_value val;

    /* Create Service-Unit AVP (grouped) */
    CHECK_FCT(fd_msg_avp_new(service_unit_avp, 0, &avp_su));
    
    /* Add CC-Total-Octets inside Service-Unit */
    CHECK_FCT(fd_msg_avp_new(avp_cc_total_octets, 0, &avp_octets));
    val.u64 = octets;
    CHECK_FCT(fd_msg_avp_setvalue(avp_octets, &val));
    CHECK_FCT(fd_msg_avp_add(avp_su, MSG_BRW_LAST_CHILD, avp_octets));
    
    /* Add Service-Unit to message */
    CHECK_FCT(fd_msg_avp_add(msg, MSG_BRW_LAST_CHILD, avp_su));
    
    return 0;
}

/* Callback when CCA is received */
static void cca_cb(void *data, struct msg **msg)
{
    struct msg *qry;
    struct avp *a, *child;
    struct avp_hdr *hdr;
    uint32_t result_code = 0;
    uint32_t request_type = 0;

    if (!msg || !*msg) {
        fd_log_error("Invalid message in CCA callback\n");
        return;
    }

    qry = *msg;
    fd_log_notice("Gy client: received CCA\n");

    /* Look for Result-Code */
    if (fd_msg_search_avp(qry, avp_result_code, &a) == 0 && a) {
        if (fd_msg_avp_hdr(a, &hdr) == 0) {
            result_code = hdr->avp_value->u32;
            fd_log_notice("CCA Result-Code: %u\n", result_code);
        }
    }

    /* Look for CC-Request-Type */
    if (fd_msg_search_avp(qry, avp_cc_request_type, &a) == 0 && a) {
        if (fd_msg_avp_hdr(a, &hdr) == 0) {
            request_type = hdr->avp_value->u32;
        }
    }

    /* Look for Granted-Service-Unit */
    if (fd_msg_search_avp(qry, avp_granted_service_unit, &a) == 0 && a) {
        /* Search for CC-Total-Octets inside Granted-Service-Unit */
        if (fd_msg_browse(a, MSG_BRW_FIRST_CHILD, &child, NULL) == 0) {
            while (child != NULL) {
                if (fd_msg_avp_hdr(child, &hdr) == 0) {
                    if (hdr->avp_code == 421) { /* CC-Total-Octets */
                        granted_quota = hdr->avp_value->u64;
                        fd_log_notice("CCA: Granted quota: %lu bytes (%.1f GB)\n", granted_quota, (double)granted_quota / (1024*1024*1024));
                        break;
                    }
                }
                if (fd_msg_browse(child, MSG_BRW_NEXT, &child, NULL) != 0) {
                    break;
                }
            }
        }
    }

    const char *request_name;
    if (request_type == 1) {
        request_name = "INITIAL";
    } else if (request_type == 2) {
        request_name = "UPDATE";
    } else if (request_type == 3) {
        request_name = "TERMINATE";
    } else {
        request_name = "UNKNOWN";
    }
    
    if (result_code == 2001) {
        fd_log_notice("CCA: %s request approved successfully\n", request_name);
    } else {
        fd_log_notice("CCA: %s request failed with code %u\n", request_name, result_code);
    }
    
    fd_msg_free(*msg);
    *msg = NULL;
}

/* Function to send a CCR */
static int send_ccr(uint32_t request_type, uint32_t request_number)
{
    struct msg *req = NULL;
    struct avp *avp;
    struct session *sess;
    union avp_value val;
    os0_t sid;
    size_t sidlen;
    static struct session *global_sess = NULL;
    
    const char *request_type_name;
    uint64_t request_quota = 0;
    uint64_t used_quota = 0;
    
    switch(request_type) {
        case 1: 
        request_type_name = "INITIAL";
            request_quota = quotas[rand() % 3];
            break;
            case 2: 
            request_type_name = "UPDATE";
            request_quota = quotas[rand() % 3];
            used_quota = 800ULL * 1024 * 1024;     /* Report 800MB used */
            total_used += used_quota;
            break;
            case 3: 
            request_type_name = "TERMINATE";
            used_quota = 400ULL * 1024 * 1024;     /* Report remaining 400MB used */
            total_used += used_quota;
            break;
        default: 
            request_type_name = "UNKNOWN"; 
            break;
    }
    
    fd_log_notice("\n=== Gy client: creating CCR (%s) ===\n", request_type_name);
    
    if (request_type == 1) {
        fd_log_notice("Scenario: User starts browsing internet\n");
        fd_log_notice("CCRI: \"Give me %.1f GB data quota\"\n", (double)request_quota / (1024*1024*1024));
    } else if (request_type == 2) {
        fd_log_notice("Scenario: User has used 800MB, quota running low\n");
        fd_log_notice("CCRU: \"I used 800MB, give me more quota\"\n");
    } else if (request_type == 3) {
        fd_log_notice("Scenario: User disconnects\n");
        fd_log_notice("CCRT: \"Session ended, I used %.1fGB total\"\n", (double)total_used / (1024*1024*1024));
    }
    
    /* Create or reuse session */
    if (request_type == 1) {
        CHECK_FCT(fd_sess_new(&global_sess, fd_g_config->cnf_diamid, fd_g_config->cnf_diamid_len, (os0_t)"gy-demo", strlen("gy-demo")));
    }
    sess = global_sess;
    
    /* Get session ID */
    CHECK_FCT(fd_sess_getsid(sess, &sid, &sidlen));
    
    /* Create the request */
    CHECK_FCT(fd_msg_new(ccr_cmd, MSGFL_ALLOC_ETEID, &req));

    /* Add Session-Id */
    CHECK_FCT(fd_msg_avp_new(avp_session_id, 0, &avp));
    val.os.data = sid;
    val.os.len = sidlen;
    CHECK_FCT(fd_msg_avp_setvalue(avp, &val));
    CHECK_FCT(fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp));

    /* Add Origin-Host */
    CHECK_FCT(fd_msg_avp_new(avp_origin_host, 0, &avp));
    val.os.data = (unsigned char *)fd_g_config->cnf_diamid;
    val.os.len = fd_g_config->cnf_diamid_len;
    CHECK_FCT(fd_msg_avp_setvalue(avp, &val));
    CHECK_FCT(fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp));

    /* Add Origin-Realm */
    CHECK_FCT(fd_msg_avp_new(avp_origin_realm, 0, &avp));
    val.os.data = (unsigned char *)fd_g_config->cnf_diamrlm;
    val.os.len = fd_g_config->cnf_diamrlm_len;
    CHECK_FCT(fd_msg_avp_setvalue(avp, &val));
    CHECK_FCT(fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp));

    /* Add Destination-Realm */
    CHECK_FCT(fd_msg_avp_new(avp_dest_realm, 0, &avp));
    val.os.data = (unsigned char *)"dpc.mnc005.mcc226.3gppnetwork.org";
    val.os.len = strlen("dpc.mnc005.mcc226.3gppnetwork.org");
    CHECK_FCT(fd_msg_avp_setvalue(avp, &val));
    CHECK_FCT(fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp));

    /* Add Auth-Application-Id (4 for DCCA/Gy) */
    CHECK_FCT(fd_msg_avp_new(avp_auth_app_id, 0, &avp));
    val.u32 = 4;
    CHECK_FCT(fd_msg_avp_setvalue(avp, &val));
    CHECK_FCT(fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp));
    
    /* Add CC-Request-Type */
    CHECK_FCT(fd_msg_avp_new(avp_cc_request_type, 0, &avp));
    val.u32 = request_type;
    CHECK_FCT(fd_msg_avp_setvalue(avp, &val));
    CHECK_FCT(fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp));

    /* Add CC-Request-Number */
    CHECK_FCT(fd_msg_avp_new(avp_cc_request_number, 0, &avp));
    val.u32 = request_number;
    CHECK_FCT(fd_msg_avp_setvalue(avp, &val));
    CHECK_FCT(fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp));

    /* Add Service-Context-Id */
    CHECK_FCT(fd_msg_avp_new(avp_service_context_id, 0, &avp));
    val.os.data = (unsigned char *)"32251@3gpp.org";
    val.os.len = strlen("32251@3gpp.org");
    CHECK_FCT(fd_msg_avp_setvalue(avp, &val));
    CHECK_FCT(fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp));

    /* Add quota request for INITIAL and UPDATE */
    if (request_type == 1 || request_type == 2) {
        fd_log_notice("Requesting quota: %.1f GB\n", (double)request_quota / (1024*1024*1024));
        add_service_unit(req, avp_requested_service_unit, request_quota);
    }
    
    /* Add usage report for UPDATE and TERMINATE */
    if (request_type == 2 || request_type == 3) {
        fd_log_notice("Reporting usage: %.1f GB\n", (double)used_quota / (1024*1024*1024));
        add_service_unit(req, avp_used_service_unit, used_quota);
    }
    
    /* Send the request */
    CHECK_FCT(fd_msg_send(&req, cca_cb, NULL));
    
    fd_log_notice("CCR (%s) sent successfully\n", request_type_name);
    return 0;
}
/* Repeat the entire sequence multiple times */
static void* client_thread(void *arg)
{
    int sequence_count = 0;
    uint32_t request_number = 0;
    const int MAX_SEQUENCES = 10;
    
    srand(time(NULL));
    // time_t start_time = time(NULL);
    /* Wait for daemon to be ready */
    CHECK_FCT_DO(fd_core_waitstartcomplete(), return NULL);
    sleep(5);
    
    while (keep_running && sequence_count < MAX_SEQUENCES) {
        fd_log_notice("\n+++ STARTING SEQUENCE %d of %d +++\n", sequence_count + 1, MAX_SEQUENCES);
        
        /* Reset usage tracking for each sequence */
        total_used = 0;
        granted_quota = 0;
        
        /* INITIAL REQUEST */
        if (keep_running) {
            fd_log_notice("\n--- PHASE 1: Session Establishment ---\n");
            if (send_ccr(1, request_number) != 0) {
                fd_log_error("Failed to send CCR INITIAL in sequence %d\n", sequence_count + 1);
            }
            request_number++;
            sleep(2);
        }
        
        /* UPDATE REQUEST */
        if (keep_running) {
            fd_log_notice("\n--- PHASE 2: Quota Update ---\n");
            if (send_ccr(2, request_number) != 0) {
                fd_log_error("Failed to send CCR UPDATE in sequence %d\n", sequence_count + 1);
            }
            request_number++;
            sleep(2);
        }
        
        /* TERMINATE REQUEST */
        if (keep_running) {
            fd_log_notice("\n--- PHASE 3: Session Termination ---\n");
            if (send_ccr(3, request_number) != 0) {
                fd_log_error("Failed to send CCR TERMINATE in sequence %d\n", sequence_count + 1);
            }
            request_number++;
        }
        
        sequence_count++;
        
        fd_log_notice("\n+++ SEQUENCE %d COMPLETE +++\n", sequence_count);
        fd_log_notice("Total data used this session: %.1f GB\n", (double)total_used / (1024*1024*1024));
        // time_t end_time = time(NULL);
        // fd_log_notice("Total execution time: %ld seconds\n", end_time - start_time);
    }
    
    return NULL;
}

/* Called when extension is loaded */
static int client_entry(char *conffile)
{
    pthread_t thread;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Look up the DCCA application */
    application_id_t dcca_id = 4;
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_APPLICATION, APPLICATION_BY_ID, &dcca_id, &app_dcca, ENOENT));

    /* Advertise support for DCCA application */
    CHECK_FCT(fd_disp_app_support(app_dcca, NULL, 1, 0));

    /* Look up dictionary objects */
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_COMMAND, CMD_BY_NAME, "Credit-Control-Request", &ccr_cmd, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_COMMAND, CMD_BY_NAME, "Credit-Control-Answer", &cca_cmd, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Session-Id", &avp_session_id, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Origin-Host", &avp_origin_host, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Origin-Realm", &avp_origin_realm, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Destination-Realm", &avp_dest_realm, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Auth-Application-Id", &avp_auth_app_id, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "CC-Request-Type", &avp_cc_request_type, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "CC-Request-Number", &avp_cc_request_number, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Result-Code", &avp_result_code, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Service-Context-Id", &avp_service_context_id, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Requested-Service-Unit", &avp_requested_service_unit, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Used-Service-Unit", &avp_used_service_unit, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Granted-Service-Unit", &avp_granted_service_unit, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "CC-Total-Octets", &avp_cc_total_octets, ENOENT));

    /* Start client thread */
    if (pthread_create(&thread, NULL, client_thread, NULL) != 0) {
        fd_log_error("Failed to create client thread\n");
        return EINVAL;
    }
    
    pthread_detach(thread);

    fd_log_notice("Gy client extension loaded (quota management demo)\n");
    return 0;
}

/* Called when extension is unloaded */
void fd_ext_fini(void)
{
    keep_running = 0;
    fd_log_notice("Gy client extension unloaded\n");
}

/* Required entry macro */
EXTENSION_ENTRY("gy_client", client_entry);


//

//=== INITIAL REQUEST ===
//Client: "Give me 0.8/1/1.2GB data quota"
//Server: "OK, here's (what u req)GB quota"

//=== UPDATE REQUEST ===  
//Client: "I used 800MB, give me more quota"
//Server: "OK, here's another 0.8/1/1.2GB quota"

//=== TERMINATE REQUEST ===
//Client: "Session ended, I used 1.2GB total" 
//Server: "OK, session closed"