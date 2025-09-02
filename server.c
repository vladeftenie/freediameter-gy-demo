#include "utils.h"

static struct disp_hdl *hdl = NULL;
static struct dict_object *ccr_cmd = NULL;
static struct dict_object *app_dcca = NULL;
static struct dict_object *avp_cc_request_type = NULL;
static struct dict_object *avp_cc_request_number = NULL;
static struct dict_object *avp_auth_app_id = NULL;
static struct dict_object *avp_service_context_id = NULL;
static struct dict_object *avp_requested_service_unit = NULL;
static struct dict_object *avp_used_service_unit = NULL;
static struct dict_object *avp_granted_service_unit = NULL;
static struct dict_object *avp_cc_total_octets = NULL;

static uint64_t total_granted = 0;
static uint64_t total_reported_usage = 0;

/* Helper function to extract octets from Service-Unit AVP */
static uint64_t extract_octets_from_service_unit(struct avp *su_avp)
{
    struct avp *child;
    struct avp_hdr *hdr;
    
    if (fd_msg_browse(su_avp, MSG_BRW_FIRST_CHILD, &child, NULL) == 0) {
        while (child != NULL) {
            if (fd_msg_avp_hdr(child, &hdr) == 0) {
                if (hdr->avp_code == 421) { /* CC-Total-Octets */
                    return hdr->avp_value->u64;
                }
            }
            if (fd_msg_browse(child, MSG_BRW_NEXT, &child, NULL) != 0) {
                break;
            }
        }
    }
    return 0;
}

/* Helper function to add Granted-Service-Unit with octets */
static int add_granted_service_unit(struct msg *ans, uint64_t octets)
{
    struct avp *avp_gsu, *avp_octets;
    union avp_value val;

    /* Create Granted-Service-Unit AVP (grouped) */
    CHECK_FCT(fd_msg_avp_new(avp_granted_service_unit, 0, &avp_gsu));
    
    /* Add CC-Total-Octets inside Granted-Service-Unit */
    CHECK_FCT(fd_msg_avp_new(avp_cc_total_octets, 0, &avp_octets));
    val.u64 = octets;
    CHECK_FCT(fd_msg_avp_setvalue(avp_octets, &val));
    CHECK_FCT(fd_msg_avp_add(avp_gsu, MSG_BRW_LAST_CHILD, avp_octets));
    
    /* Add Granted-Service-Unit to answer */
    CHECK_FCT(fd_msg_avp_add(ans, MSG_BRW_LAST_CHILD, avp_gsu));
    
    return 0;
}

/* Callback when a CCR is received */
static int ccr_cb(struct msg **msg, struct avp *avp, struct session *sess, void *opaque, enum disp_action *act)
{
    struct msg *ans;
    struct msg_hdr *hdr;
    struct avp *avp_val;
    struct avp_hdr *avp_hdr;
    union avp_value val;
    uint32_t cc_request_type = 0;
    uint32_t cc_request_number = 0;
    uint64_t requested_quota = 0;
    uint64_t reported_usage = 0;

    if (!msg || !*msg)
        return EINVAL;

    fd_log_notice("\n=== Gy server: received CCR ===\n");

    /* Parse message header */
    CHECK_FCT(fd_msg_hdr(*msg, &hdr));

    /* Extract CC-Request-Type */
    CHECK_FCT(fd_msg_search_avp(*msg, avp_cc_request_type, &avp_val));
    if (avp_val) {
        CHECK_FCT(fd_msg_avp_hdr(avp_val, &avp_hdr));
        cc_request_type = avp_hdr->avp_value->u32;
    }

    /* Extract CC-Request-Number */
    CHECK_FCT(fd_msg_search_avp(*msg, avp_cc_request_number, &avp_val));
    if (avp_val) {
        CHECK_FCT(fd_msg_avp_hdr(avp_val, &avp_hdr));
        cc_request_number = avp_hdr->avp_value->u32;
    }

    const char *request_name;
    if (cc_request_type == 1) {
        request_name = "INITIAL";
    } else if (cc_request_type == 2) {
        request_name = "UPDATE";
    } else if (cc_request_type == 3) {
        request_name = "TERMINATE";
    } else {
        request_name = "UNKNOWN";
    }

    fd_log_notice("CCR Type: %u (%s), Number: %u\n", cc_request_type, request_name, cc_request_number);

    /* Extract Requested-Service-Unit if present */
    if (fd_msg_search_avp(*msg, avp_requested_service_unit, &avp_val) == 0 && avp_val) {
        requested_quota = extract_octets_from_service_unit(avp_val);
        fd_log_notice("Requested quota: %.1f GB\n", (double)requested_quota / (1024*1024*1024));
    }

    /* Extract Used-Service-Unit if present */
    if (fd_msg_search_avp(*msg, avp_used_service_unit, &avp_val) == 0 && avp_val) {
        reported_usage = extract_octets_from_service_unit(avp_val);
        total_reported_usage += reported_usage;
        fd_log_notice("Reported usage: %.1f GB (total: %.1f GB)\n", (double)reported_usage / (1024*1024*1024), (double)total_reported_usage / (1024*1024*1024));
    }

    /* Create answer from request */
    CHECK_FCT(fd_msg_new_answer_from_req(fd_g_config->cnf_dict, msg, 0));
    ans = *msg;

    /* Add Result-Code = DIAMETER_SUCCESS */
    CHECK_FCT(fd_msg_rescode_set(ans, "DIAMETER_SUCCESS", NULL, NULL, 1));

    /* Add Auth-Application-Id */
    CHECK_FCT(fd_msg_avp_new(avp_auth_app_id, 0, &avp_val));
    val.u32 = 4;
    CHECK_FCT(fd_msg_avp_setvalue(avp_val, &val));
    CHECK_FCT(fd_msg_avp_add(ans, MSG_BRW_LAST_CHILD, avp_val));

    /* Add CC-Request-Type */
    CHECK_FCT(fd_msg_avp_new(avp_cc_request_type, 0, &avp_val));
    val.u32 = cc_request_type;
    CHECK_FCT(fd_msg_avp_setvalue(avp_val, &val));
    CHECK_FCT(fd_msg_avp_add(ans, MSG_BRW_LAST_CHILD, avp_val));

    /* Add CC-Request-Number */
    CHECK_FCT(fd_msg_avp_new(avp_cc_request_number, 0, &avp_val));
    val.u32 = cc_request_number;
    CHECK_FCT(fd_msg_avp_setvalue(avp_val, &val));
    CHECK_FCT(fd_msg_avp_add(ans, MSG_BRW_LAST_CHILD, avp_val));

    /* Grant quota for INITIAL and UPDATE requests */
    if (cc_request_type == 1 || cc_request_type == 2) {
        uint64_t quota_to_grant = requested_quota; /* Grant 1GB */
        total_granted += quota_to_grant;
        
        add_granted_service_unit(ans, quota_to_grant);
        fd_log_notice("Granted quota: %.1f GB (total granted: %.1f GB)\n", (double)quota_to_grant / (1024*1024*1024), (double)total_granted / (1024*1024*1024));
    }

    CHECK_FCT(fd_msg_send(msg, NULL, NULL));

    if (cc_request_type == 1) {
        fd_log_notice("CCA: \"OK, here's %.1f GB quota\"\n", (double)requested_quota / (1024*1024*1024));
    } else if (cc_request_type == 2) {
        fd_log_notice("CCA: \"OK, here's another %.1f GB quota\"\n", (double)requested_quota / (1024*1024*1024));
    } else if (cc_request_type == 3) {
        fd_log_notice("CCA: \"OK, session closed\"\n");
        fd_log_notice("Session summary - Granted: %.1f GB, Used: %.1f GB\n", (double)total_granted / (1024*1024*1024), (double)total_reported_usage / (1024*1024*1024));
        
        /* Reset counters for next session */
        total_granted = 0;
        total_reported_usage = 0;
    }

    fd_log_notice("CCA sent successfully for %s request\n", request_name);
    return 0;
}

/* Called when extension is loaded */
static int server_entry(char *conffile)
{
    struct disp_when data;

    /* Look up the DCCA application */
    application_id_t dcca_id = 4;
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_APPLICATION, APPLICATION_BY_ID, &dcca_id, &app_dcca, ENOENT));

    /* Advertise support for DCCA application */
    CHECK_FCT(fd_disp_app_support(app_dcca, NULL, 1, 0));

    /* Look up dictionary objects */
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_COMMAND, CMD_BY_NAME, "Credit-Control-Request", &ccr_cmd, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "CC-Request-Type", &avp_cc_request_type, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "CC-Request-Number", &avp_cc_request_number, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Auth-Application-Id", &avp_auth_app_id, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Service-Context-Id", &avp_service_context_id, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Requested-Service-Unit", &avp_requested_service_unit, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Used-Service-Unit", &avp_used_service_unit, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Granted-Service-Unit", &avp_granted_service_unit, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "CC-Total-Octets", &avp_cc_total_octets, ENOENT));

    /* Set up dispatch rule */
    memset(&data, 0, sizeof(data));
    data.command = ccr_cmd;
    data.app = app_dcca;

    /* Register our callback */
    CHECK_FCT(fd_disp_register(ccr_cb, DISP_HOW_CC, &data, NULL, &hdl));

    fd_log_notice("Gy server extension loaded (quota management server)\n");
    return 0;
}

/* Called when extension is unloaded */
void fd_ext_fini(void)
{
    if (hdl) {
        (void) fd_disp_unregister(&hdl, NULL);
    }
    fd_log_notice("Gy server extension unloaded\n");
}

/* Required entry macro */
EXTENSION_ENTRY("gy_server", server_entry);