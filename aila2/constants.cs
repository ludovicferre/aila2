using System;
using System.Collections.Generic;
using System.Text;

namespace Symantec.CWoC {
    class constants {
        /******************************************************************************
         * { Connect Winter of Code: IIS Log analyzer for Altiris Notification Server }
         * Author: Ludovic FERRE, http://www.symantec.com/connect/blogs/ludovicferre
         * {CWoc} info: http://www.symantec.com/connect/search/apachesolr_search/cwoc
         ******************************************************************************/

        /******************************************************************************
         * IIS Log file schema constants
         * This is the default schema for IIS W3C log files
         ******************************************************************************/
        public enum W3C_SCHEMA {
	        _w3c_date,
	        _w3c_time,
	        _w3c_cs_method,
	        _w3c_cs_uri,
	        _w3c_cs_uri_stem,
	        _w3c_cs_uri_query,
	        _w3c_cs_username,
	        _w3c_c_ip,
	        _w3c_sc_status,
	        _w3c_sc_sub_status,
	        _w3c_sc_win32_status,
	        _w3c_time_taken
        };

        /******************************************************************************
         * These string are matching the above enumeration to check the current schema
         ******************************************************************************/
        public static readonly string [] w3c_schema_table = new string [] {
	        "date",
	        "time",
	        "cs-method",
	        "cs-uri",
	        "cs-uri-stem",
	        "cs-uri-query",
	        "cs-username",
	        "c-ip",
	        "sc-status",
	        "sc-substatus",
	        "sc-win32-status",
	        "time-taken"
        };

        public enum HOURLY_TABLE {
            _total,
            _postevent,
            _packageinfo,
            _getpolicies,
            _taskmgmt,
            _invrulemgmt
        };


        /******************************************************************************
         * Web-applications data (enum, match strings and JSON string)
         ******************************************************************************/
        public enum ATRS_IIS_VDIR {
	        _atrs_ns_agent,
	        _atrs_ns_nscap,
	        _atrs_ns,
	        _atrs_resource,
	        _atrs_irm,		// InventoryRuleAgent
	        _atrs_packages,
	        _atrs_swportal,
	        _atrs_cta,		// ClientTaskAgent
	        _atrs_cts,		// ClientTaskServer
	        _atrs_tm,		// TaskManagement
	        _atrs_cnsl,		// 6.5, 7.x Console
	        _atrs_ac,
            _atrs_workflow,
            _atrs,
	        _other_vdir
        };

        public static readonly string [] atrs_iis_vdir = new string [] {
	        "/altiris/ns/agent/",
	        "/altiris/ns/nscap/",
	        "/altiris/ns/",
	        "/altiris/resource/",
	        "/altiris/inventoryrulemanagement/",
	        "/altiris/packageshare/",
	        "/altiris/swportal/",
	        "/altiris/clienttaskagent/",
	        "/altiris/clienttaskserver/",
	        "/altiris/taskmanagement/",
	        "/altiris/console/",
            "/altiris/activitycenter/",
            "/altiris/workflow/",
	        "/altiris",
	        "other"
        };

        public static readonly string [] json_iis_vdir = new string [] {
	        "NS Agent",	//  0
	        "NSCap",
	        "NS",
	        "Resource",
	        "InvRuleAgent",
	        "Packages",	//  5
	        "SWPortal",
	        "ClntTskAgnt",
	        "ClntTskSvr",
	        "TaskMgmt",
	        "Console",
	        "Altiris",		// 11
	        "Others"
        };

        /******************************************************************************
         * Inventory Rule Management data (enum, match strings and JSON string)
         ******************************************************************************/
        public enum ATRS_IRM_PARAMS {
            _atrs_irm_classhash,
            _atrs_irm_rulesummary,
            _atrs_irm_rules,
            _atrs_irm_classrules,
            _atrs_irm_other
        }

        public static readonly string[] atrs_irm_params = new string[] {
            "datatype=dataclasshash",
            "datatype=dataclassrulesummary",
            "datatype=rules",
            "datatype=dataclassrules"
        };

        public static readonly string[] json_irm_params = new string[] {
            "DataClassHash",
            "DCRuleSummary",
            "Rules",
            "DataclassRules",
            "Other"
        };

        /******************************************************************************
         * Task Management data (enum, match strings and JSON string)
         ******************************************************************************/
        public enum ATRS_TASK_REQ {
            _atrs_tm_execsql,
            _atrs_tm_reportdata,
            _atrs_tm_gettaskserver,
            _atrs_tm_persistent,
            _atrs_tm_gettaskver,
            _atrs_tm_refreshts,
            _atrs_tm_other
        }

        public static readonly string[] atrs_task_req = new string[] {
            "clienttask/execsqlcommand.aspx",
            "clienttask/reporttaskdata.aspx",
            "ctagent/getclienttaskservers.aspx",
            "ctagent/persistentsettings.aspx",
            "clienttask/gettaskversion.aspx",
            "clienttask/refreshtaskservers.aspx"
        };

        public static readonly string[] json_task_req = new string[] {
            "ExecSQLCommand",
            "ReportTaskData",
            "GetTaskServer",
            "PersistentSettings",
            "GetTaskVersion",
            "RefreshTaskServer",
            "Other"
        };


        /******************************************************************************
         * Altiris Agent data (enum, match strings and JSON string)
         ******************************************************************************/
        public enum ATRS_AGENT_REQ {
	        _post_event_asp,
	        _post_event_aspx,
	        _get_pkg_info,
            _get_client_policy,
	        _get_pkg_snapshot,
	        _create_resource,
	        _get_license_details,
            _get_license,
	        _other_req
        };

        public static readonly string [] json_agent_req = new string [] {
	        "Create Res.",
	        "Get Policies",
	        "Get Pkg Info",
	        "Get Snapshot",
	        "Post Event",
	        "Get License",
	        "Other"
        };

        public static readonly string [] atrs_agent_req = new string [] {
	        "postevent.asp",
	        "postevent.aspx",
	        "getpackageinfo.aspx",
	        "getclientpolicies.aspx",
	        "getpackagesnapshot.aspx",
	        "createresource.aspx",
	        "getlicense.asmx",
            "getlicensedetails.aspx",
	        "other"
        };

        /******************************************************************************
         * Http Mime types enumeration
         * Standard html mime types found in a Notificatoin Server
         ******************************************************************************/
        public enum HTTP_MIME_TYPE {
	        _htm,
	        _html,
	        _asp,
	        _aspx,
	        _asmx,
	        _ascx,
	        _axd,
	        _ashx,
	        _xml,
            _css,
            _js,
            _gif,
            _png,
            _jpg,
	        _other_mime
        };

        public static readonly string [] http_mime_type = new string []{
	        "htm",
	        "html",
	        "asp",
	        "aspx",
	        "asmx",
	        "ascx",
	        "axd",
	        "ashx",
	        "xml",
            "css",
            "js",
            "gif",
            "png",
            "jpg",
	        "Other"
        };

        /******************************************************************************
         * IIS Return codes
         ******************************************************************************/
        public enum IIS_STATUS_CODES {
	        _iis_success,
	        _iis_redirect,
	        _iis_client_error,
	        _iis_server_error
        };

        public static readonly string [] iis_status_code = new string [] {
	        "1xx,2xx Success",
	        "3xx Redirected",
	        "4xx Client error",
	        "5xx Server error"
        };

        public static readonly string [] json_status_code = new string [] {
	        "Success",
	        "Redirected",
	        "Client error",
	        "Server error"
        };

        /******************************************************************************
         * IIS Win32 Return codes
         ******************************************************************************/
        public enum IIS_WIN32_STATUS {
	        _win32_success,
	        _win32_other
        };

        public static readonly string[]  iis_win32_status = new string [] {
	        "Win32 Success",
	        "Win32 Failure"
        };
    }
}
