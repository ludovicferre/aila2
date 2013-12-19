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


        /******************************************************************************
         * Altiris Virtual Directories enumeration
         * This should allow us to gather stats on the altiris related uri details
         ******************************************************************************/
        public enum ATRS_IIS_VDIR {
	        _atrs_ns_agent,
	        _atrs_ns_nscap,
	        _atrs_ns,
	        _atrs_resource,
	        _atrs_ira,		// InventoryRuleAgent
	        _atrs_packages,
	        _atrs_swportal,
	        _atrs_cta,		// ClientTaskAgent
	        _atrs_cts,		// ClientTaskServer
	        _atrs_tm,		// TaskManagement
	        _atrs_cnsl,		// 6.5, 7.x Console
	        _atrs,
	        _other_vdir
        };

        /******************************************************************************
         * Reverse lookup for Altiris Virtual Directories
         ******************************************************************************/
        public static readonly string [] atrs_iis_vdir = new string [] {
	        "/Altiris/NS/Agent/",	//  0
	        "/Altiris/NS/NSCap/",
	        "/Altiris/NS/",
	        "/Altiris/Resource/",
	        "/Altiris/IRA[1]/",
	        "/Altiris/Packages/",	//  5
	        "/Altiris/SWPortal/",
	        "/Altiris/CTA[3]/",
	        "/Altiris/CTS[4]/",
	        "/Altiris/TaskMgmt/",
	        "/Altiris/Console/",
	        "/Altiris/",		// 11
	        "Other"
        };

        /******************************************************************************
         * Reverse lookup for Altiris Virtual Directories
         ******************************************************************************/
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
         * Atiris Agent Http requests enumeration
         * These are http request related to the Altiris Agent specifically
         ******************************************************************************/
        enum ATRS_AGENT_REQ {
	        _get_create_resource,
	        _get_client_config,
	        _get_pkg_info,
	        _get_pkg_snapshot,
	        _post_event,
	        _get_license_details,
	        _other_req,
	        _not_applicable
        };

        /******************************************************************************
         * Reverse lookup for Altiris Agent Http requests
         ******************************************************************************/
        public static readonly string [] atrs_agent_req = new string [] {
	        "Reg Client",
	        "Get Policies",
	        "Get Pkg Info",
	        "Get Snapshot",
	        "Post Event",
	        "Get License",
	        "Other"
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

        public static readonly string [] print_atrs_agent_req = new string [] {
	        "CreateResource.aspx",
	        "GetClientPolicies.aspx",
	        "GetPackageInfo.aspx",
	        "GetPackageSnapshot.aspx",
	        "PostEvent.asp",
	        "GetLicense.asmx",
	        "Other"
        };

        /******************************************************************************
         * Http Mime types enumeration
         * Standard html mime types found in a Notificatoin Server
         ******************************************************************************/
        enum HTTP_MIME_TYPE {
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
	        _other_mime
        };

        /******************************************************************************
         * Reverse lookup for Http Mime types
         ******************************************************************************/
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
	        "Other"
        };

        /******************************************************************************
         * IIS Return codes enumeration
         ******************************************************************************/
        enum IIS_STATUS_CODES {
	        _iis_success,
	        _iis_redirect,
	        _iis_client_error,
	        _iis_server_error
        };

        /******************************************************************************
         * Reverse lookup for IIS Return codes
         ******************************************************************************/
        public static readonly string [] iis_status_code = new string [] {
	        "Success  (1xx,2xx)",
	        "Redirected   (3xx)",
	        "Client error (4xx)",
	        "Server error (5xx)"
        };

        public static readonly string [] json_status_code = new string [] {
	        "Success",
	        "Redirected",
	        "Client error",
	        "Server error"
        };

        /******************************************************************************
         * IIS Win32 Return codes enumeration
         ******************************************************************************/
        enum IIS_WIN32_STATUS {
	        _win32_success,
	        _win32_other
        };

        /******************************************************************************
         * Reverse lookup for IIS Win32 Return codes
         ******************************************************************************/
        public static readonly string[]  iis_win32_status = new string [] {
	        "Win32 Success",
	        "Win32 Failure"
        };

    }
}
