var metadata = {
    name: "PostEx-BOF",
    description: "BOFs for post exploitation"
};

/// COMMANDS

var cmd_sauroneye = ax.create_command("sauroneye", "Search directories for files containing specific keywords (SauronEye ported to BOF by @shashinma)", "sauroneye -d C:\\Users -f .txt,.docx -k pass*,secret*");
cmd_sauroneye.addArgFlagString("-d", "directories", "Comma-separated list of directories to search (default: C:\\)", "C:\\");
cmd_sauroneye.addArgFlagString("-f", "filetypes", "Comma-separated list of file extensions to search (default: .txt,.docx)", ".txt,.docx");
cmd_sauroneye.addArgFlagString("-k", "keywords", "Comma-separated list of keywords (supports wildcards * ). If not specified, matches all filenames", "");
cmd_sauroneye.addArgBool("-c", "Search file contents for keywords (supports wildcards * )");
cmd_sauroneye.addArgFlagInt("-m", "maxfilesize", "Max file size to search contents in, in kilobytes (default: 1024)", 1024);
cmd_sauroneye.addArgBool("-s", "Search in system directories (Windows and AppData)");
cmd_sauroneye.addArgFlagString("-b", "beforedate", "Filter files last modified before this date (format: dd.MM.yyyy)", "");
cmd_sauroneye.addArgFlagString("-a", "afterdate", "Filter files last modified after this date (format: dd.MM.yyyy)", "");
cmd_sauroneye.addArgBool("-v", "Check if Office files contain VBA macros using OOXML detection (no OLE, stealthier)");
cmd_sauroneye.addArgBool("-D", "Show file creation and modification dates in output (format: [C:dd.MM.yyyy M:dd.MM.yyyy])");
cmd_sauroneye.addArgFlagInt("-W", "wildcardattempts", "Maximum pattern matching attempts for wildcard search (default: 1000). Increase for complex patterns", 1000);
cmd_sauroneye.addArgFlagInt("-S", "wildcardsize", "Maximum search area in KB for large files when using wildcards (default: 200KB). Increase to search more", 200);
cmd_sauroneye.addArgFlagInt("-B", "wildcardbacktrack", "Maximum backtracking operations for wildcard matching (default: 1000). Increase for complex patterns", 1000);
cmd_sauroneye.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let directories = (parsed_json["directories"] !== undefined && parsed_json["directories"] !== null) ? String(parsed_json["directories"]) : "C:\\";
    let filetypes = (parsed_json["filetypes"] !== undefined && parsed_json["filetypes"] !== null) ? String(parsed_json["filetypes"]) : ".txt,.docx";
    let keywords = (parsed_json["keywords"] !== undefined && parsed_json["keywords"] !== null) ? String(parsed_json["keywords"]) : "";
    let search_contents = (parsed_json["-c"]) ? 1 : 0;
    let max_filesize = (parsed_json["maxfilesize"] !== undefined && parsed_json["maxfilesize"] !== null) ? parseInt(parsed_json["maxfilesize"]) : 1024;
    let system_dirs = (parsed_json["-s"]) ? 1 : 0;
    let before_date = (parsed_json["beforedate"] !== undefined && parsed_json["beforedate"] !== null) ? String(parsed_json["beforedate"]) : "";
    let after_date = (parsed_json["afterdate"] !== undefined && parsed_json["afterdate"] !== null) ? String(parsed_json["afterdate"]) : "";
    let check_macro = (parsed_json["-v"]) ? 1 : 0;
    let show_date = (parsed_json["-D"]) ? 1 : 0;
    let wildcard_attempts = (parsed_json["wildcardattempts"] !== undefined && parsed_json["wildcardattempts"] !== null) ? parseInt(parsed_json["wildcardattempts"]) : 1000;
    let wildcard_size = (parsed_json["wildcardsize"] !== undefined && parsed_json["wildcardsize"] !== null) ? parseInt(parsed_json["wildcardsize"]) : 200;
    let wildcard_backtrack = (parsed_json["wildcardbacktrack"] !== undefined && parsed_json["wildcardbacktrack"] !== null) ? parseInt(parsed_json["wildcardbacktrack"]) : 1000;

    // Pack raw cmdline as first param for in-BOF validation of unknown flags
    let bof_params = ax.bof_pack("cstr,cstr,cstr,cstr,int,int,int,cstr,cstr,int,int,int,int,int", 
        [cmdline, directories, filetypes, keywords, search_contents, max_filesize, system_dirs, before_date, after_date, check_macro, show_date, wildcard_attempts, wildcard_size, wildcard_backtrack]);
    let bof_path = ax.script_dir() + "_bin/sauroneye." + ax.arch(id) + ".o";

    let cmd = "execute bof";
    if (ax.agent_info(id, "type") == "kharon") { cmd = "exec-bof"; }

    ax.execute_alias(id, cmdline, `${cmd} ${bof_path} ${bof_params}`, "Task: SauronEye file search");
});


var b_group_test = ax.create_commands_group("PostEx-BOF", [cmd_fw, cmd_screenshot, cmd_sauroneye]);
ax.register_commands_group(b_group_test, ["beacon", "gopher"], ["windows"], []);

