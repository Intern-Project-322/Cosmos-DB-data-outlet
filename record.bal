type config record {
    string baseUrl;
    string primaryKey;
};

type ScanRecord record{|
   string? asset = "";
   string? team = "";
   Vulnerability[] vulnerabilities = [];
|};

type Vulnerability record{|
    string? title = "";
    string? description = "";
    string? severity = "";
    string? url = "";
    string? cve = "";
  	string? component_name = "";
    string? component_path = "";
    string? component_type = "";
|};

type CompleteVulnerability record{|
    string? asset = "";
    string? team = "";
    string? title = "";
    string? description = "";
    string? severity = "";
    string? url = "";
    string? cve = "";
  	string? component_name = "";
    string? component_path = "";
    string? component_type = "";
|};

type NonJsonScanRecord record{
   string? asset = "";
   string? team = "";
   Vulnerability[] vulnerabilities = [];
};

type NonJsonVulnerability record{
    string? title = "";
    string? description = "";
    string? severity = "";
    string? url = "";
    string? cve = "";
  	string? component_name = "";
    string? component_path = "";
    string? component_type = "";
};

