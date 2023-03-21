type SampleRecord record {
    string? id = "";
    string? categoryId ="";
    string? categoryName = "";
    string? sku = "";
    string? name = "";
    string? description = "";
    decimal? price;
    Tag[]? tags = [];
    string? _rid = "";
    string? _self = "";
    string? _etag = "";
    string? _attachments = "";
    int? _ts;
};

type Tag record {
    string? id = "";
    string? name = "";
};


type config record {
    string baseUrl;
    string primaryKey;
};

type ScanRecord record{
   string? asset = "";
   string? team = "";
   Vulnerability[] vulnerabilities = [];
};

type Vulnerability record{
    string? title = "";
    string? description = "";
    string? severity = "";
    string? url = "";
    string? cve = "";
  	string? component_name = "";
    string? component_path = "";
    string? component_type = "";
};

type CompleteVulnerability record{
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
};
type JsonScanRecord record{|
   string? asset = "";
   string? team = "";
   JsonVulnerability[] vulnerabilities = [];
|};

type JsonVulnerability record{|
    string? title = "";
    string? description = "";
    string? severity = "";
    string? url = "";
    string? cve = "";
  	string? component_name = "";
    string? component_path = "";
    string? component_type = "";
    json...;
|};

type JsonCompleteVulnerability record{|
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

type FormattedSummaryRecord record {|
    string? scannedDate ="";
    string? scannerName = "";
    string? assetOrWebsite = "";
    string? assetVersion = "";
    string? scanId = "";
    string? url = "";
    string? severityResoutionType = "";
    int vulnerabilityCount = 0;
    string? linkToVms = "";
    string? tags = "";
    string? createdTime = "";
    string? createdDate = "";
    string? team = "";
    int reportID = 0;
    string? status = "Pending"; 
    string? status_changed_on = "";
    string? status_changed_by = "";
    
|};

type SummaryRecord record {
    string? scannedDate ="";
    string? scannerName = "";
    string? assetOrWebsite = "";
    string? assetVersion = "";
    string? scanId = "";
    string? url = "";
    SeverityResoutionDetails critical;
    SeverityResoutionDetails high;
    SeverityResoutionDetails medium;
    SeverityResoutionDetails low;
    string? linkToVms = "";
    string? tags = "";
    string? createdTime = "";
    string? createdDate = "";
    string? team = "";
    int reportID = 0;
    string? status = "Pending"; 
    string? status_changed_on = "";
    string? status_changed_by = "";
    
};

type SeverityResoutionDetails record {|
    int total = 0;
    int falsePositive = 0;
    int truePositive = 0;
    int batchForPatching = 0;
    int notAThreat = 0;
    int notApplicable = 0;	
    int inadequateInfo = 0;	
    int alreadyMitigated = 0;	
    int fixed = 0;	
    int notAssigned = 0;
|};