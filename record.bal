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
   Vulnerability[]? vulnerabilities = [];
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

