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
   string? report_reference = "";
   string? asset = "";
   //Vulnerability[]? vulnerabilities = [];
};

// type Vulnerability record{
//     string? title = "";
//     string? description = "";
//     string? severity = "";
//     string? references = "";
//     string? url = "";
//     string? parameter = "";
//   	"payload": "<payload>",
//   	"request_response_Info": "<request-response-info>",
//   	"cve": "<cve>",
//   	"component_name": "<component-name>",
//   	"component_version": "<component-version>",
//   	"component_path": "<component-path>",
//   	"line_number": "<line-number>",
//   	"component_type": "<component-type>"


// };

