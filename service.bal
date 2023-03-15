//import ballerina/log;
import ballerina/time;
import ballerina/io;
import ballerina/http;
import ballerinax/azure_cosmosdb as cosmosdb;
configurable config cosmosConfig =?;

final cosmosdb:ConnectionConfig configuration = {
            baseUrl: cosmosConfig.baseUrl,
            primaryKeyOrResourceToken:cosmosConfig.primaryKey
        };
final cosmosdb:DataPlaneClient azureCosmosClient = check new (configuration);//final

service / on new http:Listener(8090) {
    resource function get invictiScanList() returns json|error {

        time:Utc beforeConfig = time:utcNow();
        int timeBeforeConfig= beforeConfig[0];
        io:println(`Number of seconds before Config: ${beforeConfig[0]}s`);

        time:Utc afterConfig = time:utcNow();
        int timeafterConfig= afterConfig[0];
        io:println(`Number of seconds after Config: ${afterConfig[0]}s`);

        time:Utc afterConfigCheck = time:utcNow();
        int timeafterConfigCheck= afterConfigCheck[0];
        io:println(`Number of seconds after Config check: ${afterConfigCheck[0]}s`);

        string query = string `SELECT c.asset,c.team,c.vulnerabilities FROM vmsContainer c WHERE c.scanner_type = 'trivy'`;

        json[] outputs = [];

        time:Utc beforeFetching = time:utcNow();
        int timeBeforeFetching= beforeFetching[0];
        io:println(`Number of seconds before fetching: ${beforeFetching[0]}s`);

        stream<ScanRecord, error?> result = check azureCosmosClient->queryDocuments("vmsDB", "vmsContainer", query);
       
        time:Utc afterFetching = time:utcNow();
        int timeafterFetching= afterFetching[0];
        io:println(`Number of seconds after fetching: ${afterFetching[0]}s`);

        check result.forEach(function(ScanRecord scanRecord){
            Vulnerability[] vulnerabilityList = scanRecord.vulnerabilities;
            vulnerabilityList.forEach(function(Vulnerability vuln){
                CompleteVulnerability compRecord = {
                    asset: scanRecord.asset,
                    team: scanRecord.team,
                    title: vuln.title,
                    description: vuln.description,
                    severity: vuln.severity,
                    url: vuln.url,
                    cve: vuln.cve,
                    component_name: vuln.component_name,
                    component_path: vuln.component_path,
                    component_type: vuln.component_type
                };
                outputs.push(compRecord.toJson());
            });
        });

        time:Utc afterParsing = time:utcNow();
        int timeafterParsing= afterParsing[0];
        io:println(`Number of seconds after Parsing: ${afterParsing[0]}s`);

        json finalOutput = { "beforeConfig":timeBeforeConfig,
                             "afterConfig":timeafterConfig,
                             "afterConfigCheck":timeafterConfigCheck,
                             "beforeFetching":timeBeforeFetching,
                             "afterFetching":timeafterFetching,
                             "afterParsing":timeafterParsing,
                             "results":outputs};
        return finalOutput;
    }
    resource function get rawScanData() returns json |error {

        string query = string `SELECT c.asset,c.team,t.title,t.description,t.severity,t.cve,t.url,t.component_name,t.component_path,t.component_type FROM c JOIN t IN c.vulnerabilities WHERE c.scanner_type = 'trivy' AND c.reportID = 635663253`;

        time:Utc beforeFetching = time:utcNow();
        int timeBeforeFetching= beforeFetching[0];
        io:println(`Number of seconds before fetching: ${beforeFetching[0]}s`);

        stream<JsonCompleteVulnerability, error?> result = check azureCosmosClient->queryDocuments("vmsDB", "vmsContainer", query);
       
        time:Utc afterFetching = time:utcNow();
        int timeafterFetching= afterFetching[0];
        io:println(`Number of seconds after fetching: ${afterFetching[0]}s`);

        JsonCompleteVulnerability[] outputs = check from JsonCompleteVulnerability vulnRecord in result  select vulnRecord;

        time:Utc afterParsing = time:utcNow();
        int timeafterParsing= afterParsing[0];
        io:println(`Number of seconds after Parsing: ${afterParsing[0]}s`);

        return { "beforeFetching":timeBeforeFetching,
                             "afterFetching":timeafterFetching,
                             "afterParsing":timeafterParsing,
                             "results":outputs};
    }
}
