//import ballerina/log;
//import ballerina/time;
//import ballerina/io;
import ballerina/http;
//import ballerina/log;
import ballerinax/azure_cosmosdb as cosmosdb;
configurable config cosmosConfig =?;


isolated json[] outputsIso = [];

service / on new http:Listener(8090) {
    isolated resource function get invictiScanList() returns json|error {

        cosmosdb:ConnectionConfig configuration = {
            baseUrl: cosmosConfig.baseUrl,
            primaryKeyOrResourceToken:cosmosConfig.primaryKey
        };
        cosmosdb:DataPlaneClient azureCosmosClient = check new (configuration);
        string query = string `SELECT c.asset,c.team,c.vulnerabilities FROM vmsContainer c WHERE c.scanner_type = 'trivy'`;
        stream<ScanRecord, error?> result = check azureCosmosClient->queryDocuments("vmsDB", "vmsContainer", query);

        check result.forEach(isolated function(ScanRecord scanRecord){
            Vulnerability[] vulnerabilityList = scanRecord.vulnerabilities;
            foreach Vulnerability vuln in vulnerabilityList {
                lock{
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
	                        component_type: vuln.component_name
	            };
                    outputsIso.push(compRecord.toJson());
                }  
            }



        });
        lock {
            return {"results":outputsIso.clone()};
        }
    }
}