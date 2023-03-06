//import ballerina/log;
import ballerina/io;
import ballerina/http;
import ballerinax/azure_cosmosdb as cosmosdb;
configurable config cosmosConfig =?;

service / on new http:Listener(8090) {
    resource function get invictiScanList() returns string|error {
        //json output = {};
        cosmosdb:ConnectionConfig configuration = {
            baseUrl: cosmosConfig.baseUrl,
            primaryKeyOrResourceToken:cosmosConfig.primaryKey
        };
        cosmosdb:DataPlaneClient azureCosmosClient = check new (configuration);

        string query = string `SELECT c.reportId,c.vulnerabilities FROM vmsContainer c WHERE c.scanner_type = 'trivy'`;

        stream<record{}, error?> result = check azureCosmosClient->queryDocuments("vmsDB", "vmsContainer", query);
        check result.forEach(isolated function(record {} queryResult) {
            io:println(queryResult.toJson());
        });
        return "Success!";
    }
}




