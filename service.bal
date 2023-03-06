//import ballerina/log;
import ballerina/io;
import ballerina/http;
import ballerinax/azure_cosmosdb as cosmosdb;
configurable config cosmosConfig =?;

service / on new http:Listener(8090) {
    resource function get invictiScanList() returns json[]|error {
        cosmosdb:ConnectionConfig configuration = {
            baseUrl: cosmosConfig.baseUrl,
            primaryKeyOrResourceToken:cosmosConfig.primaryKey
        };
        cosmosdb:DataPlaneClient azureCosmosClient = check new (configuration);

        string query = string `SELECT c.reportReference,c.asset FROM vmsContainer c WHERE c.scanner_type = 'trivy'`;

        json[] outputs = [];
        stream<ScanRecord, error?> result = check azureCosmosClient->queryDocuments("vmsDB", "vmsContainer", query);
        //json[] theData = check from var rec in result select rec;
        check result.forEach(function(ScanRecord gdsl){
            outputs.push(gdsl.toJson());
        });
        check result.forEach(isolated function (ScanRecord queryResult) {
            io:println(queryResult.toJson());
            //outputs.push(queryResult.toJson());
            //string singleRecord = queryResult.toJsonString();

        });
        // foreach ScanRecord rec in result {
            
        // }
        return outputs;
    }
}




